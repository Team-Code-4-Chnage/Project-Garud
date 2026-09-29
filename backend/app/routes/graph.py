"""
Graph-based network representation endpoint (SIH 2026 PS:26153).

Exposes the session-derived directed IP graph and geographic threat map via REST:
  GET /graph/topology          — full graph from all active sessions with GeoIP metadata
  GET /graph/topology_geo      — optimized geographic topology for world map visualization
  GET /graph/topology/summary  — lightweight counts only (for polling)
  GET /graph/geoip/{ip}        — individual IP geolocation lookup
"""
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import SessionDB, get_db
from ..graph_state import build_session_graph
from ..geoip import resolve_ip_geo

router = APIRouter(prefix="/graph", tags=["Graph Topology"])

_RUNNING_PROCS_CACHE = set()
_ACTIVE_SOCKETS_CACHE = set()
_LAST_LIVENESS_CHECK = 0.0

def _get_live_system_state():
    global _RUNNING_PROCS_CACHE, _ACTIVE_SOCKETS_CACHE, _LAST_LIVENESS_CHECK
    now = time.time()
    if now - _LAST_LIVENESS_CHECK < 1.5:
        return _RUNNING_PROCS_CACHE, _ACTIVE_SOCKETS_CACHE

    _LAST_LIVENESS_CHECK = now
    running_procs = set()
    active_sockets = set()
    try:
        import psutil
        for p in psutil.process_iter(['name']):
            try:
                n = p.info.get('name')
                if n:
                    running_procs.add(n.lower().strip())
            except Exception:
                pass
        for c in psutil.net_connections(kind="inet"):
            if c.status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "LISTEN"):
                if c.laddr:
                    active_sockets.add(c.laddr.port)
                    if c.raddr:
                        active_sockets.add((c.laddr.port, c.raddr.port))
    except Exception:
        pass

    _RUNNING_PROCS_CACHE = running_procs
    _ACTIVE_SOCKETS_CACHE = active_sockets
    return running_procs, active_sockets


APP_BINARY_MAP = {
    "google chrome": ["chrome.exe"],
    "chrome": ["chrome.exe"],
    "microsoft edge": ["msedge.exe"],
    "msedge": ["msedge.exe"],
    "msedgewebview2": ["msedgewebview2.exe", "msedge.exe"],
    "vs code": ["code.exe"],
    "code": ["code.exe"],
    "spotify": ["spotify.exe", "spotifylauncher.exe"],
    "spotifylauncher": ["spotifylauncher.exe", "spotify.exe"],
    "discord": ["discord.exe", "discordcanary.exe", "discordptb.exe"],
    "slack": ["slack.exe"],
    "telegram": ["telegram.exe"],
    "brave": ["brave.exe"],
    "firefox": ["firefox.exe"],
    "opera": ["opera.exe", "operagx.exe"],
    "steam": ["steam.exe", "steamservice.exe"],
    "zoom": ["zoom.exe"],
    "teams": ["teams.exe", "ms-teams.exe"],
    "outlook": ["outlook.exe"],
    "whatsapp": ["whatsapp.exe"],
    "python": ["python.exe", "python3.exe", "pythonw.exe"],
    "node": ["node.exe"],
    "git": ["git.exe"],
    "postman": ["postman.exe"],
    "docker": ["docker.exe", "dockerd.exe", "com.docker.backend.exe"],
    "armourycrate.usersessionhelper": ["armourycrate.usersessionhelper.exe", "armouryswagent.exe"],
    "agy": ["agy.exe", "python.exe"],
    "codex": ["codex.exe", "node.exe"],
}


@router.get("/topology")
async def get_topology(
    min_risk: float = Query(
        0.0,
        ge=0.0,
        le=1.0,
        description="Only include sessions whose risk score is at or above this threshold.",
    ),
    limit: int = Query(150, ge=1, le=1000, description="Maximum sessions to include."),
    active_only: bool = Query(True, description="Only return live sessions whose application or socket is currently alive."),
    max_age_seconds: int = Query(75, ge=10, le=3600, description="Max inactivity age for live sessions."),
    db: AsyncSession = Depends(get_db),
):
    """
    Return a directed graph of real IP<->IP relationships derived from active sessions,
    enriched with real-world IP geolocation metadata and real-time process/socket liveness checking.
    """
    max_age = max_age_seconds if isinstance(max_age_seconds, (int, float)) else getattr(max_age_seconds, "default", 75)
    is_active_only = active_only if isinstance(active_only, bool) else getattr(active_only, "default", True)
    limit_val = limit if isinstance(limit, int) else getattr(limit, "default", 150)
    min_risk_val = min_risk if isinstance(min_risk, (int, float)) else getattr(min_risk, "default", 0.0)

    stmt = select(SessionDB).order_by(SessionDB.latest_risk_score.desc(), SessionDB.last_seen.desc()).limit(limit_val * 2)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    now_utc = datetime.now(timezone.utc)
    running_procs, active_sockets = _get_live_system_state()

    sessions = []
    seen_session_keys = set()

    for s in rows:
        if s.session_key in seen_session_keys:
            continue

        prob = float(s.latest_risk_score or 0.0)
        if prob < min_risk_val:
            continue

        is_threat = prob >= 0.25 or (s.latest_stage and s.latest_stage != "Benign")

        if is_active_only and not is_threat:
            # 1. Process Liveness Check: If an application is associated, verify it is actually running
            proc_raw = (s.process_name or "").lower().strip()
            app_raw = (s.app_name or "").lower().strip()

            target_binaries = []
            if proc_raw.endswith(".exe"):
                target_binaries = [proc_raw]
            elif app_raw in APP_BINARY_MAP:
                val = APP_BINARY_MAP[app_raw]
                target_binaries = val if isinstance(val, list) else [val]
            else:
                for k, b in APP_BINARY_MAP.items():
                    if k in app_raw:
                        target_binaries = b if isinstance(b, list) else [b]
                        break

            # If the application binary is known but no longer running on the host OS, it's CLOSED!
            if target_binaries and running_procs and not any(b in running_procs for b in target_binaries):
                continue

            # 2. Socket / Recency Check
            has_live_socket = (
                s.src_port in active_sockets
                or s.dst_port in active_sockets
                or (s.src_port, s.dst_port) in active_sockets
            )
            is_recent = False
            if s.last_seen:
                s_seen = s.last_seen if s.last_seen.tzinfo else s.last_seen.replace(tzinfo=timezone.utc)
                age = (now_utc - s_seen).total_seconds()
                is_recent = age <= max_age

            if not has_live_socket and not is_recent:
                continue

        seen_session_keys.add(s.session_key)
        sessions.append({
            "session_key": s.session_key,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "src_port": s.src_port,
            "dst_port": s.dst_port,
            "protocol": getattr(s, "protocol", "TCP"),
            "predicted_stage": s.latest_stage or "Benign",
            "latest_risk_score": prob,
            "flow_count": s.flow_count or 0,
            "source": s.source,
            "app_name": s.app_name or s.process_name or "Network Flow",
        })

        if len(sessions) >= limit:
            break

    graph = build_session_graph(sessions)
    graph["sessions_included"] = len(sessions)
    graph["filter_applied"] = {"min_risk": min_risk, "limit": limit}

    # Enrich nodes and edges with real-world GeoIP coordinates
    for node in graph["nodes"]:
        geo = resolve_ip_geo(node["id"])
        node["latitude"] = geo["latitude"]
        node["longitude"] = geo["longitude"]
        node["city"] = geo["city"]
        node["region"] = geo.get("region", "")
        node["country"] = geo["country"]
        node["country_code"] = geo["country_code"]
        node["org"] = geo["org"]
        node["flag"] = geo["flag"]
        node["is_internal"] = geo["is_internal"]

    valid_edges = []
    for edge in graph["edges"]:
        if edge["source"] == edge["target"]:
            continue  # Self-loops should not render as global geo lines
        src_geo = resolve_ip_geo(edge["source"])
        dst_geo = resolve_ip_geo(edge["target"])
        edge["src_lat"] = src_geo["latitude"]
        edge["src_lon"] = src_geo["longitude"]
        edge["dst_lat"] = dst_geo["latitude"]
        edge["dst_lon"] = dst_geo["longitude"]
        edge["src_city"] = src_geo["city"]
        edge["dst_city"] = dst_geo["city"]
        edge["src_country"] = src_geo["country"]
        edge["dst_country"] = dst_geo["country"]
        edge["src_flag"] = src_geo.get("flag", "🌐")
        edge["dst_flag"] = dst_geo.get("flag", "🌐")
        valid_edges.append(edge)

    graph["edges"] = valid_edges
    return graph


@router.get("/topology_geo")
async def get_topology_geo(
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(150, ge=1, le=500),
    active_only: bool = Query(True, description="Only return live sessions whose application or socket is currently alive."),
    max_age_seconds: int = Query(75, ge=10, le=3600, description="Max inactivity age for live sessions."),
    db: AsyncSession = Depends(get_db),
):
    """Optimized geographic projection endpoint for world map visualization."""
    return await get_topology(min_risk=min_risk, limit=limit, active_only=active_only, max_age_seconds=max_age_seconds, db=db)


@router.get("/geoip/{ip}")
async def get_ip_geo(ip: str):
    """Lookup real geographic location, ISP/Organization, and country for an IP."""
    return resolve_ip_geo(ip)


@router.get("/topology/summary")
async def get_topology_summary(db: AsyncSession = Depends(get_db)):
    """Lightweight summary: node and edge counts, high-risk IPs, kill-chain distribution."""
    stmt = select(SessionDB).order_by(SessionDB.latest_risk_score.desc()).limit(500)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    sessions = [
        {
            "session_key": s.session_key,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "predicted_stage": s.latest_stage or "Benign",
            "latest_risk_score": float(s.latest_risk_score or 0.0),
            "flow_count": s.flow_count or 0,
        }
        for s in rows
    ]
    graph = build_session_graph(sessions)
    return {
        "node_count": graph["node_count"],
        "edge_count": graph["edge_count"],
        "high_risk_nodes": graph["high_risk_nodes"],
        "high_risk_count": len(graph["high_risk_nodes"]),
        "kill_chain_summary": graph["kill_chain_summary"],
    }
