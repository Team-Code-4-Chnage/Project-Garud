"""
Graph-based network representation endpoint (SIH 2026 PS:26153).

Exposes the session-derived directed IP graph via REST so the frontend (and
demo) can query it.  Two endpoints:

  GET /graph/topology          — full graph from all active sessions
  GET /graph/topology/summary  — lightweight counts only (for polling)
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import SessionDB, get_db
from ..graph_state import build_session_graph

router = APIRouter(prefix="/graph", tags=["Graph Topology"])


@router.get("/topology")
async def get_topology(
    min_risk: float = Query(
        0.0,
        ge=0.0,
        le=1.0,
        description="Only include sessions whose risk score is at or above this threshold.",
    ),
    limit: int = Query(200, ge=1, le=1000, description="Maximum sessions to include."),
    db: AsyncSession = Depends(get_db),
):
    """
    Return a directed graph of IP↔IP relationships derived from active sessions.

    Each node is an observed IP address; each edge is a session between two IPs.
    Nodes carry `max_risk` (highest infiltration probability across their sessions)
    and `max_stage` (the most advanced kill-chain stage seen).  Edges carry the
    current stage label and infiltration probability of the session.

    This satisfies the PS 26153 requirement for a **graph-based representation of
    network state** — the graph evolves in real time as new flows are ingested.
    """
    stmt = select(SessionDB).order_by(SessionDB.latest_risk_score.desc()).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    sessions = []
    for s in rows:
        prob = float(s.latest_risk_score or 0.0)
        if prob < min_risk:
            continue
        sessions.append({
            "session_key": s.session_key,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "predicted_stage": s.predicted_stage,
            "latest_risk_score": prob,
            "flow_count": s.flow_count or 0,
            "source": s.source,
        })

    graph = build_session_graph(sessions)
    graph["sessions_included"] = len(sessions)
    graph["filter_applied"] = {"min_risk": min_risk, "limit": limit}
    return graph


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
            "predicted_stage": s.predicted_stage,
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
