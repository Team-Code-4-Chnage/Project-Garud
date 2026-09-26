"""
WebSocket /ws/live — real-time flow feed + sessions list endpoint.

BUG-01 fix: _active_connections and broadcast() moved to live.py to allow
ingestion.py to import broadcast without a circular dependency.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import FlowRecordDB, SessionDB, get_db
from ..live import (  # noqa: F401 (re-exported for convenience)
    broadcast,
    register,
    unregister,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/ws/live")
@router.websocket("/api/packets/ws")
async def websocket_live_feed(
    websocket: WebSocket,
    session_key: Optional[str] = Query(None),
):
    """
    WebSocket endpoint for real-time flow events.
    Clients can optionally filter by session_key (?session_key=...).
    """
    await websocket.accept()
    register(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        unregister(websocket)
    except Exception as e:
        logger.debug("WebSocket client disconnected: %s", e)
        unregister(websocket)


@router.get("/sessions")
async def get_sessions(
    limit: int = Query(50, ge=1, le=200),
    sort_by: str = Query("last_seen", description="Sort field: last_seen, latest_risk_score, flow_count"),
    source: Optional[str] = Query(None, description="Filter by source: live, simulated, or all"),
    active_within_seconds: Optional[int] = Query(
        None, ge=1,
        description="Only return sessions whose last_seen is within this many seconds "
                     "(e.g. 300 for a true 'currently active' view). Omit for full history.",
    ),
    db: AsyncSession = Depends(get_db),
):
    """Get tracked sessions with their latest risk scores."""
    sort_col = {
        "last_seen": desc(SessionDB.last_seen),
        "latest_risk_score": desc(SessionDB.latest_risk_score),
        "flow_count": desc(SessionDB.flow_count),
    }.get(sort_by, desc(SessionDB.last_seen))

    stmt = select(SessionDB)
    if source == "live":
        stmt = stmt.where(SessionDB.source != "simulated")
    elif source == "simulated":
        stmt = stmt.where(SessionDB.source == "simulated")
    if active_within_seconds is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_within_seconds)
        stmt = stmt.where(SessionDB.last_seen >= cutoff)

    stmt = stmt.order_by(sort_col).limit(limit)
    result = await db.execute(stmt)
    sessions = result.scalars().all()

    return [
        {
            "id": s.id,
            "session_key": s.session_key,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "flow_count": s.flow_count,
            "latest_risk_score": s.latest_risk_score,
            "latest_stage": s.latest_stage,
            "max_stage_reached": s.max_stage_reached,
            "direction": s.direction,
            "process_name": s.process_name,
            "app_name": s.app_name,
            "tot_fwd_pkts": s.tot_fwd_pkts or 0,
            "tot_bwd_pkts": s.tot_bwd_pkts or 0,
            "src_identity": s.src_identity,
            "dst_identity": s.dst_identity,
            "source": s.source,
            "first_seen": s.first_seen.isoformat() if s.first_seen else None,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        }
        for s in sessions
    ]


@router.get("/sessions/{session_key}/flows")
async def get_session_flows(
    session_key: str,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Get flow records for a specific session (for building forecast windows)."""
    stmt = (
        select(FlowRecordDB)
        .where(FlowRecordDB.session_key == session_key)
        .order_by(desc(FlowRecordDB.timestamp))
        .limit(limit)
    )
    result = await db.execute(stmt)
    flows = result.scalars().all()

    from ..config import FLOW_FEATURES
    return [
        {
            "id": f.id,
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol or "TCP",
            "process_name": f.process_name,
            "app_name": f.app_name,
            "direction": f.direction,
            "src_identity": f.src_identity,
            "dst_identity": f.dst_identity,
            "features": {feat: getattr(f, feat) for feat in FLOW_FEATURES},
            "infiltration_prob": f.infiltration_prob,
            "predicted_stage": f.predicted_stage,
            "source": f.source,
        }
        for f in flows
    ]


@router.get("/dashboard/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Aggregate stats for the dashboard header."""
    total_sessions = await db.execute(select(func.count(SessionDB.id)))
    total_flows = await db.execute(select(func.count(FlowRecordDB.id)))
    active_alerts = await db.execute(
        select(func.count()).select_from(
            select(SessionDB).where(SessionDB.latest_risk_score > 0.5).subquery()
        )
    )

    from .system import SystemState
    sim_count = await db.execute(
        select(func.count(SessionDB.id)).where(SessionDB.source == "simulated")
    )
    has_simulated = (SystemState.mode == "simulated") and ((sim_count.scalar() or 0) > 0)

    dir_rows = await db.execute(
        select(SessionDB.direction, func.count(SessionDB.id)).group_by(SessionDB.direction)
    )
    dir_map = {row[0]: row[1] for row in dir_rows.all() if row[0]}

    return {
        "total_sessions": total_sessions.scalar() or 0,
        "total_flows": total_flows.scalar() or 0,
        "at_risk_sessions": active_alerts.scalar() or 0,
        "has_simulated_data": has_simulated,
        "direction_breakdown": {
            "inbound": dir_map.get("inbound", 0),
            "outbound": dir_map.get("outbound", 0),
            "internal": dir_map.get("internal", 0),
        },
    }


@router.get("/dashboard/stage-distribution")
async def stage_distribution(db: AsyncSession = Depends(get_db)):
    """Count flows grouped by predicted_stage for reports."""
    stmt = (
        select(
            FlowRecordDB.predicted_stage,
            func.count(FlowRecordDB.id).label("count"),
        )
        .where(FlowRecordDB.predicted_stage.isnot(None))
        .group_by(FlowRecordDB.predicted_stage)
        .order_by(func.count(FlowRecordDB.id).desc())
    )
    result = await db.execute(stmt)
    rows = result.all()
    return [{"stage": row[0], "count": row[1]} for row in rows]


@router.get("/flows/recent")
async def get_recent_flows(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Get the most recent flow records across all sessions for live feed bootstrapping."""
    stmt = (
        select(FlowRecordDB)
        .order_by(desc(FlowRecordDB.timestamp), desc(FlowRecordDB.id))
        .limit(limit)
    )
    result = await db.execute(stmt)
    flows = result.scalars().all()
    return [
        {
            "id": f.id,
            "session_key": f.session_key,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol or "TCP",
            "direction": f.direction,
            "source": f.source,
            "process_name": f.process_name,
            "app_name": f.app_name,
            "src_identity": f.src_identity,
            "dst_identity": f.dst_identity,
            "tot_fwd_pkts": f.tot_fwd_pkts or 0,
            "tot_bwd_pkts": f.tot_bwd_pkts or 0,
            "flow_bytes_s": f.flow_bytes_s or 0.0,
            "flow_pkts_s": f.flow_pkts_s or 0.0,
            "flow_duration": f.flow_duration or 0.0,
            "infiltration_prob": f.infiltration_prob,
            "predicted_stage": f.predicted_stage,
            "is_alert": (f.infiltration_prob or 0.0) > 0.5 or (bool(f.predicted_stage) and f.predicted_stage != "Benign"),
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            "_ts": f.timestamp.isoformat() if f.timestamp else None,
        }
        for f in flows
    ]

