"""GET /alerts — real alert data from SQLite. POST /alerts/{id}/acknowledge."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import AlertDB, get_db
from ..schemas import AlertOut

router = APIRouter()


@router.get("/alerts", response_model=list[AlertOut])
async def get_alerts(
    severity: str | None = Query(None, description="Filter by severity: critical, high, medium, low"),
    acknowledged: bool | None = Query(None, description="Filter by acknowledged status"),
    stage: str | None = Query(None, description="Filter by MITRE stage"),
    search: str | None = Query(None, description="Search session key, stage, or playbook action"),
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AlertDB).order_by(desc(AlertDB.created_at))

    if severity and severity.lower() != "all":
        stmt = stmt.where(func.lower(AlertDB.severity) == severity.lower().strip())
    if acknowledged is not None:
        stmt = stmt.where(AlertDB.acknowledged == acknowledged)
    if stage and stage.lower() != "all":
        stmt = stmt.where(func.lower(AlertDB.predicted_stage).ilike(f"%{stage.lower().strip()}%"))
    if search and search.strip():
        search_pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                AlertDB.session_key.ilike(search_pattern),
                AlertDB.predicted_stage.ilike(search_pattern),
                AlertDB.recommended_action.ilike(search_pattern),
                AlertDB.severity.ilike(search_pattern),
            )
        )

    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return [AlertOut.model_validate(a) for a in alerts]


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(AlertDB).where(AlertDB.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    alert.acknowledged = True
    await db.commit()
    return {"status": "acknowledged", "alert_id": alert_id}


@router.post("/alerts/acknowledge-all")
async def acknowledge_all_alerts(db: AsyncSession = Depends(get_db)):
    """Acknowledge all pending unacknowledged alerts in a single bulk transaction."""
    result = await db.execute(
        select(AlertDB).where(AlertDB.acknowledged.is_(False))
    )
    unack_alerts = result.scalars().all()
    count = len(unack_alerts)
    for a in unack_alerts:
        a.acknowledged = True
    await db.commit()
    return {"status": "all_acknowledged", "count": count}


@router.get("/alerts/stats")
async def alert_stats(db: AsyncSession = Depends(get_db)):
    """Summary counts for the dashboard header and filter badge tallies."""
    total = (await db.execute(select(func.count(AlertDB.id)))).scalar() or 0
    unack = (await db.execute(
        select(func.count(AlertDB.id)).where(AlertDB.acknowledged.is_(False))
    )).scalar() or 0
    critical_unack = (await db.execute(
        select(func.count(AlertDB.id)).where(
            func.lower(AlertDB.severity) == "critical", AlertDB.acknowledged.is_(False)
        )
    )).scalar() or 0
    high_unack = (await db.execute(
        select(func.count(AlertDB.id)).where(
            func.lower(AlertDB.severity) == "high", AlertDB.acknowledged.is_(False)
        )
    )).scalar() or 0
    medium_unack = (await db.execute(
        select(func.count(AlertDB.id)).where(
            func.lower(AlertDB.severity) == "medium", AlertDB.acknowledged.is_(False)
        )
    )).scalar() or 0
    low_unack = (await db.execute(
        select(func.count(AlertDB.id)).where(
            func.lower(AlertDB.severity) == "low", AlertDB.acknowledged.is_(False)
        )
    )).scalar() or 0

    critical_total = (await db.execute(
        select(func.count(AlertDB.id)).where(func.lower(AlertDB.severity) == "critical")
    )).scalar() or 0
    high_total = (await db.execute(
        select(func.count(AlertDB.id)).where(func.lower(AlertDB.severity) == "high")
    )).scalar() or 0
    medium_total = (await db.execute(
        select(func.count(AlertDB.id)).where(func.lower(AlertDB.severity) == "medium")
    )).scalar() or 0
    low_total = (await db.execute(
        select(func.count(AlertDB.id)).where(func.lower(AlertDB.severity) == "low")
    )).scalar() or 0

    return {
        "total": total,
        "unacknowledged": unack,
        "acknowledged": max(0, total - unack),
        "critical_unacknowledged": critical_unack,
        "high_unacknowledged": high_unack,
        "medium_unacknowledged": medium_unack,
        "low_unacknowledged": low_unack,
        "critical_total": critical_total,
        "high_total": high_total,
        "medium_total": medium_total,
        "low_total": low_total,
    }


@router.post("/alerts/clear")
async def clear_all_alerts(db: AsyncSession = Depends(get_db)):
    """Purge all alerts from the database."""
    from sqlalchemy import delete
    await db.execute(delete(AlertDB))
    await db.commit()
    return {"status": "cleared"}

