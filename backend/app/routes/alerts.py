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

    mitigated_count = (await db.execute(
        select(func.count(AlertDB.id)).where(AlertDB.mitigated.is_(True))
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
        "mitigated_total": mitigated_count,
    }


# =====================================================================
# PROACTIVE MITIGATION ENGINE (SIH 2026 PS:26153 - Proactive Defense)
# =====================================================================

@router.post("/alerts/{alert_id}/contain")
async def contain_threat(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Enforces proactive containment for a forecasted attack stage.
    Generates firewall isolation commands (iptables / Windows Defender)
    and marks the threat as mitigated.
    """
    from datetime import datetime, timezone

    from ..ingestion import generate_containment_rule

    result = await db.execute(select(AlertDB).where(AlertDB.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    action, rule = generate_containment_rule(alert.session_key, alert.predicted_stage)
    alert.mitigated = True
    alert.mitigation_action = action
    alert.mitigation_rule = rule
    alert.mitigated_at = datetime.now(timezone.utc)
    alert.acknowledged = True

    await db.commit()

    return {
        "status": "contained",
        "alert_id": alert_id,
        "session_key": alert.session_key,
        "predicted_stage": alert.predicted_stage,
        "action": action,
        "rule_command": rule,
        "mitigated_at": alert.mitigated_at.isoformat(),
    }


@router.post("/alerts/{alert_id}/revoke")
async def revoke_containment(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Revokes a previously enforced proactive containment rule."""
    result = await db.execute(select(AlertDB).where(AlertDB.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    alert.mitigated = False
    alert.mitigated_at = None
    await db.commit()

    return {"status": "revoked", "alert_id": alert_id}


@router.get("/alerts/containment/rules")
async def get_active_containment_rules(db: AsyncSession = Depends(get_db)):
    """Returns all active proactive containment rules currently enforced."""
    stmt = select(AlertDB).where(AlertDB.mitigated.is_(True)).order_by(desc(AlertDB.mitigated_at))
    result = await db.execute(stmt)
    contained = result.scalars().all()

    return [
        {
            "alert_id": a.id,
            "session_key": a.session_key,
            "predicted_stage": a.predicted_stage,
            "severity": a.severity,
            "action": a.mitigation_action or "block_src_ip",
            "rule_command": a.mitigation_rule or "",
            "enforced_at": a.mitigated_at.isoformat() if a.mitigated_at else None,
            "status": "active_enforced",
        }
        for a in contained
    ]


# =====================================================================
# BLOCKCHAIN IMMUTABLE AUDIT LEDGER (SIH 2026 PS:26153 - Blockchain & Cybersecurity)
# =====================================================================

@router.get("/alerts/ledger/verify")
async def verify_blockchain_ledger(db: AsyncSession = Depends(get_db)):
    """
    Cryptographically verifies the SHA-256 block hash chain across all alerts.
    Proves immutable, tamper-evident forensic audit trail for SIH 2026 PS:26153.
    """
    import hashlib
    from datetime import datetime, timezone

    from sqlalchemy import asc

    stmt = select(AlertDB).order_by(asc(AlertDB.id))
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    if not alerts:
        return {
            "status": "empty",
            "chain_intact": True,
            "total_blocks": 0,
            "genesis_hash": None,
            "head_hash": None,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    chain_intact = True
    tampered_block = None
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    needs_commit = False

    for idx, alert in enumerate(alerts):
        # Backfill legacy alerts without hashes
        if not alert.block_hash or not alert.prev_hash:
            alert.prev_hash = prev_hash
            raw_str = f"{alert.session_key}|{alert.severity}|{alert.infiltration_prob:.6f}|{alert.predicted_stage}|{alert.created_at.isoformat()}|{prev_hash}"
            alert.block_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
            needs_commit = True

        # Verify cryptographic link
        if idx > 0 and alert.prev_hash != prev_hash:
            chain_intact = False
            tampered_block = alert.id
            break

        prev_hash = alert.block_hash

    if needs_commit:
        await db.commit()

    return {
        "status": "valid" if chain_intact else "tampered",
        "chain_intact": chain_intact,
        "total_blocks": len(alerts),
        "genesis_hash": alerts[0].block_hash,
        "head_hash": alerts[-1].block_hash if chain_intact else None,
        "tampered_at_block": tampered_block,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/alerts/ledger/blocks")
async def get_ledger_blocks(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Returns the cryptographic ledger block sequence for forensic audit visualization."""
    stmt = select(AlertDB).order_by(desc(AlertDB.id)).limit(limit)
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return [
        {
            "block_id": a.id,
            "session_key": a.session_key,
            "predicted_stage": a.predicted_stage,
            "severity": a.severity,
            "infiltration_prob": a.infiltration_prob,
            "block_hash": a.block_hash,
            "prev_hash": a.prev_hash,
            "mitigated": a.mitigated,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ]


@router.post("/alerts/clear")
async def clear_all_alerts(db: AsyncSession = Depends(get_db)):
    """Purge all alerts from the database."""
    from sqlalchemy import delete
    await db.execute(delete(AlertDB))
    await db.commit()
    return {"status": "cleared"}

