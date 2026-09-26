"""
System control routes — Mode toggle (Live vs Simulated), simulator control,
and simulated data purging.
"""
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import DB_DIR
from ..database import AlertDB, FlowRecordDB, SessionDB, get_db
from ..network_identity import get_host_identity
from ..network_state import tracker as network_tracker

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/system", tags=["System"])


class SystemState:
    mode: str = "live"
    simulator_proc: Optional[subprocess.Popen] = None

    @classmethod
    def is_simulator_running(cls) -> bool:
        if cls.simulator_proc is not None:
            if cls.simulator_proc.poll() is None:
                return True
            cls.simulator_proc = None
        return False

    @classmethod
    def stop_simulator(cls) -> bool:
        if cls.simulator_proc is not None:
            try:
                cls.simulator_proc.terminate()
                cls.simulator_proc.wait(timeout=2.0)
            except Exception:
                try:
                    cls.simulator_proc.kill()
                except Exception:
                    pass
            cls.simulator_proc = None
            return True
        return False


class ModeUpdateRequest(BaseModel):
    mode: str


@router.get("/mode")
async def get_system_mode():
    """Get current operating mode and simulator status."""
    return {
        "mode": SystemState.mode,
        "allow_simulation": SystemState.mode == "simulated",
        "simulator_running": SystemState.is_simulator_running(),
    }


@router.post("/mode")
async def set_system_mode(req: ModeUpdateRequest):
    """
    Switch between 'live' and 'simulated' modes.
    When switching to 'live', automatically stops any running simulator.
    """
    new_mode = req.mode.strip().lower()
    if new_mode not in ("live", "simulated"):
        raise HTTPException(
            status_code=400,
            detail="Invalid mode. Must be 'live' or 'simulated'.",
        )

    SystemState.mode = new_mode
    if new_mode == "live":
        stopped = SystemState.stop_simulator()
        if stopped:
            logger.info("Switched to LIVE mode — stopped background simulator.")

    logger.info("System operating mode changed to: %s", new_mode.upper())
    return {
        "mode": SystemState.mode,
        "allow_simulation": SystemState.mode == "simulated",
        "simulator_running": SystemState.is_simulator_running(),
    }


class SimulatorStartRequest(BaseModel):
    speed: float = 1.0
    sessions: int = 4
    scenario: str = "full_kill_chain"
    auto_switch_mode: bool = True


@router.post("/simulator/start")
async def start_simulator(
    req: Optional[SimulatorStartRequest] = None,
    speed: Optional[float] = None,
    sessions: Optional[int] = None,
    scenario: Optional[str] = None,
):
    """
    Launch traffic simulator subprocess.
    Auto-switches operating mode to 'simulated' if requested.
    """
    req_speed = (req.speed if req else None) or speed or 1.0
    req_sessions = (req.sessions if req else None) or sessions or 4
    req_scenario = (req.scenario if req else None) or scenario or "full_kill_chain"
    auto_switch = req.auto_switch_mode if req else True

    if SystemState.mode != "simulated":
        if auto_switch:
            SystemState.mode = "simulated"
            logger.info("Auto-switched system operating mode to SIMULATED for traffic simulator.")
        else:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Simulator cannot be started in LIVE mode. "
                    "Switch mode to 'Simulated' in Settings first."
                ),
            )

    if SystemState.is_simulator_running():
        return {
            "status": "already_running",
            "pid": SystemState.simulator_proc.pid if SystemState.simulator_proc else None,
            "mode": SystemState.mode,
        }

    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    project_root = os.path.dirname(backend_dir)
    sim_script = os.path.join(project_root, "demo", "traffic_simulator.py")

    if not os.path.exists(sim_script):
        raise HTTPException(
            status_code=404,
            detail=f"Traffic simulator script not found at {sim_script}",
        )

    # Prefer virtual environment python binary if available
    venv_python = os.path.join(backend_dir, "venv", "Scripts", "python.exe")
    python_exe = venv_python if os.path.exists(venv_python) else sys.executable

    log_path = os.path.join(DB_DIR, "simulator.log")
    os.makedirs(DB_DIR, exist_ok=True)

    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"[{datetime.now(timezone.utc).isoformat()}] Project Garud Cyber Attack Traffic Simulator\n")
        f.write(f"Scenario Preset: {req_scenario} | Sessions: {req_sessions} | Speed: {req_speed}s\n")
        f.write("=" * 70 + "\n\n")

    cmd = [
        python_exe,
        "-u",  # Unbuffered output
        sim_script,
        "--api", "http://127.0.0.1:8000",
        "--sessions", str(req_sessions),
        "--speed", str(req_speed),
        "--scenario", req_scenario,
    ]

    try:
        log_fp = open(log_path, "a", encoding="utf-8", buffering=1)
        proc = subprocess.Popen(
            cmd,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
        )
        SystemState.simulator_proc = proc
        logger.info("Traffic simulator launched (PID %d) with scenario '%s'", proc.pid, req_scenario)
        return {
            "status": "started",
            "pid": proc.pid,
            "mode": SystemState.mode,
            "scenario": req_scenario,
            "speed": req_speed,
            "sessions": req_sessions,
        }
    except Exception as e:
        logger.error("Failed to launch traffic simulator: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to start simulator: {e}")


@router.get("/simulator/status")
async def get_simulator_status():
    """Get real-time simulator status and stream latest terminal log lines."""
    running = SystemState.is_simulator_running()
    logs = ""
    log_path = os.path.join(DB_DIR, "simulator.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                logs = "".join(lines[-200:])
        except Exception as e:
            logs = f"Error reading simulator logs: {e}"

    return {
        "running": running,
        "mode": SystemState.mode,
        "pid": SystemState.simulator_proc.pid if running and SystemState.simulator_proc else None,
        "logs": logs,
    }


@router.post("/simulator/stop")
async def stop_simulator():
    """Stop the running traffic simulator."""
    was_running = SystemState.stop_simulator()
    log_path = os.path.join(DB_DIR, "simulator.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"\n[{datetime.now(timezone.utc).isoformat()}] Simulation stopped by operator.\n")
        except Exception:
            pass
    return {"status": "stopped", "was_running": was_running}


@router.post("/purge-simulated")
async def purge_simulated_data(db: AsyncSession = Depends(get_db)):
    """
    Delete all simulated flows, sessions, and alerts from the database.
    Leaves real live capture and CSV data completely untouched.
    """
    from sqlalchemy import select
    res = await db.execute(select(SessionDB.session_key).where(SessionDB.source == "simulated"))
    sim_keys = [r[0] for r in res.all()]

    deleted_alerts = 0
    deleted_flows = 0
    deleted_sessions = 0

    if sim_keys:
        stmt_alerts = delete(AlertDB).where(AlertDB.session_key.in_(sim_keys))
        del_a = await db.execute(stmt_alerts)
        deleted_alerts = del_a.rowcount or 0

    stmt_flows = delete(FlowRecordDB).where(FlowRecordDB.source == "simulated")
    del_f = await db.execute(stmt_flows)
    network_tracker.reset("simulated")
    deleted_flows = del_f.rowcount or 0

    stmt_sessions = delete(SessionDB).where(SessionDB.source == "simulated")
    del_s = await db.execute(stmt_sessions)
    deleted_sessions = del_s.rowcount or 0

    await db.commit()
    logger.info(
        "Purged simulated data: %d flows, %d sessions, %d alerts deleted",
        deleted_flows,
        deleted_sessions,
        deleted_alerts,
    )
    return {
        "status": "purged",
        "deleted_flows": deleted_flows,
        "deleted_sessions": deleted_sessions,
        "deleted_alerts": deleted_alerts,
    }


ARCHIVE_DIR = DB_DIR / "archives"
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


class CycleState:
    cycle_id: str = ""
    started_at: datetime = datetime.now(timezone.utc)
    _initialized: bool = False

    @classmethod
    def ensure_initialized(cls) -> None:
        """Ensure cycle state is initialized if accessed outside lifespan."""
        if not cls._initialized or not cls.cycle_id:
            cls.initialize()

    @classmethod
    def initialize(cls, force: bool = False) -> str:
        """Explicitly initialize or reset monitoring cycle."""
        if not cls._initialized or force or not cls.cycle_id:
            now = datetime.now(timezone.utc)
            cls.cycle_id = now.strftime("cycle_%Y%m%d_%H%M%S")
            cls.started_at = now
            cls._initialized = True
        return cls.cycle_id


def _compute_wellbeing_score(total_flows: int, alerts: list, max_stage: str) -> float:
    """
    Calculate an interpretable Network Wellbeing Score (0 to 100%).
    100 = completely pristine, healthy baseline.
    Deductions applied for attacks, anomalies, and active compromise stages.
    """
    if total_flows == 0:
        return 100.0

    score = 100.0

    for a in alerts:
        sev = (a.get("severity") or "").lower()
        if sev == "critical":
            score -= 15.0
        elif sev == "high":
            score -= 8.0
        elif sev == "medium":
            score -= 4.0
        elif sev == "low":
            score -= 1.0

    stage_penalties = {
        "Exfiltration": 35.0,
        "C2": 25.0,
        "Lateral Movement": 15.0,
        "Initial Access": 10.0,
        "Reconnaissance": 5.0,
        "Benign": 0.0,
    }
    score -= stage_penalties.get(max_stage, 0.0)

    return round(max(0.0, min(100.0, score)), 1)


async def archive_and_reset_cycle(db: AsyncSession, reason: str = "manual") -> dict:
    """
    Archive all active flows, sessions, and alerts into a timestamped JSON file,
    then clear active tables and reset in-memory buffers for a fresh cycle.
    """
    from sqlalchemy import func, select

    from ..ingestion import _session_buffers

    now = datetime.now(timezone.utc)
    CycleState.ensure_initialized()
    archive_id = CycleState.cycle_id

    sess_res = await db.execute(select(SessionDB))
    sessions = sess_res.scalars().all()

    alert_res = await db.execute(select(AlertDB))
    alerts = alert_res.scalars().all()

    flow_cnt_res = await db.execute(select(func.count(FlowRecordDB.id)))
    total_flows = flow_cnt_res.scalar() or 0

    max_stage = "Benign"
    app_flow_counts = {}
    for s in sessions:
        if s.max_stage_reached and s.max_stage_reached != "Benign":
            max_stage = s.max_stage_reached
        app = s.app_name or s.process_name or "Unknown"
        app_flow_counts[app] = app_flow_counts.get(app, 0) + (s.flow_count or 1)

    alerts_data = [
        {
            "id": a.id,
            "session_key": a.session_key,
            "severity": a.severity,
            "infiltration_prob": a.infiltration_prob,
            "predicted_stage": a.predicted_stage,
            "recommended_action": a.recommended_action,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "acknowledged": a.acknowledged,
        }
        for a in alerts
    ]

    sessions_data = [
        {
            "session_key": s.session_key,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "flow_count": s.flow_count,
            "latest_risk_score": s.latest_risk_score,
            "latest_stage": s.latest_stage,
            "max_stage_reached": s.max_stage_reached,
            "direction": s.direction,
            "process_name": getattr(s, "process_name", None),
            "app_name": getattr(s, "app_name", None),
            "tot_fwd_pkts": getattr(s, "tot_fwd_pkts", 0),
            "tot_bwd_pkts": getattr(s, "tot_bwd_pkts", 0),
            "source": s.source,
            "first_seen": s.first_seen.isoformat() if s.first_seen else None,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        }
        for s in sessions
    ]

    wellbeing = _compute_wellbeing_score(total_flows, alerts_data, max_stage)

    archive_doc = {
        "cycle_id": archive_id,
        "started_at": CycleState.started_at.isoformat(),
        "archived_at": now.isoformat(),
        "reason": reason,
        "stats": {
            "total_flows": total_flows,
            "total_sessions": len(sessions_data),
            "total_alerts": len(alerts_data),
            "max_stage": max_stage,
            "wellbeing_score": wellbeing,
            "top_apps": [
                {"name": k, "flows": v}
                for k, v in sorted(app_flow_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ],
        },
        "sessions": sessions_data,
        "alerts": alerts_data,
    }

    if total_flows > 0 or len(sessions_data) > 0 or reason == "manual":
        archive_file = ARCHIVE_DIR / f"{archive_id}.json"
        try:
            with open(archive_file, "w", encoding="utf-8") as f:
                json.dump(archive_doc, f, indent=2)
            logger.info("Archived cycle %s to %s (%d flows, %d sessions)",
                        archive_id, archive_file.name, total_flows, len(sessions_data))
        except Exception as e:
            logger.error("Failed to write cycle archive: %s", e)

    await db.execute(delete(FlowRecordDB))
    await db.execute(delete(SessionDB))
    await db.execute(delete(AlertDB))
    await db.commit()

    _session_buffers.clear()

    new_cycle_id = CycleState.initialize(force=True)

    logger.info("Initialized fresh cycle: %s", new_cycle_id)
    return {
        "status": "cycle_reset",
        "previous_cycle_id": archive_id,
        "new_cycle_id": new_cycle_id,
        "started_at": now.isoformat(),
        "archived_flows": total_flows,
        "archived_sessions": len(sessions_data),
        "wellbeing_score": wellbeing,
    }


@router.post("/cycle/start")
async def start_new_cycle(db: AsyncSession = Depends(get_db)):
    """
    Manually start a fresh monitoring cycle.
    Archives previous cycle data and clears the active flow dashboard.
    """
    return await archive_and_reset_cycle(db, reason="manual")


@router.get("/cycle/current")
async def get_current_cycle():
    """Get active cycle metadata."""
    CycleState.ensure_initialized()
    return {
        "cycle_id": CycleState.cycle_id,
        "started_at": CycleState.started_at.isoformat(),
        "elapsed_seconds": (datetime.now(timezone.utc) - CycleState.started_at).total_seconds(),
    }


@router.get("/cycles")
async def list_archived_cycles():
    """List all archived cycles with health and wellbeing metrics."""
    cycles = []
    if not ARCHIVE_DIR.exists():
        return []

    for file_path in sorted(ARCHIVE_DIR.glob("cycle_*.json"), reverse=True):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
                cycles.append({
                    "cycle_id": doc.get("cycle_id", file_path.stem),
                    "started_at": doc.get("started_at"),
                    "archived_at": doc.get("archived_at"),
                    "reason": doc.get("reason", "unknown"),
                    "stats": doc.get("stats", {}),
                })
        except Exception as e:
            logger.warning("Error reading archive %s: %s", file_path.name, e)

    return cycles


@router.get("/cycles/{cycle_id}")
async def get_archived_cycle_detail(cycle_id: str):
    """Retrieve full session and alert contents of a past cycle."""
    file_path = ARCHIVE_DIR / f"{cycle_id}.json"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Cycle archive '{cycle_id}' not found")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading cycle: {e}")


@router.get("/host-identity")
async def get_host_network_identity():
    """Retrieve local machine hostname, active adapters, and local IPs."""
    return get_host_identity()

