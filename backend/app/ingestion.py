"""
Flow ingestion logic — accepts raw flow records, validates, scales, buffers
into windows, auto-runs prediction, creates alerts, broadcasts via WebSocket.

Fixes applied:
  BUG-01  — broadcast() now called after db.commit() so Live Logs actually receive events
  BUG-02  — _session_buffers evicted via TTL sweep in evict_stale_buffers()
  §7      — data provenance (source field) stored per flow and per session
  §11A    — RFC1918-based traffic direction classification on session create
  §5 (KillChain flapping) — max_stage_reached is monotonic (never decreases)
"""
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import (
    ADAPTIVE_EMA_ALPHA,
    ADAPTIVE_SIGMA_MULTIPLIER,
    ADAPTIVE_THRESHOLD_ENABLED,
    DEFAULT_THRESHOLD,
    FLOW_FEATURES,
    SESSION_TIME_BUCKET_SECONDS,
    STAGES,
    WINDOW_SIZE,
)
from .database import AlertDB, FlowRecordDB, SessionDB
from .inference import predict_single
from .live import broadcast
from .model_loader import artifacts
from .network_identity import classify_ip_identity
from .process_resolver import resolve_process
from .schemas import FlowRecord

logger = logging.getLogger(__name__)

_session_buffers: dict[str, dict] = defaultdict(
    lambda: {"flows": [], "last_updated": datetime.now(timezone.utc)}
)

_BUFFER_TTL_SECONDS = SESSION_TIME_BUCKET_SECONDS * 2


def evict_stale_buffers():
    """
    Remove buffer entries that haven't been updated in >TTL seconds.
    Call periodically (e.g., from a background task) or opportunistically
    during ingestion to prevent unbounded memory growth.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_BUFFER_TTL_SECONDS)
    stale = [k for k, v in _session_buffers.items() if v["last_updated"] < cutoff]
    for k in stale:
        del _session_buffers[k]
    if stale:
        logger.info("Evicted %d stale session buffers", len(stale))
    return len(stale)


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_private(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def classify_direction(src_ip: Optional[str], dst_ip: Optional[str]) -> str:
    """
    Classify traffic direction using RFC1918 private-range heuristic.
    Returns "inbound" | "outbound" | "internal" | "unknown"
    """
    src_private = _is_private(src_ip)
    dst_private = _is_private(dst_ip)

    if src_private and dst_private:
        return "internal"
    elif not src_private and dst_private:
        return "inbound"
    elif src_private and not dst_private:
        return "outbound"
    return "unknown"


def derive_session_key(src_ip: Optional[str], dst_ip: Optional[str],
                       timestamp: Optional[datetime] = None) -> str:
    """
    Group flows into sessions by (src_ip, dst_ip, time_bucket).
    Falls back to a counter-based key if IPs aren't provided.
    """
    src = src_ip or "unknown"
    dst = dst_ip or "unknown"
    if timestamp:
        bucket = int(timestamp.timestamp()) // SESSION_TIME_BUCKET_SECONDS
    else:
        bucket = int(datetime.now(timezone.utc).timestamp()) // SESSION_TIME_BUCKET_SECONDS
    return f"{src}->{dst}@{bucket}"


def _severity_from_prob(prob: float) -> str:
    if prob >= 0.8:
        return "critical"
    elif prob >= 0.6:
        return "high"
    elif prob >= DEFAULT_THRESHOLD:
        return "medium"
    return "low"


def _recommended_action(stage: str, session_key: str) -> str:
    """
    Playbook-style recommendation template keyed on predicted MITRE stage.
    These are rule-based templates, not model-generated text.
    """
    parts = session_key.split("->")
    src = parts[0] if len(parts) > 0 else "source"
    dst = parts[1].split("@")[0] if len(parts) > 1 else "destination"

    actions = {
        "Reconnaissance": f"Investigate port scanning activity from {src}. Check firewall logs for SYN sweeps targeting {dst}.",
        "Initial Access": f"Block suspicious authentication attempts from {src} to {dst}. Review access logs for brute-force patterns.",
        "Lateral Movement": f"Isolate {dst} from internal network. Audit lateral connections from {src} for credential reuse.",
        "C2": f"Inspect outbound traffic from {dst} for beaconing patterns. Check DNS queries for DGA indicators.",
        "Exfiltration": f"URGENT: Block outbound data transfer from {dst}. Capture traffic for forensic analysis. Check for large file uploads.",
        "Benign": "No action required — traffic appears normal.",
    }
    return actions.get(stage, f"Review traffic between {src} and {dst}.")


def _stage_index(stage: str) -> int:
    """Return the integer index of a stage name, or 0 for Benign."""
    try:
        return STAGES.index(stage)
    except ValueError:
        return 0


async def ingest_single_flow(
    flow: FlowRecord,
    db: AsyncSession,
) -> dict:
    """
    Process a single flow record:
    1. Validate + extract features
    2. Store raw record in DB (with provenance)
    3. Scale and buffer for windowing
    4. If window is full → run prediction
    5. If alert → persist alert
    6. Broadcast result via WebSocket (BUG-01 fix)

    Returns dict with prediction results (if window was full) or buffer status.
    """
    if not artifacts.is_loaded:
        raise RuntimeError("Model not loaded — cannot ingest flows")

    # Features are used exactly as received. They must already follow the training definitions
    # (CICFlowMeter output; capture/flow_state.py reproduces it). Short flows keep their real duration
    # and rates: the training data has no duration floor, and a floor here would change what the
    # model sees for most scan and probe flows.
    raw_features = np.array([flow.to_feature_array()], dtype=np.float32)

    if np.any(~np.isfinite(raw_features)):
        raise ValueError("Flow contains NaN or Inf values — rejected")

    import random
    if random.random() < 0.01:
        evict_stale_buffers()

    session_key = derive_session_key(flow.src_ip, flow.dst_ip, flow.timestamp)
    source = getattr(flow, "source", None) or "api"

    src_identity = classify_ip_identity(flow.src_ip)
    dst_identity = classify_ip_identity(flow.dst_ip)

    if src_identity == "HOST" and dst_identity != "HOST":
        direction = "outbound"
        port_for_proc = getattr(flow, "src_port", None)
    elif dst_identity == "HOST" and src_identity != "HOST":
        direction = "inbound"
        port_for_proc = getattr(flow, "dst_port", None)
    elif src_identity == "HOST" and dst_identity == "HOST":
        direction = "internal"
        port_for_proc = getattr(flow, "src_port", None) or getattr(flow, "dst_port", None)
    else:
        direction = classify_direction(flow.src_ip, flow.dst_ip)
        port_for_proc = getattr(flow, "src_port", None) or getattr(flow, "dst_port", None)

    proc_info = resolve_process(port_for_proc, getattr(flow, "protocol", "TCP"))
    process_name = getattr(flow, "process_name", None) or proc_info.get("process_name")
    app_name = getattr(flow, "app_name", None) or proc_info.get("app_name")
    app_icon = proc_info.get("app_icon", "network")

    db_record = FlowRecordDB(
        session_key=session_key,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=getattr(flow, "src_port", None),
        dst_port=getattr(flow, "dst_port", None),
        protocol=getattr(flow, "protocol", "TCP") or "TCP",
        process_name=process_name,
        app_name=app_name,
        direction=direction,
        src_identity=src_identity,
        dst_identity=dst_identity,
        timestamp=flow.timestamp or datetime.now(timezone.utc),
        source=source,
        **{f: getattr(flow, f) for f in FLOW_FEATURES},
    )
    db.add(db_record)

    result = await db.execute(
        select(SessionDB).where(SessionDB.session_key == session_key)
    )
    session = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    fwd_pkts = float(getattr(flow, "tot_fwd_pkts", 0) or 0)
    bwd_pkts = float(getattr(flow, "tot_bwd_pkts", 0) or 0)

    if session is None:
        session = SessionDB(
            session_key=session_key,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            flow_count=1,
            first_seen=now,
            last_seen=now,
            source=source,
            direction=direction,
            process_name=process_name,
            app_name=app_name,
            tot_fwd_pkts=fwd_pkts,
            tot_bwd_pkts=bwd_pkts,
            src_identity=src_identity,
            dst_identity=dst_identity,
            max_stage_reached="Benign",
        )
        db.add(session)
    else:
        session.flow_count += 1
        session.last_seen = now
        session.tot_fwd_pkts = (session.tot_fwd_pkts or 0.0) + fwd_pkts
        session.tot_bwd_pkts = (session.tot_bwd_pkts or 0.0) + bwd_pkts
        if process_name and not session.process_name:
            session.process_name = process_name
        if app_name and not session.app_name:
            session.app_name = app_name
        if session.direction == "unknown" and direction != "unknown":
            session.direction = direction
        if not session.src_identity and src_identity:
            session.src_identity = src_identity
        if not session.dst_identity and dst_identity:
            session.dst_identity = dst_identity

    scaled = artifacts.scale_features(raw_features)[0]
    buf = _session_buffers[session_key]
    buf["flows"].append(scaled)
    buf["last_updated"] = now

    if len(buf["flows"]) > WINDOW_SIZE * 2:
        buf["flows"] = buf["flows"][-WINDOW_SIZE:]

    result_data = {
        "session_key": session_key,
        "buffer_size": len(buf["flows"]),
        "prediction": None,
        "alert": None,
        "heartbleed_alert": None,
    }

    if getattr(flow, "heartbleed_signature", False):
        session.latest_risk_score = 1.0
        session.latest_stage = "Exfiltration"
        current_max_idx = _stage_index(session.max_stage_reached or "Benign")
        if _stage_index("Exfiltration") > current_max_idx:
            session.max_stage_reached = "Exfiltration"
        db_record.infiltration_prob = 1.0
        db_record.predicted_stage = "Exfiltration"

        heartbleed_action = (
            "CVE-2014-0160 (Heartbleed) signature detected: malformed TLS "
            "Heartbeat payload_length exceeds the record's actual size. "
            "Isolate host and patch OpenSSL immediately. This is a "
            "deterministic wire-format signature match, not an ML inference."
        )
        heartbleed_alert = AlertDB(
            session_key=session_key,
            severity="critical",
            infiltration_prob=1.0,
            predicted_stage="Exfiltration",
            recommended_action=heartbleed_action,
            created_at=now,
        )
        db.add(heartbleed_alert)
        result_data["heartbleed_alert"] = {
            "severity": "critical",
            "predicted_stage": "Exfiltration",
            "infiltration_prob": 1.0,
            "recommended_action": heartbleed_action,
            "signature": "heartbleed_cve_2014_0160",
        }

    if len(buf["flows"]) >= WINDOW_SIZE:
        window = np.array(buf["flows"][-WINDOW_SIZE:], dtype=np.float32)
        prediction = predict_single(window)
        result_data["prediction"] = prediction

        predicted_stage = prediction["predicted_stage"]

        session.latest_risk_score = prediction["infiltration_probability"]
        session.latest_stage = predicted_stage

        current_max_idx = _stage_index(session.max_stage_reached or "Benign")
        new_stage_idx = _stage_index(predicted_stage)
        if new_stage_idx > current_max_idx:
            session.max_stage_reached = predicted_stage

        db_record.infiltration_prob = prediction["infiltration_probability"]
        db_record.predicted_stage = predicted_stage

        prob = prediction["infiltration_probability"]
        effective_threshold = DEFAULT_THRESHOLD
        is_alert = prediction["is_alert"]

        if ADAPTIVE_THRESHOLD_ENABLED:
            prev_ema = buf.get("prob_ema")
            if prev_ema is None:
                buf["prob_ema"] = prob
                buf["prob_var"] = 0.0
            else:
                diff = prob - prev_ema
                buf["prob_ema"] = (1 - ADAPTIVE_EMA_ALPHA) * prev_ema + ADAPTIVE_EMA_ALPHA * prob
                buf["prob_var"] = (1 - ADAPTIVE_EMA_ALPHA) * buf.get("prob_var", 0.0) + ADAPTIVE_EMA_ALPHA * (diff ** 2)

            std = float(np.sqrt(max(0.0, buf.get("prob_var", 0.0))))
            adaptive_thresh = min(0.95, max(DEFAULT_THRESHOLD, buf["prob_ema"] + ADAPTIVE_SIGMA_MULTIPLIER * std))
            effective_threshold = round(adaptive_thresh, 4)
            is_alert = prob > effective_threshold

        prediction["is_alert"] = is_alert
        prediction["effective_threshold"] = effective_threshold

        if is_alert:
            severity = _severity_from_prob(prob)
            action = _recommended_action(predicted_stage, session_key)

            alert = AlertDB(
                session_key=session_key,
                severity=severity,
                infiltration_prob=prob,
                predicted_stage=predicted_stage,
                recommended_action=action,
                created_at=now,
            )
            db.add(alert)
            result_data["alert"] = {
                "severity": severity,
                "predicted_stage": predicted_stage,
                "infiltration_prob": prob,
                "recommended_action": action,
                "effective_threshold": effective_threshold,
            }

    await db.commit()

    try:
        event_type = "alert" if (result_data["alert"] or result_data["heartbleed_alert"]) else (
            "prediction" if result_data["prediction"] else "flow_ingested"
        )
        await broadcast({
            "type": event_type,
            "session_key": session_key,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": getattr(flow, "src_port", None),
            "dst_port": getattr(flow, "dst_port", None),
            "protocol": getattr(flow, "protocol", "TCP") or "TCP",
            "direction": direction,
            "source": source,
            "process_name": process_name,
            "app_name": app_name,
            "app_icon": app_icon,
            "src_identity": src_identity,
            "dst_identity": dst_identity,
            "tot_fwd_pkts": fwd_pkts,
            "tot_bwd_pkts": bwd_pkts,
            "flow_bytes_s": getattr(flow, "flow_bytes_s", 0.0),
            "flow_pkts_s": getattr(flow, "flow_pkts_s", 0.0),
            "flow_count": session.flow_count,
            "infiltration_prob": (
                result_data["heartbleed_alert"]["infiltration_prob"]
                if result_data["heartbleed_alert"]
                else result_data["prediction"]["infiltration_probability"]
                if result_data["prediction"] else None
            ),
            "predicted_stage": (
                result_data["heartbleed_alert"]["predicted_stage"]
                if result_data["heartbleed_alert"]
                else result_data["prediction"]["predicted_stage"]
                if result_data["prediction"] else None
            ),
            "is_alert": bool(result_data["alert"] or result_data["heartbleed_alert"]),
            "max_stage_reached": session.max_stage_reached,
            "alert": result_data["alert"],
            "heartbleed_alert": result_data["heartbleed_alert"],
            "timestamp": now.isoformat(),
        })
    except Exception as exc:
        logger.warning("WebSocket broadcast failed (non-fatal): %s", exc)

    return result_data


def clear_session_buffer(session_key: str):
    """Clear the in-memory buffer for a session."""
    _session_buffers.pop(session_key, None)


def get_buffer_status() -> dict:
    """Return current buffer status for debugging."""
    return {
        key: len(val["flows"]) for key, val in _session_buffers.items()
    }
