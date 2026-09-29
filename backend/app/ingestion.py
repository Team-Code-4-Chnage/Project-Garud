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
import hashlib
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import (
    ADAPTIVE_EMA_ALPHA,
    ADAPTIVE_SIGMA_MULTIPLIER,
    ADAPTIVE_THRESHOLD_ENABLED,
    DEFAULT_THRESHOLD,
    FLOW_FEATURES,
    SESSION_IDLE_TIMEOUT_SECONDS,
    SESSION_TIME_BUCKET_SECONDS,
    STAGES,
    WINDOW_SIZE,
)
from .database import AlertDB, FlowRecordDB, SessionDB
from .drift import drift_monitor
from .inference import predict_single
from .live import broadcast
from .model_loader import artifacts
from .network_identity import classify_ip_identity
from .network_state import tracker as network_tracker
from .process_resolver import resolve_process
from .schemas import FlowRecord

logger = logging.getLogger(__name__)


def generate_containment_rule(session_key: str, predicted_stage: str) -> tuple[str, str]:
    """Generate firewall / containment commands for proactive mitigation (SIH 2026 PS:26153)."""
    src_ip = session_key.split("->")[0] if "->" in session_key else session_key
    dst_ip = session_key.split("->")[1].split("@")[0] if "->" in session_key else "target"

    if predicted_stage in ("C2", "Exfiltration"):
        action = "block_outbound"
        rule = (
            f"# Windows Defender (Egress Block):\n"
            f'netsh advfirewall firewall add rule name="Garud-Block-Egress-{dst_ip}" dir=out action=block remoteip={dst_ip}\n'
            f"# Linux iptables:\n"
            f"iptables -A OUTPUT -d {dst_ip} -j REJECT"
        )
    elif predicted_stage == "Lateral Movement":
        action = "isolate_host"
        rule = (
            f"# Windows Defender (Host Isolation):\n"
            f'netsh advfirewall firewall add rule name="Garud-Isolate-{src_ip}" dir=in action=block remoteip={src_ip}\n'
            f'netsh advfirewall firewall add rule name="Garud-Isolate-Out-{src_ip}" dir=out action=block localip={src_ip}\n'
            f"# Linux iptables:\n"
            f"iptables -A INPUT -s {src_ip} -j DROP\n"
            f"iptables -A OUTPUT -s {src_ip} -j DROP"
        )
    else:
        action = "block_src_ip"
        rule = (
            f"# Windows Defender (Inbound Block):\n"
            f'netsh advfirewall firewall add rule name="Garud-Block-{src_ip}" dir=in action=block remoteip={src_ip}\n'
            f"# Linux iptables:\n"
            f"iptables -A INPUT -s {src_ip} -j DROP"
        )
    return action, rule


async def _create_chained_alert(
    db: AsyncSession,
    session_key: str,
    severity: str,
    infiltration_prob: float,
    predicted_stage: str,
    recommended_action: str,
    now: datetime,
) -> AlertDB:
    """Creates an alert with cryptographic SHA-256 blockchain hashing and proactive mitigation rule."""
    last_hash = (
        await db.execute(
            select(AlertDB.block_hash)
            .where(AlertDB.block_hash.isnot(None))
            .order_by(desc(AlertDB.id))
            .limit(1)
        )
    ).scalar_one_or_none()

    prev_hash = last_hash or "0000000000000000000000000000000000000000000000000000000000000000"
    mit_action, mit_rule = generate_containment_rule(session_key, predicted_stage)

    raw_str = f"{session_key}|{severity}|{infiltration_prob:.6f}|{predicted_stage}|{now.isoformat()}|{prev_hash}"
    block_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    return AlertDB(
        session_key=session_key,
        severity=severity,
        infiltration_prob=infiltration_prob,
        predicted_stage=predicted_stage,
        recommended_action=recommended_action,
        created_at=now,
        mitigated=False,
        mitigation_action=mit_action,
        mitigation_rule=mit_rule,
        block_hash=block_hash,
        prev_hash=prev_hash,
    )

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
    Mint a fresh session key for (src_ip, dst_ip) starting at timestamp's time bucket.
    Used to start a new session; an ONGOING conversation is kept under its existing key by
    resolve_session_key() below, regardless of which bucket the current flow falls in.
    """
    src = src_ip or "unknown"
    dst = dst_ip or "unknown"
    if timestamp:
        bucket = int(timestamp.timestamp()) // SESSION_TIME_BUCKET_SECONDS
    else:
        bucket = int(datetime.now(timezone.utc).timestamp()) // SESSION_TIME_BUCKET_SECONDS
    return f"{src}->{dst}@{bucket}"


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def resolve_session_key(db: AsyncSession, src_ip: Optional[str], dst_ip: Optional[str],
                              timestamp: Optional[datetime] = None) -> str:
    """
    A session for one (src_ip, dst_ip) pair is one continuous conversation: as long as flows keep
    arriving within SESSION_IDLE_TIMEOUT_SECONDS of the previous one, they belong to the SAME
    session_key, no matter how many fixed time buckets that spans. Only a real gap starts a new
    session. Without this, any app with a connection open longer than one bucket (e.g. Chrome or
    Spotify streaming for more than a few minutes) would appear as several duplicate "sessions" in
    the tracked-sessions view, and the model's sliding window for that conversation would be reset
    and lose its temporal context every time the bucket rolled over.

    Continuation is judged on wall-clock arrival time (matching how SessionDB.last_seen is stamped
    below), not on the flow's own timestamp: a batch replay of old historical flows arriving within
    the same few real seconds is one session, even though their embedded timestamps span hours.
    """
    now = datetime.now(timezone.utc)
    if src_ip and dst_ip:
        result = await db.execute(
            select(SessionDB.session_key, SessionDB.last_seen)
            .where(SessionDB.src_ip == src_ip, SessionDB.dst_ip == dst_ip)
            .order_by(SessionDB.last_seen.desc())
            .limit(1)
        )
        row = result.first()
        if row is not None:
            key, last_seen = row
            if (now - _as_utc(last_seen)).total_seconds() <= SESSION_IDLE_TIMEOUT_SECONDS:
                return key
    return derive_session_key(src_ip, dst_ip, timestamp)


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


TRUSTED_HOST_PROCESSES = {
    "onedrive.sync.service.exe",
    "onedrive.exe",
    "language_server_windows_x64.exe",
    "code.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "svchost.exe",
    "antigravity.exe",
    "antigravity ide.exe",
    "explorer.exe",
    "startmenuexperiencehost.exe",
    "system",
    "backgroundtaskhost.exe",
    "searchhost.exe",
    "runtimebroker.exe",
    "msmpeng.exe",
    "mpdefendercoreservice.exe",
    "brave.exe",
    "nvcontainer.exe",
    "msedgewebview2.exe",
    "spotify.exe",
    "spotifylauncher.exe",
    "dsaservice.exe",
    "mspcmanager.exe",
    "node.exe",
    "python.exe",
    "git.exe",
}


def validate_attack_plausibility(
    stage: str,
    flow: FlowRecord,
    direction: str,
    dst_identity: str,
    process_name: Optional[str],
) -> tuple[str, bool]:
    """
    Apply domain security rules and network topology checks to prevent model false alarms
    on benign operational traffic. Returns (plausible_stage, is_valid_attack).
    """
    pname_clean = (process_name or "").lower().strip()
    is_trusted_app = any(t in pname_clean for t in TRUSTED_HOST_PROCESSES) if pname_clean else False
    is_live_capture = getattr(flow, "source", "") == "live_capture"
    dst_port = getattr(flow, "dst_port", None) or 0

    if stage == "Benign":
        return "Benign", not (is_trusted_app or is_live_capture)

    # 1. Trusted OS and productivity binaries running locally are legitimate host processes.
    if is_trusted_app:
        return "Benign", False

    # 2. Lateral Movement can NEVER be outbound to an external internet host (NAT_PEER)
    #    Lateral movement is strictly internal host-to-host pivoting (LAN_PEER / internal subnet)
    if stage == "Lateral Movement":
        if direction == "outbound" or dst_identity == "NAT_PEER" or is_live_capture:
            return "Benign", False

    # 3. Live host capture communicating over standard web ports (80, 443, 8080, 8443)
    #    or DNS (53) is normal operational traffic, not attack stages.
    if is_live_capture and dst_port in (80, 443, 53, 8080, 8443):
        return "Benign", False

    # 4. Reconnaissance: requires scan characteristics (port scan or syn sweep)
    #    Connections to standard web/DNS ports by host apps or live capture are never reconnaissance
    if stage == "Reconnaissance" and is_live_capture:
        return "Benign", False

    # 5. Initial Access / Brute Force: host traffic communicating on standard web ports is not brute force
    if stage == "Initial Access" and is_live_capture and dst_port in (80, 443, 8080, 8443):
        return "Benign", False

    return stage, True


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

    drift_monitor.record_flow(raw_features)

    import random
    if random.random() < 0.01:
        evict_stale_buffers()

    session_key = await resolve_session_key(db, flow.src_ip, flow.dst_ip, flow.timestamp)
    source = getattr(flow, "source", None) or "api"
    network_tracker.add(flow, source)  # per-minute network state for the network world model

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
            src_port=getattr(flow, "src_port", None),
            dst_port=getattr(flow, "dst_port", None),
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
        # a session can span several ports over its life (e.g. a browser opening new connections to
        # the same host); track the most recently used one, since that reflects current activity
        if getattr(flow, "src_port", None):
            session.src_port = flow.src_port
        if getattr(flow, "dst_port", None):
            session.dst_port = flow.dst_port
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
        heartbleed_alert = await _create_chained_alert(
            db=db,
            session_key=session_key,
            severity="critical",
            infiltration_prob=1.0,
            predicted_stage="Exfiltration",
            recommended_action=heartbleed_action,
            now=now,
        )
        db.add(heartbleed_alert)
        result_data["heartbleed_alert"] = {
            "severity": "critical",
            "predicted_stage": "Exfiltration",
            "infiltration_prob": 1.0,
            "recommended_action": heartbleed_action,
            "signature": "heartbleed_cve_2014_0160",
            "block_hash": heartbleed_alert.block_hash,
            "prev_hash": heartbleed_alert.prev_hash,
            "mitigation_rule": heartbleed_alert.mitigation_rule,
        }

    if len(buf["flows"]) >= WINDOW_SIZE:
        window = np.array(buf["flows"][-WINDOW_SIZE:], dtype=np.float32)
        prediction = predict_single(window)
        result_data["prediction"] = prediction

        predicted_stage = prediction["predicted_stage"]
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

        # Domain Security Sanity Check & Physical Plausibility Validation
        validated_stage, is_valid_attack = validate_attack_plausibility(
            stage=predicted_stage,
            flow=flow,
            direction=direction,
            dst_identity=dst_identity,
            process_name=process_name,
        )

        if not is_valid_attack and not result_data["heartbleed_alert"]:
            predicted_stage = "Benign"
            prediction["predicted_stage"] = "Benign"
            prediction["predicted_stage_id"] = 0
            prob = min(prob, 0.04)  # normalize nominal background risk
            prediction["infiltration_probability"] = prob
            is_alert = False
        elif is_alert and predicted_stage == "Benign" and not result_data["heartbleed_alert"]:
            # High-confidence attack flow where binary head triggered but stage argmax was Benign
            dst_port = getattr(flow, "dst_port", None) or 0
            if dst_port in (80, 443, 8080, 8443):
                predicted_stage = "Initial Access"
            else:
                predicted_stage = "Reconnaissance"
            prediction["predicted_stage"] = predicted_stage
            prediction["predicted_stage_id"] = _stage_index(predicted_stage)

        if predicted_stage == "Benign" and not result_data["heartbleed_alert"]:
            is_alert = False

        prediction["is_alert"] = is_alert
        prediction["effective_threshold"] = effective_threshold

        stage_changed = (session.latest_stage != predicted_stage)
        session.latest_risk_score = prob
        session.latest_stage = predicted_stage

        current_max_idx = _stage_index(session.max_stage_reached or "Benign")
        new_stage_idx = _stage_index(predicted_stage)
        if new_stage_idx > current_max_idx:
            session.max_stage_reached = predicted_stage

        db_record.infiltration_prob = prob
        db_record.predicted_stage = predicted_stage

        if is_alert and (predicted_stage != "Benign" or result_data["heartbleed_alert"]):
            should_create_alert = (
                stage_changed
                or session.flow_count == WINDOW_SIZE
                or (session.flow_count % 20 == 0)
            )

            if should_create_alert:
                severity = _severity_from_prob(prob)
                action = _recommended_action(predicted_stage, session_key)

                alert = await _create_chained_alert(
                    db=db,
                    session_key=session_key,
                    severity=severity,
                    infiltration_prob=prob,
                    predicted_stage=predicted_stage,
                    recommended_action=action,
                    now=now,
                )
                db.add(alert)
                result_data["alert"] = {
                    "severity": severity,
                    "predicted_stage": predicted_stage,
                    "infiltration_prob": prob,
                    "recommended_action": action,
                    "effective_threshold": effective_threshold,
                    "block_hash": alert.block_hash,
                    "prev_hash": alert.prev_hash,
                    "mitigation_rule": alert.mitigation_rule,
                }

    await db.commit()

    try:
        event_type = "alert" if (result_data["alert"] or result_data["heartbleed_alert"]) else (
            "prediction" if result_data["prediction"] else "flow_ingested"
        )
        await broadcast({
            "id": db_record.id,
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
