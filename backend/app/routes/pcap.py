"""
POST /ingest/pcap — parse PCAP network captures and ingest extracted flows.
Uses capture/flow_table.py (Scapy) to rebuild flows and the 22 model features exactly as the
training data defines them.
"""
import logging
import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..flow_state import FlowState  # noqa: F401  (re-exported for tests)
from ..ingestion import ingest_single_flow
from ..schemas import FlowRecord, IngestResponse

PcapFlowState = FlowState

logger = logging.getLogger(__name__)
router = APIRouter()



@router.post("/ingest/pcap", response_model=IngestResponse)
async def ingest_pcap(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest network traffic from an uploaded .pcap or .pcapng file.
    Reconstructs bi-directional flows, computes 22 CIC-IDS features,
    and feeds them through the attack forecasting engine.
    """
    filename = (file.filename or "").lower()
    if not (filename.endswith(".pcap") or filename.endswith(".cap") or filename.endswith(".pcapng")):
        raise HTTPException(
            status_code=422,
            detail="File must be a PCAP capture (.pcap, .cap, .pcapng)",
        )

    try:
        from capture.flow_table import flows_from_pcap
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Scapy is not installed on the backend server",
        )

    content = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    errors = []
    accepted = 0
    rejected = 0
    alerts_generated = 0

    try:
        # Same flow assembly and features as live capture and as the training data
        # (CICFlowMeter semantics; parity measured by experiments/pcap_parity.py).
        flows = flows_from_pcap(tmp_path)
    except Exception as e:
        logger.error("Failed to parse PCAP file: %s", e)
        raise HTTPException(status_code=422, detail=f"Failed to parse PCAP file: {e}")
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    for flow_state in sorted(flows, key=lambda fl: fl.start_time):
        key = f"{flow_state.src_ip}:{flow_state.src_port}-{flow_state.dst_ip}:{flow_state.dst_port}-{flow_state.protocol}"
        try:
            feat_dict = flow_state.to_features()
            feat_dict["src_ip"] = flow_state.src_ip
            feat_dict["dst_ip"] = flow_state.dst_ip
            feat_dict["src_port"] = flow_state.src_port
            feat_dict["dst_port"] = flow_state.dst_port
            feat_dict["protocol"] = proto_map.get(flow_state.protocol, str(flow_state.protocol))
            feat_dict["source"] = "pcap_upload"
            feat_dict["heartbleed_signature"] = flow_state.heartbleed_detected
            feat_dict["timestamp"] = (
                datetime.fromtimestamp(flow_state.start_time, tz=timezone.utc)
                if flow_state.start_time > 0
                else datetime.now(timezone.utc)
            )

            flow_record = FlowRecord(**feat_dict)
            result = await ingest_single_flow(flow_record, db)
            accepted += 1
            if result.get("alert") or result.get("heartbleed_alert"):
                alerts_generated += 1
        except Exception as exc:
            rejected += 1
            if len(errors) < 10:
                errors.append(f"Flow {key}: {exc}")

    return IngestResponse(
        flows_accepted=accepted,
        flows_rejected=rejected,
        errors=errors,
        alerts_generated=alerts_generated,
    )
