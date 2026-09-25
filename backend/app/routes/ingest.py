"""
POST /ingest — single flow record or CSV batch upload.
Real ingestion: validate → scale → buffer → predict → alert.
"""
import csv
import io
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import FLOW_FEATURES
from ..database import get_db
from ..ingestion import get_buffer_status, ingest_single_flow
from ..schemas import FlowRecord, IngestResponse, SingleFlowIngestResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/ingest", response_model=SingleFlowIngestResponse)
async def ingest_flow(
    flow: FlowRecord,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a single flow record."""
    if getattr(flow, "source", None) == "simulated":
        from .system import SystemState
        if SystemState.mode == "live":
            raise HTTPException(
                status_code=403,
                detail=(
                    "Simulation traffic rejected: system is in LIVE-ONLY mode. "
                    "Switch mode to 'Simulated' in Settings to allow synthetic flows."
                ),
            )

    try:
        result = await ingest_single_flow(flow, db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/ingest/csv", response_model=IngestResponse)
async def ingest_csv(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Batch ingest from a CSV file upload."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=422, detail="File must be a CSV")

    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))

    accepted = 0
    rejected = 0
    errors = []
    alerts_generated = 0

    for row_num, row in enumerate(reader, start=2):
        try:
            flow_data = {}
            for feat in FLOW_FEATURES:
                val = row.get(feat)
                if val is None:
                    raise ValueError(f"Missing column: {feat}")
                try:
                    flow_data[feat] = float(val)
                except (ValueError, TypeError):
                    raise ValueError(f"Non-numeric value for {feat}: {val!r}")

            flow_data["src_ip"] = row.get("src_ip") or row.get("Src IP") or row.get("Source IP")
            flow_data["dst_ip"] = row.get("dst_ip") or row.get("Dst IP") or row.get("Destination IP")
            # optional context used by the network-state model (unique ports, protocol mix)
            for key, names in (("src_port", ("src_port", "Source Port")), ("dst_port", ("dst_port", "Destination Port"))):
                raw = next((row.get(n) for n in names if row.get(n) not in (None, "")), None)
                if raw is not None:
                    flow_data[key] = int(float(raw))
            proto = row.get("protocol") or row.get("Protocol")
            if proto:
                flow_data["protocol"] = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(str(proto).split(".")[0], str(proto))
            flow_data["source"] = "csv_upload"

            ts_raw = row.get("timestamp") or row.get("Timestamp")
            if ts_raw:
                try:
                    flow_data["timestamp"] = datetime.fromisoformat(ts_raw)
                except ValueError:
                    flow_data["timestamp"] = None

            flow = FlowRecord(**flow_data)
            result = await ingest_single_flow(flow, db)
            accepted += 1

            if result.get("alert") or result.get("heartbleed_alert"):
                alerts_generated += 1

        except (ValueError, TypeError, KeyError) as e:
            rejected += 1
            if len(errors) < 20:
                errors.append(f"Row {row_num}: {str(e)}")

    return IngestResponse(
        flows_accepted=accepted,
        flows_rejected=rejected,
        errors=errors,
        alerts_generated=alerts_generated,
    )


@router.get("/ingest/buffer-status")
async def buffer_status():
    """Debug endpoint: show current session buffer sizes."""
    return get_buffer_status()
