"""
POST /ingest/pcap — parse PCAP network captures and ingest extracted flows.
Uses capture/flow_table.py (Scapy) to rebuild flows and the 22 model features exactly as the
training data defines them.
"""
import logging
import os

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..flow_state import FlowState  # noqa: F401  (re-exported for tests)
from ..schemas import IngestResponse
from ..upload_ingest import ingest_pcap_path, is_pcap, save_upload

PcapFlowState = FlowState

logger = logging.getLogger(__name__)
router = APIRouter()



@router.post("/ingest/pcap", response_model=IngestResponse, response_model_by_alias=True)
async def ingest_pcap(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest network traffic from an uploaded .pcap or .pcapng file (any size).
    Reconstructs bi-directional flows, computes the 22 CIC-IDS features exactly as the training data
    defines them, and feeds them through the attack forecasting engine.
    """
    path = await save_upload(file)
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
        if not is_pcap(head):
            raise HTTPException(status_code=422, detail="File must be a PCAP or PCAPNG capture")
        return await ingest_pcap_path(path, db)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
