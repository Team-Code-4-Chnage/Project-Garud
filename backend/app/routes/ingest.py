"""
POST /ingest — single flow record or CSV batch upload.
Real ingestion: validate → scale → buffer → predict → alert.
"""
import logging
import os

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..ingestion import get_buffer_status, ingest_single_flow
from ..schemas import FlowRecord, IngestResponse, SingleFlowIngestResponse
from ..upload_ingest import ingest_path, save_upload

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
    except Exception as e:
        logger.exception("Unexpected error during flow ingestion: %s", e)
        raise HTTPException(status_code=500, detail=f"Flow ingestion error: {str(e)}")


async def _handle_upload(file: UploadFile, db: AsyncSession, expect: str | None = None) -> dict:
    path = await save_upload(file)
    try:
        result = await ingest_path(path, db, file.filename or "")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    if expect and result["input_kind"] != expect:
        raise HTTPException(status_code=422, detail=f"The file content is a {result['input_kind']}, not a {expect}.")
    return result


@router.post("/ingest/csv", response_model=IngestResponse, response_model_by_alias=True)
async def ingest_csv(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    """Batch-ingest a flow table into the live system (sessions, alerts, live forecast). For analysis that must not touch the live system use POST /offline/analyze."""
    return await _handle_upload(file, db, expect="table")


@router.get("/ingest/buffer-status")
async def buffer_status():
    """Debug endpoint: show current session buffer sizes."""
    return get_buffer_status()
