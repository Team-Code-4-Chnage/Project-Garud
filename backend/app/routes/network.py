"""Network-state world model routes (per-minute network-wide state, 4-minute forecast, sustained alert).

There is exactly one forecast, combining every recorded flow regardless of source or IP. `/network/sources`
is informational only (flow counts by ingestion source); it never selects or filters what is forecast.
"""
from typing import Optional

from fastapi import APIRouter, HTTPException

from ..network_state import tracker

router = APIRouter(prefix="/network", tags=["Network State"])


@router.get("/sources")
async def sources():
    """Total recorded flows and a breakdown by ingestion source, for information only."""
    return tracker.summary()


@router.get("/forecast")
async def forecast():
    """Combined network-wide state history, sustained-alert status, and the t+1..t+4 forecast."""
    result = tracker.analyze()
    if result.get("status") in ("model_unavailable", "model_error"):
        raise HTTPException(status_code=503, detail=result.get("detail"))
    return result


@router.post("/reset")
async def reset(source: Optional[str] = None):
    tracker.reset(source)
    return {"reset": source or "all"}
