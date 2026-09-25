"""Network-state world model routes (per-minute network state, 4-minute forecast, sustained alert)."""
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from ..network_state import tracker

router = APIRouter(prefix="/network", tags=["Network State"])


@router.get("/sources")
async def sources():
    """Traffic sources with recorded flows, most recent first."""
    return tracker.sources()


@router.get("/forecast")
async def forecast(source: Optional[str] = Query(None, description="defaults to the most recently active source")):
    """Per-minute network state and risk history, sustained-alert status, and the t+1..t+4 forecast."""
    if source is None:
        srcs = tracker.sources()
        if not srcs:
            return {"status": "no_data"}
        source = srcs[0]["source"]
    result = tracker.analyze(source)
    if result.get("status") == "model_unavailable":
        raise HTTPException(status_code=503, detail=result.get("detail"))
    return result


@router.post("/reset")
async def reset(source: Optional[str] = None):
    tracker.reset(source)
    return {"reset": source or "all"}
