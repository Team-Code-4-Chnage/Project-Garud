"""MITRE ATT&CK interpretation routes (analyst-written lookup, not a model prediction)."""
from fastapi import APIRouter, HTTPException

from ..mitre import full_mapping, lookup

router = APIRouter(prefix="/mitre", tags=["MITRE"])


@router.get("/mapping")
async def mapping():
    """Whole behaviour and legacy-stage mapping with rationale and confidence for each entry."""
    return full_mapping()


@router.get("/lookup/{label}")
async def lookup_label(label: str):
    entry = lookup(label)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"No MITRE interpretation for '{label}'")
    return entry
