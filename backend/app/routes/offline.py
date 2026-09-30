"""
Offline analysis of uploaded files. Nothing here reads or writes the live system's tables.
"""
import io

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from ..offline_analysis import OfflineError, analyze_offline, convert_to_garud_csv, remove_quietly
from ..upload_ingest import save_upload

router = APIRouter(prefix="/offline", tags=["Offline Analysis"])


@router.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """
    Analyse a flow table (CSV/TSV, optionally gzip; CICFlowMeter, Zeek, NetFlow, UNSW-NB15 or Garud
    columns) or a PCAP/PCAPNG capture, without adding anything to the live system. There is no size limit.
    Returns per-flow scores, a per-minute timeline, the network-state forecast for the end of the file,
    and label-based results if the file carries labels.
    """
    path = await save_upload(file)
    try:
        return await run_in_threadpool(analyze_offline, path, file.filename or "")
    except OfflineError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    finally:
        remove_quietly(path)


@router.post("/convert")
async def convert(file: UploadFile = File(...)):
    """Return the uploaded file converted to this project's flow-CSV layout (22 features plus identity)."""
    path = await save_upload(file)
    try:
        df = await run_in_threadpool(convert_to_garud_csv, path)
    except (OfflineError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    finally:
        remove_quietly(path)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    name = (file.filename or "flows").rsplit(".", 1)[0]
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}_garud.csv"'})
