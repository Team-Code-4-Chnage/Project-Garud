"""
Upload ingestion into the live system (POST /ingest/csv and /ingest/pcap): any flow table or capture.

The file is streamed to disk and processed in chunks, so there is no size limit other than free disk
space. Tables are converted to the 22 model features by flow_schema.adapt_frame; captures go through the
same flow reconstruction as live capture. Flows are scored in bulk (one commit per batch, no per-flow
GeoIP or WebSocket work).
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any

import pandas as pd
from fastapi import HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession

from .flow_schema import SchemaError, adapt_frame, is_malicious_label
from .ingestion import BulkContext, ingest_single_flow
from .schemas import FlowRecord
from .table_reader import PCAP_MAGIC, UnreadableFile, open_source, read_chunks

logger = logging.getLogger(__name__)

COMMIT_EVERY = 500
MAX_ERRORS = 20
NULL_TEXT = {"", "nan", "none", "null", "-", "(empty)"}


def is_pcap(head: bytes) -> bool:
    return head[:4] in PCAP_MAGIC


async def save_upload(file: UploadFile) -> str:
    """Copy the upload to a temporary file in 1 MiB steps and return its path."""
    suffix = os.path.splitext(file.filename or "")[1] or ".upload"
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="garud_upload_")
    try:
        with os.fdopen(fd, "wb") as out:
            await run_in_threadpool(shutil.copyfileobj, file.file, out, 1024 * 1024)
    except Exception:
        os.remove(path)
        raise
    return path


def _clean(value: Any) -> Any:
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return None
    if isinstance(value, str) and value.strip().lower() in NULL_TEXT:
        return None
    return value


async def ingest_path(path: str, db: AsyncSession, filename: str = "") -> dict:
    try:
        src = open_source(path)
    except UnreadableFile as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    try:
        if src.kind == "pcap":
            return await ingest_pcap_path(src.path, db)
        return await ingest_table(src, db)
    finally:
        src.cleanup()


async def ingest_table(src, db: AsyncSession) -> dict:
    accepted = rejected = alerts = rows_read = 0
    errors: list[str] = []
    report: dict[str, Any] | None = None
    nonfinite = ts_unparsed = 0
    evaluation = dict(labelled_rows=0, labelled_malicious=0, flagged=0, true_positive=0, false_positive=0,
                      scored_rows=0)
    labels: dict[str, int] = {}
    pending = 0
    ctx = BulkContext()

    try:
        for chunk in read_chunks(src):
            try:
                feats, meta, rep = await run_in_threadpool(adapt_frame, chunk)
            except SchemaError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            if report is None:
                report = rep
            nonfinite += rep["nonfinite_values_set_to_zero"]
            ts_unparsed += rep.get("timestamps_unparsed", 0)

            values = feats.to_dict("records")
            metas = meta.to_dict("records")
            for i, (fv, mv) in enumerate(zip(values, metas)):
                row_no = rows_read + i + 2
                try:
                    rec = dict(fv)
                    for k in ("src_ip", "dst_ip", "protocol"):
                        rec[k] = _clean(mv.get(k))
                    for k in ("src_port", "dst_port"):
                        v = _clean(mv.get(k))
                        rec[k] = int(v) if v is not None else None
                    ts = mv.get("timestamp")
                    rec["timestamp"] = None if ts is None or pd.isna(ts) else ts.to_pydatetime()
                    rec["source"] = "csv_upload"
                    flow = FlowRecord(**rec)
                    result = await ingest_single_flow(flow, db, bulk=True, ctx=ctx)
                    accepted += 1
                    pending += 1
                    pred = result.get("prediction")
                    flagged = bool(result.get("alert") or result.get("heartbleed_alert")
                                   or (pred and pred.get("is_alert")))
                    if result.get("alert") or result.get("heartbleed_alert"):
                        alerts += 1
                    label = _clean(mv.get("label"))
                    truth = is_malicious_label(label) if label is not None else None
                    if truth is not None:
                        labels[str(label)] = labels.get(str(label), 0) + 1
                        evaluation["labelled_rows"] += 1
                        evaluation["labelled_malicious"] += int(truth)
                        if pred is not None:
                            evaluation["scored_rows"] += 1
                            evaluation["flagged"] += int(flagged)
                            evaluation["true_positive"] += int(flagged and truth)
                            evaluation["false_positive"] += int(flagged and not truth)
                    if pending >= COMMIT_EVERY:
                        await db.commit()
                        pending = 0
                except Exception as exc:  # one bad row must not stop the file
                    rejected += 1
                    if len(errors) < MAX_ERRORS:
                        errors.append(f"Row {row_no}: {exc}")
            rows_read += len(chunk)
        if pending:
            await db.commit()
    except UnreadableFile as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc))
    except HTTPException:
        await db.rollback()
        raise

    report["nonfinite_values_set_to_zero"] = nonfinite
    report["timestamps_unparsed"] = ts_unparsed
    if ts_unparsed:
        report["assumptions"].append(f"{ts_unparsed} rows have no usable timestamp; they are placed at their upload time")
    if report["missing_identity"]:
        report["assumptions"].append(f"no {', '.join(report['missing_identity'])} column: those rows are ungrouped")
    return dict(
        flows_accepted=accepted, flows_rejected=rejected, errors=errors, alerts_generated=alerts,
        input_kind="table", rows_read=rows_read, schema=report,
        evaluation=evaluation if evaluation["labelled_rows"] else None,
        label_counts=labels or None,
    )


async def ingest_pcap_path(path: str, db: AsyncSession) -> dict:
    try:
        from capture.flow_table import flows_from_pcap
    except ImportError:
        raise HTTPException(status_code=500, detail="Scapy is not installed on the backend server")
    try:
        flows = await run_in_threadpool(flows_from_pcap, path)
    except Exception as exc:
        logger.error("Failed to parse PCAP file: %s", exc)
        raise HTTPException(status_code=422, detail=f"Failed to parse PCAP file: {exc}")

    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    accepted = rejected = alerts = pending = 0
    ctx = BulkContext()
    errors: list[str] = []
    for fs in sorted(flows, key=lambda f: f.start_time):
        try:
            rec = fs.to_features()
            rec.update(
                src_ip=fs.src_ip, dst_ip=fs.dst_ip, src_port=fs.src_port, dst_port=fs.dst_port,
                protocol=proto_map.get(fs.protocol, str(fs.protocol)), source="pcap_upload",
                heartbleed_signature=fs.heartbleed_detected,
                timestamp=(datetime.fromtimestamp(fs.start_time, tz=timezone.utc) if fs.start_time > 0
                           else datetime.now(timezone.utc)),
            )
            result = await ingest_single_flow(FlowRecord(**rec), db, bulk=True, ctx=ctx)
            accepted += 1
            pending += 1
            if result.get("alert") or result.get("heartbleed_alert"):
                alerts += 1
            if pending >= COMMIT_EVERY:
                await db.commit()
                pending = 0
        except Exception as exc:
            rejected += 1
            if len(errors) < MAX_ERRORS:
                errors.append(f"Flow {fs.src_ip}:{fs.src_port}-{fs.dst_ip}:{fs.dst_port}: {exc}")
    if pending:
        await db.commit()
    return dict(flows_accepted=accepted, flows_rejected=rejected, errors=errors, alerts_generated=alerts,
                input_kind="pcap", rows_read=len(flows), schema=None, evaluation=None, label_counts=None)
