"""
Reads a flow table of unknown container and layout into text DataFrames (every cell a string).

Recognised by content, not by file name:
  - packet captures (PCAP, PCAPNG) are reported as such, not read here;
  - gzip and zip containers (the first data member is used);
  - Parquet;
  - JSON arrays, JSON lines and nested records (Suricata eve.json flow events), flattened to dotted names;
  - Zeek logs (#fields header, tab separated, "-" for unset);
  - delimited text with any of , ; tab | as separator, UTF-8 / UTF-16 with or without BOM, comment lines,
    blank lines, ragged rows, and files with no header when they hold the 22 model features in order.

The reader yields chunks so that a file is never held in memory as one object.
"""
from __future__ import annotations

import csv
import gzip
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Iterator

import pandas as pd

from .config import FLOW_FEATURES

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
CHUNK_ROWS = 50_000
UNSET = ["-", "(empty)", "", "nan", "NaN", "null", "NULL", "None", "N/A", "n/a"]


class UnreadableFile(ValueError):
    """The file is empty, of an unsupported type, or cannot be parsed. The message says what to do."""


@dataclass
class Source:
    """Where the bytes really are after unpacking containers."""
    path: str
    kind: str                       # pcap | parquet | json | zeek | delimited
    container: str | None = None    # gzip | zip
    temp: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def cleanup(self) -> None:
        for p in self.temp:
            try:
                os.remove(p)
            except OSError:
                pass


def _head(path: str, n: int = 65536) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def _unpack(path: str) -> tuple[str, str | None, list[str]]:
    """Strip gzip/zip containers (repeatedly). Returns (path, container, temp files created)."""
    temp, container = [], None
    for _ in range(3):
        head = _head(path, 4)
        if head[:2] == b"\x1f\x8b":
            fd, out = tempfile.mkstemp(prefix="garud_unpack_")
            with gzip.open(path, "rb") as src, os.fdopen(fd, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            temp.append(out)
            path, container = out, container or "gzip"
        elif head[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(path) as z:
                members = [i for i in z.infolist() if not i.is_dir() and not i.filename.startswith("__MACOSX")]
                if any(i.filename.startswith("xl/") for i in members):
                    raise UnreadableFile("This is an Excel workbook. Save it as CSV and upload that.")
                if not members:
                    raise UnreadableFile("The zip archive is empty.")
                member = max(members, key=lambda i: i.file_size)
                fd, out = tempfile.mkstemp(prefix="garud_unpack_")
                with z.open(member) as src, os.fdopen(fd, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
            temp.append(out)
            path, container = out, container or "zip"
        else:
            break
    return path, container, temp


def _decode_head(head: bytes) -> tuple[str, str]:
    """(text of the head, encoding) handling UTF-8/16 with BOM."""
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if head.startswith(bom):
            return head.decode(enc, errors="replace"), enc
    if b"\x00" in head[:200]:
        return head.decode("utf-16", errors="replace"), "utf-16"
    return head.decode("utf-8", errors="replace"), "utf-8"


def open_source(path: str) -> Source:
    path, container, temp = _unpack(path)
    head = _head(path)
    if not head.strip():
        raise UnreadableFile("The file is empty.")
    if head[:4] in PCAP_MAGIC:
        return Source(path, "pcap", container, temp)
    if head[:4] == b"PAR1":
        return Source(path, "parquet", container, temp)
    text, _ = _decode_head(head)
    stripped = text.lstrip()
    if stripped.startswith("#separator") or stripped.startswith("#fields"):
        return Source(path, "zeek", container, temp)
    if stripped[:1] in "[{":
        return Source(path, "json", container, temp)
    return Source(path, "delimited", container, temp)


# --- delimited text ------------------------------------------------------------------------------------

def _sniff_delimiter(sample_lines: list[str]) -> str:
    lines = [ln for ln in sample_lines if ln.strip() and not ln.lstrip().startswith("#")][:50]
    if not lines:
        return ","
    try:
        return csv.Sniffer().sniff("\n".join(lines[:20]), delimiters=",;\t|").delimiter
    except csv.Error:
        pass
    best, best_score = ",", -1.0
    for d in (",", "\t", ";", "|"):
        counts = [ln.count(d) for ln in lines]
        if counts[0] == 0:
            continue
        consistent = sum(1 for c in counts if c == counts[0]) / len(counts)
        score = consistent * counts[0]
        if score > best_score:
            best, best_score = d, score
    return best


def _looks_numeric(cell: str) -> bool:
    try:
        float(str(cell).strip().replace(",", "."))
        return True
    except ValueError:
        return False


def _read_delimited(src: Source) -> Iterator[pd.DataFrame]:
    head = _head(src.path)
    text, enc = _decode_head(head)
    lines = text.splitlines()
    sep = _sniff_delimiter(lines)
    if sep == ";":
        src.notes.append("semicolon-separated file: commas inside numbers are read as decimal commas")
    first = next((ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")), "")
    cells = next(csv.reader([first], delimiter=sep), [])
    headerless = bool(cells) and sum(_looks_numeric(c) for c in cells) / len(cells) > 0.8
    kwargs = dict(sep=sep, dtype=str, encoding=enc, encoding_errors="replace", on_bad_lines="skip",
                  comment="#", skip_blank_lines=True, na_values=UNSET, keep_default_na=False,
                  chunksize=CHUNK_ROWS, low_memory=False)
    if headerless:
        if len(cells) == len(FLOW_FEATURES):
            kwargs["header"] = None
            kwargs["names"] = list(FLOW_FEATURES)
            src.notes.append("no header row: the 22 columns are taken as the model features in their standard order")
        else:
            raise UnreadableFile(
                f"The file has no header row and {len(cells)} numeric columns. Add a header line with column "
                f"names, or provide exactly {len(FLOW_FEATURES)} columns in the order: {', '.join(FLOW_FEATURES)}.")
    try:
        reader = pd.read_csv(src.path, **kwargs)
        for chunk in reader:
            if sep == ";":
                chunk = chunk.apply(lambda col: col.str.replace(",", ".", regex=False) if col.dtype == object else col)
            yield chunk
    except pd.errors.EmptyDataError as exc:
        raise UnreadableFile("The file has no rows.") from exc
    except pd.errors.ParserError as exc:
        raise UnreadableFile(f"The file could not be parsed as a table: {exc}") from exc


# --- Zeek ----------------------------------------------------------------------------------------------

def _read_zeek(src: Source) -> Iterator[pd.DataFrame]:
    names = None
    unset, empty = "-", "(empty)"
    with open(src.path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#fields"):
                names = line.rstrip("\n").split("\t")[1:]
            elif line.startswith("#unset_field"):
                unset = line.rstrip("\n").split("\t")[1]
            elif line.startswith("#empty_field"):
                empty = line.rstrip("\n").split("\t")[1]
            elif not line.startswith("#"):
                break
    if not names:
        raise UnreadableFile("Zeek log without a #fields header.")
    for chunk in pd.read_csv(src.path, sep="\t", comment="#", names=names, header=None, dtype=str,
                             na_values=[unset, empty], keep_default_na=False, chunksize=CHUNK_ROWS,
                             encoding_errors="replace", on_bad_lines="skip"):
        yield chunk


# --- JSON ----------------------------------------------------------------------------------------------

def _flatten(records: list) -> pd.DataFrame:
    df = pd.json_normalize(records, sep="_")
    return df.astype("string")


def _read_json(src: Source) -> Iterator[pd.DataFrame]:
    with open(src.path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.read(1)
        fh.seek(0)
        if first == "[":
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise UnreadableFile(f"Invalid JSON: {exc}") from exc
            if not isinstance(data, list) or not all(isinstance(r, dict) for r in data[:100]):
                raise UnreadableFile("The JSON array must contain one object per flow.")
            for i in range(0, len(data), CHUNK_ROWS):
                yield _flatten(data[i:i + CHUNK_ROWS])
            return
        batch, bad = [], 0
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(rec, dict):
                batch.append(rec)
            if len(batch) >= CHUNK_ROWS:
                yield _flatten(batch)
                batch = []
        if batch:
            yield _flatten(batch)
        if bad:
            src.notes.append(f"{bad} JSON lines could not be parsed and were skipped")


def _read_parquet(src: Source) -> Iterator[pd.DataFrame]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise UnreadableFile("Parquet needs the pyarrow package on the server.") from exc
    pf = pq.ParquetFile(src.path)
    for batch in pf.iter_batches(batch_size=CHUNK_ROWS):
        yield batch.to_pandas().astype("string")


def read_chunks(src: Source) -> Iterator[pd.DataFrame]:
    """Text DataFrames of the table, in file order."""
    reader = {"delimited": _read_delimited, "zeek": _read_zeek, "json": _read_json, "parquet": _read_parquet}.get(src.kind)
    if reader is None:
        raise UnreadableFile("This file is not a table.")
    any_rows = False
    for chunk in reader(src):
        chunk = chunk.dropna(how="all")
        if len(chunk):
            any_rows = True
            yield chunk
    if not any_rows:
        raise UnreadableFile("The file has a header but no data rows.")
