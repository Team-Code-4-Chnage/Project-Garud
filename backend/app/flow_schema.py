"""
Converts flow tables of different origin into the 22 features the models were trained on.

Supported by column recognition, not by file type: CICFlowMeter (CIC-IDS2017/2018, raw and
MachineLearningCSV names), Zeek conn.log, Suricata eve.json flow events, nfdump, Argus, NetFlow/IPFIX
exports, UNSW-NB15 and this project's own layout. Names are normalised (case, spaces, punctuation), so
"Flow Duration", "flow_duration" and "FLOW-DURATION" are one column.

Nothing is invented silently. For each feature the report says whether it was read directly, derived
from other columns (with the rule) or absent and set to 0, which is what the training pipeline does for
features a source cannot provide (data/preprocess_cicids.py). Units are checked against the data, not
only assumed: durations are compared with packet counts and packet rates, and a wrong unit is corrected
and reported. Everything that had to be assumed is listed in report["assumptions"].
"""
from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd

from .config import FLOW_FEATURES
from .labels import UNKNOWN, behaviour_of, is_attack_label


def norm(name: Any) -> str:
    """Lower-case, collapse every run of non-alphanumeric characters to one underscore."""
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


# --- column vocabularies (all normalised) ---------------------------------------------------------

DIRECT = {
    "flow_duration": ["flow_duration"],
    "tot_fwd_pkts": ["tot_fwd_pkts", "total_fwd_packets", "total_fwd_packet", "fwd_packets", "spkts", "orig_pkts",
                     "in_pkts", "packets_fwd", "src_pkts", "in_packets", "flow_pkts_toserver", "ipkt", "src_packets",
                     "pkts_toserver", "packets_sent"],
    "tot_bwd_pkts": ["tot_bwd_pkts", "total_backward_packets", "total_bwd_packets", "total_bwd_packet", "bwd_packets",
                     "dpkts", "resp_pkts", "out_pkts", "packets_bwd", "dst_pkts", "out_packets", "flow_pkts_toclient",
                     "opkt", "dst_packets", "pkts_toclient", "packets_received"],
    "fwd_pkt_len_mean": ["fwd_pkt_len_mean", "fwd_packet_length_mean", "fwd_seg_size_avg", "avg_fwd_segment_size"],
    "bwd_pkt_len_mean": ["bwd_pkt_len_mean", "bwd_packet_length_mean", "bwd_seg_size_avg", "avg_bwd_segment_size"],
    "flow_bytes_s": ["flow_bytes_s", "flow_byts_s", "bytes_s", "byte_rate", "bps"],
    "flow_pkts_s": ["flow_pkts_s", "flow_packets_s", "pkts_s", "packet_rate", "pps"],
    "flow_iat_mean": ["flow_iat_mean"],
    "flow_iat_std": ["flow_iat_std"],
    "fwd_iat_mean": ["fwd_iat_mean"],
    "bwd_iat_mean": ["bwd_iat_mean"],
    "syn_flag_cnt": ["syn_flag_cnt", "syn_flag_count", "syn_count", "syn"],
    "ack_flag_cnt": ["ack_flag_cnt", "ack_flag_count", "ack_count", "ack"],
    "fin_flag_cnt": ["fin_flag_cnt", "fin_flag_count", "fin_count", "fin"],
    "rst_flag_cnt": ["rst_flag_cnt", "rst_flag_count", "rst_count", "rst"],
    "psh_flag_cnt": ["psh_flag_cnt", "psh_flag_count", "psh_count", "psh"],
    "urg_flag_cnt": ["urg_flag_cnt", "urg_flag_count", "urg_count", "urg"],
    "down_up_ratio": ["down_up_ratio"],
    "pkt_size_avg": ["pkt_size_avg", "average_packet_size", "avg_packet_size", "packet_length_mean", "avg_pkt_size"],
    "ttl_variance": ["ttl_variance"],
    "tcp_win_size": ["tcp_win_size", "init_win_bytes_forward", "init_fwd_win_byts", "swin", "tcp_window_size",
                     "tcp_window"],
    "retransmit_cnt": ["retransmit_cnt", "retransmissions", "retransmits", "retrans"],
}
FWD_BYTES = ["total_length_of_fwd_packets", "totlen_fwd_pkts", "sbytes", "orig_bytes", "orig_ip_bytes", "in_bytes",
             "bytes_fwd", "src_bytes", "fwd_bytes", "flow_bytes_toserver", "ibyt", "bytes_toserver", "bytes_sent"]
BWD_BYTES = ["total_length_of_bwd_packets", "totlen_bwd_pkts", "dbytes", "resp_bytes", "resp_ip_bytes", "out_bytes",
             "bytes_bwd", "dst_bytes", "bwd_bytes", "flow_bytes_toclient", "obyt", "bytes_toclient", "bytes_received"]
TOTAL_BYTES = ["bytes", "total_bytes", "octets", "flow_bytes", "octet_delta_count", "totbytes", "byt"]
TOTAL_PKTS = ["packets", "total_packets", "pkts", "totpkts", "pkt", "packet_delta_count", "flow_packets"]
DUR_US = ["flow_duration_us", "duration_us"]
DUR_MS = ["flow_duration_ms", "duration_ms", "flow_duration_milliseconds"]
DUR_S = ["duration", "dur", "flow_duration_s", "duration_s", "flow_duration_seconds", "flow_age", "td", "flow_time"]
FWD_HDR = ["fwd_header_length", "fwd_header_len"]
BWD_HDR = ["bwd_header_length", "bwd_header_len"]
SUBFLOW_FWD = ["subflow_fwd_packets", "subflow_fwd_pkts"]
ZEEK_HISTORY = ["history", "conn_history"]
TCP_FLAGS = ["tcp_flags", "flags", "tcpflags", "flg", "flow_tcp_flags"]

SRC_IP = ["src_ip", "source_ip", "src", "srcip", "id_orig_h", "orig_h", "source_address", "saddr", "ipv4_src_addr",
          "sourceipv4address", "ip_src", "sa", "src_addr", "sourceip", "client_ip"]
DST_IP = ["dst_ip", "destination_ip", "dst", "dstip", "id_resp_h", "resp_h", "destination_address", "daddr",
          "ipv4_dst_addr", "destinationipv4address", "ip_dst", "dest_ip", "da", "dst_addr", "destinationip", "server_ip"]
SRC_PORT = ["src_port", "source_port", "sport", "srcport", "id_orig_p", "orig_p", "l4_src_port", "sp", "sourceport"]
DST_PORT = ["dst_port", "destination_port", "dport", "dstport", "id_resp_p", "resp_p", "l4_dst_port", "dest_port",
            "dp", "destinationport"]
PROTO = ["protocol", "proto", "ip_protocol", "protocol_name", "l4_proto", "protocol_identifier", "pr"]
TIME = ["timestamp", "flow_start_time", "start_time", "stime", "ts", "time", "first_seen", "flowstart",
        "first_switched", "frame_time", "flow_start", "flow_start_timestamp", "start", "begin", "datetime", "date_time",
        "event_time", "flowstartmilliseconds", "flow_start_milliseconds", "tstart"]
END_TIME = ["end_time", "flow_end_time", "etime", "te", "last_seen", "flow_end", "last_switched", "flowend", "end",
            "flowendmilliseconds", "tend"]
DATE_ONLY = ["date", "flow_date", "day"]
LABEL = ["label", "stage_label", "class", "attack_cat", "attack_type", "category", "alert_category", "attack",
         "alert_signature", "threat", "tag", "y", "target", "is_attack", "malicious", "is_malicious"]

PROTO_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMP"}

# A source must give at least this much for the models to have something real to work with.
CORE_GROUPS = {
    "duration": ["flow_duration"] + DUR_US + DUR_MS + DUR_S + ["flow_start", "start_time", "stime"],
    "packets": DIRECT["tot_fwd_pkts"] + DIRECT["tot_bwd_pkts"] + TOTAL_PKTS,
    "bytes": FWD_BYTES + BWD_BYTES + TOTAL_BYTES + DIRECT["flow_bytes_s"] + DIRECT["pkt_size_avg"],
}


class SchemaError(ValueError):
    """The table does not contain enough recognisable flow information."""


def is_malicious_label(label) -> bool | None:
    return is_attack_label(label)


def _first(cols: dict[str, str], names: list[str]) -> str | None:
    return next((cols[n] for n in names if n in cols), None)


_THOUSANDS = re.compile(r"^\s*[-+]?\d{1,3}(,\d{3})+(\.\d+)?\s*$")


def _to_num(series: pd.Series) -> pd.Series:
    """Numbers from text: thousands separators, percent signs, Infinity/NaN spellings, stray spaces."""
    if pd.api.types.is_numeric_dtype(series):
        return series.astype(float)
    num = pd.to_numeric(series, errors="coerce").astype(float)         # fast path: clean numbers
    failed = num.isna() & series.notna()
    if failed.any():                                                   # slow path only for the odd cells
        s = series[failed].astype("string").str.strip()
        thousands = s.str.match(_THOUSANDS).fillna(False)
        if thousands.any():
            s = s.where(~thousands, s.str.replace(",", "", regex=False))
        num[failed] = pd.to_numeric(s.str.rstrip("%"), errors="coerce").astype(float)
    return num


def _num(df: pd.DataFrame, col: str | None) -> pd.Series | None:
    return None if col is None else _to_num(df[col])


# --- time -----------------------------------------------------------------------------------------------

def _slash_order(s: pd.Series) -> str:
    """'day' or 'month' first for d/m/Y-style strings, decided from unambiguous rows."""
    parts = s.str.extract(r"^(\d{1,2})[/.\-](\d{1,2})[/.\-]\d{2,4}")
    a = pd.to_numeric(parts[0], errors="coerce")
    b = pd.to_numeric(parts[1], errors="coerce")
    if (a > 12).any():
        return "day"
    if (b > 12).any():
        return "month"
    return "ambiguous"


def _parse_time(series: pd.Series, notes: list[str]) -> pd.Series:
    """UTC timestamps from ISO strings, d/m/Y or m/d/Y dates, epoch numbers, Excel serials."""
    num = _to_num(series)
    if num.notna().mean() > 0.9:
        vals = num.dropna().abs()
        med = float(vals.median()) if len(vals) else 0.0
        if 20_000 < med < 80_000:
            notes.append("numeric timestamps in the range of Excel serial dates are read as days since 1899-12-30")
            return pd.to_datetime(num, unit="D", origin="1899-12-30", utc=True, errors="coerce")
        unit = "s" if med < 1e11 else "ms" if med < 1e14 else "us" if med < 1e17 else "ns"
        notes.append(f"numeric timestamps are read as epoch {unit}")
        return pd.to_datetime(num, unit=unit, utc=True, errors="coerce")
    s = series.astype("string").fillna("").str.strip()
    slash = s.str.match(r"^\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}").mean() > 0.5
    dayfirst = False
    if slash:
        order = _slash_order(s)
        dayfirst = order != "month"
        notes.append({
            "day": "dates such as 23/02/2018 are read day-first (a day above 12 was found)",
            "month": "dates such as 02/23/2018 are read month-first (a value above 12 was found in the second position)",
            "ambiguous": "all dates are valid both ways; they are read day-first (the CIC-IDS convention)",
        }[order])
    return pd.to_datetime(s, utc=True, errors="coerce", dayfirst=dayfirst)


def _clock_only(series: pd.Series) -> pd.Series | None:
    s = series.astype("string").fillna("").str.strip()
    if s.str.match(r"^\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?$").mean() < 0.9:
        return None
    return pd.to_timedelta(s.where(s.str.count(":") == 2, s + ":00"), errors="coerce")


def _history_count(hist: pd.Series, letters: str) -> pd.Series:
    return hist.fillna("").astype(str).apply(lambda h: sum(h.count(c) for c in letters)).astype(float)


def detect_format(cols: dict[str, str]) -> str:
    if "flow_duration" in cols and ("total_fwd_packets" in cols or "tot_fwd_pkts" in cols):
        return "cicflowmeter" if "total_fwd_packets" in cols else "garud"
    if "id_orig_h" in cols or "orig_h" in cols or "history" in cols:
        return "zeek_conn"
    if "flow_pkts_toserver" in cols or "dest_ip" in cols:
        return "suricata_eve"
    if "sbytes" in cols or "spkts" in cols:
        return "unsw_nb15_or_argus"
    if any(n in cols for n in ("ibyt", "ipkt", "td")):
        return "nfdump"
    if any(n in cols for n in ("in_bytes", "in_pkts", "octet_delta_count", "ipv4_src_addr")):
        return "netflow"
    return "unrecognised"


# --- duration unit --------------------------------------------------------------------------------------

def _snap_scale(ratio: float) -> float | None:
    """Nearest of 1, 1e3, 1e6 to a measured implied/stated duration ratio, if it is close enough."""
    if not np.isfinite(ratio) or ratio <= 0:
        return None
    best = min((1.0, 1e3, 1e6), key=lambda f: abs(np.log10(ratio) - np.log10(f)))
    return best if abs(np.log10(ratio) - np.log10(best)) < 0.35 else None


def _check_duration_unit(dur_us: pd.Series, pkts: pd.Series | None, pps: pd.Series | None, report: dict) -> pd.Series:
    """Compare duration with packets / packet rate and correct a wrong unit."""
    if pkts is None or pps is None:
        return dur_us
    ok = (dur_us > 0) & (pkts > 0) & (pps > 0)
    if ok.sum() < 20:
        return dur_us
    implied_us = (pkts[ok] / pps[ok]) * 1e6             # duration the rate column implies, in microseconds
    ratio = float(np.median(implied_us / dur_us[ok]))   # implied / stated
    scale = _snap_scale(ratio)
    if scale is not None and scale != 1.0:
        report["assumptions"].append(
            f"the stated duration is {scale:g} times smaller than the packet rate columns imply, so it was "
            "converted to microseconds")
        return dur_us * scale
    if scale is None:
        report["assumptions"].append(
            "the duration does not match the packet rate columns; it is used as given (microseconds)")
    return dur_us


def _split_ip_port(ips: pd.Series) -> tuple[pd.Series, pd.Series | None]:
    """'1.2.3.4:80' -> ('1.2.3.4', 80) when every non-empty value has that shape."""
    s = ips.astype("string").str.strip()
    m = s.str.extract(r"^(\d{1,3}(?:\.\d{1,3}){3})[:.](\d{1,5})$")
    valid = m[0].notna()
    if len(s) and valid.any() and valid.sum() >= 0.9 * s.notna().sum():
        return m[0].where(valid, s), pd.to_numeric(m[1], errors="coerce")
    return s, None


def select_label_column(df: pd.DataFrame, cols: dict[str, str]) -> str | None:
    """The label column whose values can be interpreted, preferring the earlier names in LABEL."""
    for name in LABEL:
        col = cols.get(name)
        if col is None:
            continue
        vals = df[col].astype("string").dropna().head(2000)
        if len(vals) == 0:
            continue
        known = np.mean([behaviour_of(v) not in (None, UNKNOWN) for v in vals])
        if known >= 0.5:
            return col
    return None


# --- main entry -----------------------------------------------------------------------------------------

def adapt_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """
    Return (features, meta, report).

    features: one row per input row, columns FLOW_FEATURES, all finite floats.
    meta: src_ip, dst_ip, src_port, dst_port, protocol, timestamp (UTC or NaT), label (original text or None).
    """
    cols: dict[str, str] = {}
    for original in df.columns:
        cols.setdefault(norm(original), original)

    core_names = {g: names for g, names in CORE_GROUPS.items()}
    have_core = [g for g, names in core_names.items() if _first(cols, names) is not None]
    if not have_core:
        raise SchemaError(
            "No flow measurements recognised. Expected columns such as flow_duration, tot_fwd_pkts, "
            "tot_bwd_pkts (or CICFlowMeter names like 'Flow Duration', 'Total Fwd Packets'; Zeek, Suricata, "
            "NetFlow or nfdump names like duration, orig_pkts, resp_pkts, in_bytes, out_bytes). "
            f"Columns found: {list(df.columns)[:15]}"
        )

    report: dict[str, Any] = {"format": detect_format(cols), "read": {}, "derived": {}, "defaulted": [],
                              "assumptions": [], "warnings": []}
    feats: dict[str, pd.Series] = {}
    n = len(df)
    zeros = pd.Series(np.zeros(n), index=df.index)

    def take(feature: str, series: pd.Series | None, how: str, source: str) -> None:
        if series is None:
            return
        feats[feature] = series.astype(float)
        report[how][feature] = source

    for feat, names in DIRECT.items():
        col = _first(cols, names)
        if col is not None:
            take(feat, _num(df, col), "read", str(col))

    # timestamps first: they can supply the duration and the timeline
    time_notes: list[str] = []
    tcol = _first(cols, TIME)
    date_col = _first(cols, DATE_ONLY)
    if tcol is not None:
        clock = _clock_only(df[tcol])
        if clock is not None and date_col is not None:
            meta_ts = _parse_time(df[date_col], time_notes).dt.normalize() + clock
            report["assumptions"].append(f"timestamp = date column '{date_col}' + time column '{tcol}'")
        elif clock is not None:
            base = pd.Timestamp("2000-01-01", tz="UTC")
            rolled = (clock.diff() < pd.Timedelta(0)).cumsum()
            meta_ts = base + clock + rolled * pd.Timedelta(days=1)
            report["assumptions"].append(
                f"column '{tcol}' has times without dates: they are placed on 2000-01-01, advancing one day each "
                "time the clock wraps around")
        else:
            meta_ts = _parse_time(df[tcol], time_notes)
    elif date_col is not None:
        meta_ts = _parse_time(df[date_col], time_notes)
        report["assumptions"].append(f"only the date column '{date_col}' is available: all flows of a day share "
                                     "its midnight, so minute-level timelines are not meaningful")
    else:
        meta_ts = pd.Series(pd.NaT, index=df.index, dtype="datetime64[ns, UTC]")
    meta_ts = meta_ts.where((meta_ts.dt.year >= 1990) & (meta_ts.dt.year <= 2100))
    report["assumptions"].extend(time_notes)
    end_col = _first(cols, END_TIME)
    end_ts = _parse_time(df[end_col], []) if end_col is not None else None

    # duration in microseconds (the CICFlowMeter unit)
    if "flow_duration" in feats:
        report["assumptions"].append(f"column '{report['read']['flow_duration']}' is read as microseconds "
                                     "(CICFlowMeter unit)")
    else:
        for names, factor, unit in ((DUR_US, 1.0, "microseconds"), (DUR_MS, 1e3, "milliseconds"),
                                    (DUR_S, 1e6, "seconds")):
            col = _first(cols, names)
            if col is not None:
                take("flow_duration", _num(df, col) * factor, "derived", f"{col} ({unit}) x {factor:g}")
                report["assumptions"].append(f"column '{col}' is read as {unit}")
                break
        else:
            if end_ts is not None and meta_ts.notna().any():
                take("flow_duration", (end_ts - meta_ts).dt.total_seconds() * 1e6, "derived",
                     f"{end_col} - {tcol} in microseconds")

    fwd_b, bwd_b = _num(df, _first(cols, FWD_BYTES)), _num(df, _first(cols, BWD_BYTES))
    tot_b, tot_p_col = _num(df, _first(cols, TOTAL_BYTES)), _num(df, _first(cols, TOTAL_PKTS))
    if tot_b is None and fwd_b is not None and bwd_b is not None:
        tot_b = fwd_b + bwd_b
    fwd_p, bwd_p = feats.get("tot_fwd_pkts"), feats.get("tot_bwd_pkts")
    if fwd_p is None and bwd_p is None and tot_p_col is not None:
        take("tot_fwd_pkts", tot_p_col, "derived", "total packets (no direction split available)")
        report["assumptions"].append("only total packets are available; they are counted as forward packets")
        fwd_p = feats["tot_fwd_pkts"]
    if fwd_p is not None or bwd_p is not None:
        tot_p = (fwd_p if fwd_p is not None else 0) + (bwd_p if bwd_p is not None else 0)
    else:
        tot_p = tot_p_col

    if "flow_duration" in feats:
        feats["flow_duration"] = _check_duration_unit(feats["flow_duration"], tot_p, feats.get("flow_pkts_s"), report)
    dur_s = feats["flow_duration"] / 1e6 if "flow_duration" in feats else None

    with np.errstate(divide="ignore", invalid="ignore"):
        if "fwd_pkt_len_mean" not in feats and fwd_b is not None and fwd_p is not None:
            take("fwd_pkt_len_mean", fwd_b / fwd_p, "derived", "forward bytes / forward packets")
        if "bwd_pkt_len_mean" not in feats and bwd_b is not None and bwd_p is not None:
            take("bwd_pkt_len_mean", bwd_b / bwd_p, "derived", "backward bytes / backward packets")
        if "flow_bytes_s" not in feats and tot_b is not None and dur_s is not None:
            take("flow_bytes_s", tot_b / dur_s, "derived", "total bytes / duration")
        if "flow_pkts_s" not in feats and tot_p is not None and dur_s is not None:
            take("flow_pkts_s", tot_p / dur_s, "derived", "total packets / duration")
        if "pkt_size_avg" not in feats and tot_b is not None and tot_p is not None:
            take("pkt_size_avg", tot_b / tot_p, "derived", "total bytes / total packets")
        if "flow_iat_mean" not in feats and tot_p is not None and "flow_duration" in feats:
            take("flow_iat_mean", feats["flow_duration"] / (tot_p - 1), "derived", "duration / (total packets - 1)")
        if "down_up_ratio" not in feats and fwd_p is not None and bwd_p is not None:
            take("down_up_ratio", np.floor(bwd_p / fwd_p), "derived",
                 "backward packets // forward packets (as capture/flow_state.py)")

    if "ttl_variance" not in feats:
        fh, bh = _num(df, _first(cols, FWD_HDR)), _num(df, _first(cols, BWD_HDR))
        if fh is not None and bh is not None:
            take("ttl_variance", (fh.fillna(0) - bh.fillna(0)).abs(), "derived",
                 "|fwd header length - bwd header length| (definition used for the training data)")
    if "retransmit_cnt" not in feats:
        sub = _num(df, _first(cols, SUBFLOW_FWD))
        if sub is not None and fwd_p is not None:
            take("retransmit_cnt", (fwd_p.fillna(0) - sub.fillna(0)).clip(lower=0), "derived",
                 "forward packets - subflow forward packets (as in the training data)")

    hist_col = _first(cols, ZEEK_HISTORY)
    if hist_col is not None:
        h = df[hist_col]
        for feat, letters in (("syn_flag_cnt", "SsHh"), ("ack_flag_cnt", "Aa"), ("fin_flag_cnt", "Ff"),
                              ("rst_flag_cnt", "Rr")):
            if feat not in feats:
                take(feat, _history_count(h, letters), "derived", f"count of {letters!r} in Zeek history")
        if "retransmit_cnt" not in feats:
            take("retransmit_cnt", _history_count(h, "Tt"), "derived", "count of 'T' in Zeek history")
    else:
        fl_col = _first(cols, TCP_FLAGS)
        if fl_col is not None:
            raw = df[fl_col].astype("string").fillna("").str.strip()
            code = pd.to_numeric(raw, errors="coerce")
            if code.notna().mean() > 0.9:
                for feat, bit in (("fin_flag_cnt", 1), ("syn_flag_cnt", 2), ("rst_flag_cnt", 4),
                                  ("psh_flag_cnt", 8), ("ack_flag_cnt", 16), ("urg_flag_cnt", 32)):
                    if feat not in feats:
                        take(feat, ((code.fillna(0).astype(int) & bit) > 0).astype(float), "derived",
                             f"bit {bit} of {fl_col} (flag present, not a packet count)")
            else:  # letter flags such as "....S." or "SAF"
                for feat, letter in (("syn_flag_cnt", "S"), ("ack_flag_cnt", "A"), ("fin_flag_cnt", "F"),
                                     ("rst_flag_cnt", "R"), ("psh_flag_cnt", "P"), ("urg_flag_cnt", "U")):
                    if feat not in feats:
                        take(feat, raw.str.upper().str.contains(letter, regex=False).astype(float), "derived",
                             f"flag letter {letter} in {fl_col} (flag present, not a packet count)")

    # assemble in model order; absent features are zero, as in the training pipeline
    cleaned, nonfinite, negative, constant = {}, 0, 0, []
    for feat in FLOW_FEATURES:
        s = feats.get(feat)
        if s is None:
            report["defaulted"].append(feat)
            cleaned[feat] = zeros.to_numpy()
            continue
        arr = s.to_numpy(dtype=float)
        bad = ~np.isfinite(arr)
        nonfinite += int(bad.sum())
        arr = np.where(bad, 0.0, arr)
        negative += int((arr < 0).sum())
        if n > 20 and np.ptp(arr) == 0:
            constant.append(feat)
        cleaned[feat] = arr
    features = pd.DataFrame(cleaned, index=df.index, columns=FLOW_FEATURES)
    report["nonfinite_values_set_to_zero"] = nonfinite
    if negative:
        report["warnings"].append(f"{negative} negative feature values were kept as given")
    if constant:
        report["warnings"].append("constant in this file (they carry no information): " + ", ".join(constant))
    obtained = len(report["read"]) + len(report["derived"])
    if obtained < 8:
        report["warnings"].append(
            f"only {obtained} of 22 features could be obtained; predictions from so little information are unreliable")

    # identity, ports, protocol
    def text(names):
        c = _first(cols, names)
        return df[c].astype("string").str.strip() if c is not None else pd.Series([None] * n, index=df.index)

    def port(names):
        c = _first(cols, names)
        if c is None:
            return pd.Series([pd.NA] * n, index=df.index, dtype="Int64")
        p = _to_num(df[c])
        return p.where((p >= 0) & (p <= 65535)).round().astype("Int64")

    src_ip, dst_ip = text(SRC_IP), text(DST_IP)
    src_port, dst_port = port(SRC_PORT), port(DST_PORT)
    if src_ip.notna().any():
        src_ip, sp = _split_ip_port(src_ip)
        if sp is not None and src_port.isna().all():
            src_port = sp.round().astype("Int64")
            report["assumptions"].append("source ports were split from 'address:port' values")
    if dst_ip.notna().any():
        dst_ip, dp = _split_ip_port(dst_ip)
        if dp is not None and dst_port.isna().all():
            dst_port = dp.round().astype("Int64")
            report["assumptions"].append("destination ports were split from 'address:port' values")
    meta = pd.DataFrame({"src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port},
                        index=df.index)
    pc = _first(cols, PROTO)
    if pc is not None:
        raw = df[pc].astype("string").fillna("").str.strip().str.split(".").str[0]
        meta["protocol"] = raw.map(
            lambda v: PROTO_NAMES.get(v, v.upper() if isinstance(v, str) and v and v.lower() != "nan" else "TCP"))
    else:
        meta["protocol"] = "TCP"
        report["defaulted"].append("protocol (assumed TCP)")

    meta["timestamp"] = meta_ts
    report["timestamps_unparsed"] = int(meta_ts.isna().sum())
    report["timestamp_column"] = str(tcol or date_col) if (tcol or date_col) else None

    lc = select_label_column(df, cols)
    meta["label"] = df[lc].astype("string").str.strip() if lc is not None else None
    report["label_column"] = str(lc) if lc is not None else None
    report["missing_identity"] = [k for k, names in (("src_ip", SRC_IP), ("dst_ip", DST_IP))
                                  if _first(cols, names) is None]
    return features, meta, report
