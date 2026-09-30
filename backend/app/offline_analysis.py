"""
Offline analysis of an uploaded file, isolated from the live system.

Nothing here touches the database, the live tracker or the WebSocket feed. One call does everything:

  1. open the file whatever its container and layout (table_reader), convert the columns to the 22 model
     features (flow_schema) and complete missing structure in a documented way;
  2. label every flow: with the file's own labels when it has them, otherwise with the real-data flow
     classifier (behaviour, attack probability, confidence);
  3. build the network state per minute on the file's own dates, split the timeline at long gaps, and run
     the network-state model on each segment: risk and behaviour for the next 4 minutes, exactly as the
     model produces them (no rules, caps or blending);
  4. when the file has labels, measure the models on it: per-flow detection, and a back-test of every
     forecast the network model would have issued against what happened next.
"""
from __future__ import annotations

import logging
import math
import os
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd
import torch

from .config import FLOW_FEATURES
from .flow_classifier import get_classifier
from .flow_schema import SchemaError, adapt_frame
from .labels import behaviour_of
from .model_loader import artifacts
from .network_state import tracker as live_tracker
from .table_reader import UnreadableFile, open_source, read_chunks

logger = logging.getLogger(__name__)

GAP_MINUTES = 60                 # a longer silence starts a new segment of the timeline
MAX_SEGMENTS = 8                 # most recent segments analysed in detail
MAX_MINUTES_PER_SEGMENT = 2880   # a segment longer than two days is analysed on its last two days
BLOCK_ROWS = 30                  # session size when the file has no addresses (as in preprocessing)
MIN_TIMELINE_MINUTES = 40        # a synthetic timeline spans about this many minutes
MIN_ROWS_PER_MINUTE = 20
DISPLAY_STATE = ["n_flows", "n_uniq_dst_port", "n_conn_rate", "f_total_bytes", "f_syn_ratio"]


class OfflineError(ValueError):
    """The file cannot be analysed; the message is shown to the user."""


# --- small helpers -------------------------------------------------------------------------------------

def _json_safe(obj):
    """Plain Python values only; NaN and infinity become null (they are not valid JSON)."""
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, np.generic):
        obj = obj.item()
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj


def _f(v):
    if v is None:
        return None
    v = float(v)
    return None if math.isnan(v) or math.isinf(v) else v


class Steps:
    """The automation steps, with what each did and how long it took."""

    def __init__(self):
        self.items: list[dict] = []
        self._t = time.perf_counter()

    def done(self, name: str, detail: str) -> None:
        now = time.perf_counter()
        self.items.append(dict(step=name, detail=detail, seconds=round(now - self._t, 2)))
        self._t = now


# --- loading -------------------------------------------------------------------------------------------

def _load_table(src) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    feats, metas, report = [], [], None
    nonfinite = ts_unparsed = 0
    warnings: list[str] = []
    try:
        for chunk in read_chunks(src):
            try:
                f, m, rep = adapt_frame(chunk)
            except SchemaError as exc:
                raise OfflineError(str(exc)) from exc
            report = report or rep
            nonfinite += rep["nonfinite_values_set_to_zero"]
            ts_unparsed += rep.get("timestamps_unparsed", 0)
            warnings.extend(w for w in rep.get("warnings", []) if w not in warnings)
            feats.append(f)
            metas.append(m)
    except UnreadableFile as exc:
        raise OfflineError(str(exc)) from exc
    report["nonfinite_values_set_to_zero"] = nonfinite
    report["timestamps_unparsed"] = ts_unparsed
    report["warnings"] = warnings
    report["assumptions"].extend(n for n in src.notes if n not in report["assumptions"])
    return pd.concat(feats, ignore_index=True), pd.concat(metas, ignore_index=True), report


def _load_pcap(path: str) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    try:
        from capture.flow_table import flows_from_pcap
    except ImportError as exc:
        raise OfflineError("Scapy is not installed on the backend server") from exc
    try:
        flows = flows_from_pcap(path)
    except Exception as exc:
        raise OfflineError(f"Failed to parse the capture: {exc}") from exc
    if not flows:
        raise OfflineError("No IP flows were found in the capture.")
    flows.sort(key=lambda f: f.start_time)
    proto = {6: "TCP", 17: "UDP", 1: "ICMP"}
    feats = pd.DataFrame([f.to_features() for f in flows], columns=FLOW_FEATURES)
    meta = pd.DataFrame({
        "src_ip": [f.src_ip for f in flows], "dst_ip": [f.dst_ip for f in flows],
        "src_port": pd.array([f.src_port for f in flows], dtype="Int64"),
        "dst_port": pd.array([f.dst_port for f in flows], dtype="Int64"),
        "protocol": [proto.get(f.protocol, str(f.protocol)) for f in flows],
        "timestamp": pd.to_datetime([f.start_time for f in flows], unit="s", utc=True),
        "label": None,
    })
    report = {"format": "packet_capture", "read": {k: "reconstructed from packets" for k in FLOW_FEATURES},
              "derived": {}, "defaulted": ["urg_flag_cnt", "retransmit_cnt"], "assumptions": [], "warnings": [],
              "nonfinite_values_set_to_zero": 0, "timestamps_unparsed": 0, "label_column": None,
              "timestamp_column": "packet timestamps", "missing_identity": []}
    return feats, meta, report


# --- completing the structure ---------------------------------------------------------------------------

def _complete_structure(feats: pd.DataFrame, meta: pd.DataFrame, report: dict):
    """Fill timeline and session structure. Returns (feats, meta, notes); notes say what was synthesised."""
    n = len(feats)
    notes: dict[str, Any] = {"timeline_synthesized": False, "sessions": "address pairs"}
    ts = meta["timestamp"]
    valid = int(ts.notna().sum())
    single_instant = valid > 0 and ts.dropna().nunique() == 1 and n > 1
    if valid == 0 or single_instant:
        per_min = max(MIN_ROWS_PER_MINUTE, math.ceil(n / MIN_TIMELINE_MINUTES))
        start = ts.dropna().iloc[0].floor("min") if single_instant \
            else pd.Timestamp(datetime.now(timezone.utc)).floor("min")
        meta["timestamp"] = start + pd.to_timedelta(np.arange(n) // per_min, unit="min") \
            + pd.to_timedelta((np.arange(n) % per_min) * (60.0 / per_min), unit="s")
        notes["timeline_synthesized"] = True
        notes["rows_per_minute"] = per_min
        why = "every flow has the same timestamp" if single_instant else "no usable timestamps"
        report["assumptions"].append(
            f"{why}: rows are placed in file order, {per_min} rows per minute; the time axis is synthetic")
    elif valid < n:
        meta["timestamp"] = ts.ffill().bfill()
        report["assumptions"].append(f"{n - valid} rows without a timestamp take the time of the previous row")
    order = np.argsort(meta["timestamp"].to_numpy(), kind="stable")
    if not np.array_equal(order, np.arange(n)):
        feats = feats.iloc[order].reset_index(drop=True)
        meta = meta.iloc[order].reset_index(drop=True)
        report["assumptions"].append("rows were not in time order and were sorted by timestamp")

    for col in ("src_ip", "dst_ip"):
        meta[col] = meta[col].astype("string")
        meta[col] = meta[col].where(meta[col].notna() & (meta[col].str.strip() != ""), None)
    has_ips = meta["src_ip"].notna().any() and meta["dst_ip"].notna().any()
    if has_ips:
        meta["src_ip"] = meta["src_ip"].fillna("0.0.0.0")
        meta["dst_ip"] = meta["dst_ip"].fillna("0.0.0.0")
        meta["session"] = meta["src_ip"] + " -> " + meta["dst_ip"]
    else:
        meta["src_ip"] = "0.0.0.0"
        meta["dst_ip"] = "0.0.0.0"
        block = np.arange(n) // BLOCK_ROWS * BLOCK_ROWS
        meta["session"] = "rows " + (block + 1).astype(str) + "-" + (block + BLOCK_ROWS).astype(str)
        notes["sessions"] = f"blocks of {BLOCK_ROWS} consecutive rows"
        report["assumptions"].append(
            f"no source/destination addresses: flows are grouped in blocks of {BLOCK_ROWS} consecutive rows, and the "
            "address-based network features (unique hosts, host shares) are constant")
    return feats, meta, notes


def prepare(path: str, steps: Steps):
    """Open, convert and complete. Returns feats, meta, report, notes, input_kind, container."""
    try:
        src = open_source(path)
    except UnreadableFile as exc:
        raise OfflineError(str(exc)) from exc
    try:
        if src.kind == "pcap":
            feats, meta, report = _load_pcap(src.path)
            steps.done("read", f"packet capture: {len(feats):,} flows reconstructed from packets")
        else:
            feats, meta, report = _load_table(src)
            box = f", inside a {src.container} container" if src.container else ""
            steps.done("read", f"{src.kind} table{box}: {len(feats):,} rows, format {report['format']}")
        feats, meta, notes = _complete_structure(feats, meta, report)
        got = len(report["read"]) + len(report["derived"])
        steps.done("convert", f"{got} of 22 model features obtained ({len(report['read'])} read, "
                              f"{len(report['derived'])} derived), {len(report['defaulted'])} absent")
        return feats, meta, report, notes, ("pcap" if src.kind == "pcap" else "table"), src.container
    finally:
        src.cleanup()


# --- labels and per-flow predictions --------------------------------------------------------------------

def label_and_score(feats: pd.DataFrame, meta: pd.DataFrame, steps: Steps):
    """Per-flow predictions, and the truth taken from the file's labels when it has any."""
    clf = get_classifier()
    pred = clf.predict(feats)
    flagged = pred["attack_prob"] >= clf.threshold
    truth_beh = None
    if meta["label"].notna().any():
        truth_beh = meta["label"].map(lambda v: behaviour_of(v) if isinstance(v, str) else None)
    detail = f"{int(flagged.sum()):,} of {len(feats):,} flows flagged as attacks by the flow classifier"
    detail += ("; the file's own labels are kept as ground truth" if truth_beh is not None
               else "; the file has no labels, so predicted labels are provided")
    steps.done("label", detail)
    return clf, pred, flagged, truth_beh


def _flow_evaluation(truth_beh: pd.Series, pred: dict, flagged: np.ndarray) -> dict | None:
    known = truth_beh.notna() & (truth_beh != "Unknown")
    if not known.any():
        return None
    k = known.to_numpy()
    t = (truth_beh[known] != "Benign").to_numpy()
    p, fl = pred["attack_prob"][k], flagged[k]
    tp, fp = int((fl & t).sum()), int((fl & ~t).sum())
    fn, tn = int((~fl & t).sum()), int((~fl & ~t).sum())
    out = dict(
        labelled_rows=int(known.sum()), malicious=int(t.sum()), benign=int((~t).sum()),
        true_positive=tp, false_positive=fp, false_negative=fn, true_negative=tn,
        precision=_f(tp / (tp + fp)) if tp + fp else None, recall=_f(tp / (tp + fn)) if tp + fn else None,
        false_positive_rate=_f(fp / (fp + tn)) if fp + tn else None, roc_auc=None, pr_auc=None,
        label_counts={str(k_): int(v) for k_, v in truth_beh[known].value_counts().head(12).items()},
    )
    if t.any() and (~t).any():
        from sklearn.metrics import average_precision_score, roc_auc_score
        out["roc_auc"] = _f(roc_auc_score(t, p))
        out["pr_auc"] = _f(average_precision_score(t, p))
    fam = {}
    pb = pred["behaviour"][k]
    tb = truth_beh[known].to_numpy()
    for b in sorted(set(tb) - {"Benign"}):
        m = tb == b
        fam[b] = dict(rows=int(m.sum()), detected=_f(float(fl[m].mean())), family_correct=_f(float((pb[m] == b).mean())))
    out["families"] = fam
    return out


# --- network-state model, pure ---------------------------------------------------------------------------

def _run_network_model(m, states: pd.DataFrame):
    """Rollouts from every window of the segment, indexed by the minute the window ends on."""
    Z = m.encode(states)
    T = len(Z)
    idx = np.arange(m.W - 1, T)
    wins = np.stack([Z[i - m.W + 1:i + 1] for i in idx]).astype(np.float32)
    S, R, C = [], [], []
    with torch.no_grad():
        for i in range(0, len(wins), 1024):
            s, r, c = m.model.rollout(torch.from_numpy(wins[i:i + 1024]), m.H)
            S.append(s.numpy())
            R.append(r.numpy())
            C.append(c.numpy())
    S, R, C = np.concatenate(S), np.concatenate(R), np.concatenate(C)
    risk = 1.0 / (1.0 + np.exp(-R))
    e = np.exp(C - C.max(-1, keepdims=True))
    return dict(Z=Z, idx=idx, S=S, risk=risk, beh=e / e.sum(-1, keepdims=True))


def _segment_report(m, states: pd.DataFrame, frame: pd.DataFrame, has_truth: bool, seg_id: int) -> dict:
    """Forecast, alerts and (with truth) back-test for one continuous segment."""
    from worldmodel_v3.lib import evaluate_alerts, sustained

    T = len(states)
    seg = dict(id=seg_id, start=states.index[0].isoformat(), end=states.index[-1].isoformat(), minutes=T)
    if T < m.W:
        seg["status"] = "too_short"
        seg["detail"] = f"{T} minutes of traffic; the network model needs at least {m.W}"
        return seg
    run = _run_network_model(m, states)
    idx, risk, beh, S, Z = run["idx"], run["risk"], run["beh"], run["S"], run["Z"]
    score = np.full(T, np.nan)
    score[idx] = risk.max(axis=1)                       # the model's own rule: max risk over the next H minutes
    thr, N = m.thr, m.N
    alert = sustained(np.nan_to_num(score) >= thr, N)

    last = len(idx) - 1
    decoded = m.decode(S[last])
    feats_idx = [m.features.index(f) for f in DISPLAY_STATE if f in m.features]
    steps = []
    for k in range(m.H):
        order = np.argsort(-beh[last, k])[:3]
        steps.append(dict(
            step=k + 1, minute=(states.index[-1] + pd.Timedelta(minutes=k + 1)).isoformat(), risk=float(risk[last, k]),
            behaviours=[dict(behaviour=m.behaviours[j], probability=float(beh[last, k, j])) for j in order],
            state={m.features[j]: float(decoded[k, j]) for j in feats_idx}))
    seg["forecast"] = dict(steps=steps, threshold=thr, sustained_minutes_needed=N, alert=bool(alert[-1]),
                           peak_risk=float(risk[last].max()))

    per_min = []
    for i, t in enumerate(states.index):
        row = frame.iloc[i]
        per_min.append(dict(
            minute=t.isoformat(), flows=int(row["flows"]) if pd.notna(row["flows"]) else 0,
            flagged=int(row["flagged"]) if pd.notna(row["flagged"]) else 0,
            mean_attack_prob=_f(row["mean_prob"]) if pd.notna(row["mean_prob"]) else None,
            behaviour=row["behaviour"] if pd.notna(row["behaviour"]) else "Benign",
            labelled_attacks=int(row["labelled_attacks"]) if has_truth and pd.notna(row["labelled_attacks"]) else None,
            model_risk=_f(score[i]), alert=bool(alert[i])))
    seg["per_minute"] = per_min

    # how well the network model predicted this file's own next states
    valid = idx[idx + m.H < T]
    if len(valid):
        n_v = len(valid)
        mse, persist = [], []
        for k in range(m.H):
            tgt = Z[valid + 1 + k]
            mse.append(float(np.mean((S[:n_v, k] - tgt) ** 2)))
            persist.append(float(np.mean((Z[valid] - tgt) ** 2)))
        track = None
        if "n_flows" in m.features:
            j = m.features.index("n_flows")
            pred1 = m.decode(S[:n_v, 0])[:, j]
            actual1 = np.expm1(Z[valid + 1, j] * m.std[j] + m.mean[j])
            track = [dict(minute=states.index[v + 1].isoformat(), predicted=float(p), actual=float(a))
                     for v, p, a in zip(valid, pred1, actual1)]
        seg["state_evaluation"] = dict(horizons=list(range(1, m.H + 1)), model_mse=mse, persistence_mse=persist,
                                       windows=int(n_v), n_flows_tracking=track)

    if has_truth:
        y = (frame["labelled_attacks"].fillna(0).to_numpy() > 0).astype(int)
        bt: dict[str, Any] = dict(attack_minutes=int(y.sum()), quiet_minutes=int((y == 0).sum()))
        from sklearn.metrics import average_precision_score, roc_auc_score
        per_h = []
        for k in range(m.H):
            ok = idx + 1 + k < T
            yy, rr = y[idx[ok] + 1 + k], risk[ok, k]
            entry = dict(horizon=k + 1, windows=int(ok.sum()))
            if 0 < yy.sum() < len(yy):
                entry.update(roc_auc=_f(roc_auc_score(yy, rr)), pr_auc=_f(average_precision_score(yy, rr)))
            per_h.append(entry)
        bt["per_horizon"] = per_h
        if y.sum() and (y == 0).any():
            res = evaluate_alerts({"seg": score}, {"seg": y}, thr, N)
            leads = res["leads"]
            bt["early_warning"] = dict(
                episodes=res["eligible"], warned_within_20_min=len(leads),
                median_lead_minutes=_f(float(np.median(leads))) if leads else None,
                false_alarm_events=res["fa_events"], quiet_hours=res["quiet_windows"] / 60.0)
        if "behaviour_true" in frame:
            bt_true = frame["behaviour_true"].to_numpy()
            hits = tot = 0
            for w, i in enumerate(idx):
                if i + 1 < T and y[i + 1] == 1 and bt_true[i + 1] in m.behaviours:
                    tot += 1
                    hits += int(np.argmax(beh[w, 0]) == m.behaviours.index(bt_true[i + 1]))
            if tot:
                bt["next_minute_behaviour_accuracy_on_attack_minutes"] = dict(minutes=tot, correct=hits)
        seg["backtest"] = bt
    seg["status"] = "ok"
    return seg


# --- assembling the report ---------------------------------------------------------------------------------

def _minute_frame(meta: pd.DataFrame, pred: dict, flagged: np.ndarray, truth_beh: pd.Series | None) -> pd.DataFrame:
    ts = meta["timestamp"]
    minute = (ts.dt.tz_convert("UTC").dt.tz_localize(None) if ts.dt.tz is not None else ts).dt.floor("min")
    df = pd.DataFrame({"minute": minute, "p": pred["attack_prob"], "flag": flagged, "beh": pred["behaviour"]})
    if truth_beh is not None:
        df["atk"] = truth_beh.notna() & ~truth_beh.isin(["Benign", "Unknown"])
        df["tb"] = truth_beh.where(df["atk"])
    g = df.groupby("minute")
    out = pd.DataFrame({"flows": g.size(), "flagged": g["flag"].sum(), "mean_prob": g["p"].mean()})
    top = df[df["flag"]].groupby("minute")["beh"].agg(lambda s: s.value_counts().idxmax())
    out["behaviour"] = top.reindex(out.index).fillna("Benign")
    if truth_beh is not None:
        out["labelled_attacks"] = g["atk"].sum()
        tb = df[df["atk"]].groupby("minute")["tb"].agg(lambda s: s.value_counts().idxmax())
        out["behaviour_true"] = tb.reindex(out.index).fillna("Benign")
    return out


def _segments(minutes: pd.DatetimeIndex) -> list[tuple[pd.Timestamp, pd.Timestamp]]:
    """Continuous stretches of activity: a silence longer than GAP_MINUTES splits the timeline."""
    if len(minutes) == 0:
        return []
    gaps = np.where(np.diff(minutes.values).astype("timedelta64[m]").astype(int) > GAP_MINUTES)[0]
    starts = np.concatenate([[0], gaps + 1])
    ends = np.concatenate([gaps, [len(minutes) - 1]])
    return [(minutes[s], minutes[e]) for s, e in zip(starts, ends)]


def analyze_offline(path: str, filename: str = "") -> dict:
    steps = Steps()
    if not artifacts.is_loaded:
        raise OfflineError("The models are not loaded.")
    m = live_tracker.model
    if m is None:
        raise OfflineError("The network-state model is not available.")
    feats, meta, report, notes, input_kind, container = prepare(path, steps)
    n = len(feats)
    clf, pred, flagged, truth_beh = label_and_score(feats, meta, steps)
    has_truth = truth_beh is not None

    from worldmodel_v3.state import flows_from_features, full_grid, minute_states
    ts = meta["timestamp"]
    state_meta = meta[["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]].assign(timestamp=ts)
    all_states = minute_states(flows_from_features(pd.concat([feats, state_meta], axis=1)))
    frame = _minute_frame(meta, pred, flagged, truth_beh)
    steps.done("timeline", f"{len(all_states):,} active minutes from {all_states.index.min()} "
                           f"to {all_states.index.max()}")

    segs = _segments(all_states.index)
    chosen = sorted(segs, key=lambda se: se[1])[-MAX_SEGMENTS:]
    details = []
    for i, (a, b) in enumerate(chosen):
        st = full_grid(all_states.loc[a:b])
        if len(st) > MAX_MINUTES_PER_SEGMENT:
            st = st.iloc[-MAX_MINUTES_PER_SEGMENT:]
        det = _segment_report(m, st, frame.reindex(st.index), has_truth, i)
        det["flows"] = int(frame.reindex(st.index)["flows"].fillna(0).sum())
        details.append(det)
    ok = [d for d in details if d["status"] == "ok"]
    steps.done("forecast", f"{len(ok)} of {len(segs)} activity periods are long enough for the network model "
                           f"(it needs {m.W} minutes)")

    sess = pd.DataFrame({"session": meta["session"].astype(str), "p": pred["attack_prob"], "flag": flagged,
                         "beh": pred["behaviour"]})
    top = []
    for name, g in sess.groupby("session", sort=False):
        fl = g[g["flag"]]
        top.append(dict(session=str(name), flows=int(len(g)), flagged=int(len(fl)), max_prob=_f(g["p"].max()),
                        behaviour=(fl["beh"].value_counts().idxmax() if len(fl) else "Benign")))
    top.sort(key=lambda r: (r["flagged"], r["max_prob"] or 0), reverse=True)

    counts = pd.Series(pred["behaviour"]).value_counts()
    cfg = clf.config
    held = cfg.get("held_out_test", {})
    notes_out = [
        "Nothing from this file was added to live sessions, alerts, logs, the map or the live forecast.",
        (f"Flow labels come from a classifier trained on real CIC-IDS2017 flows; on its held-out test segments it "
         f"reached precision {held.get('precision', 0):.2f} and recall {held.get('recall', 0):.2f} at a false-positive "
         f"rate of {held.get('fpr', 0):.3f}. Attack families absent from its training data are largely missed."),
        ("The forecast is the network-state model's own output for the last minutes of each activity period, without "
         "rules or adjustments; see docs/model_card.md for its measured accuracy."),
    ]
    if not has_truth:
        notes_out.append("The file has no labels, so there is no ground truth: predicted labels are provided and "
                         "no accuracy is claimed for this file.")
    return _json_safe(dict(
        filename=filename, input_kind=input_kind, container=container, rows=n, pipeline=steps.items,
        schema=report, sessions_grouping=notes["sessions"],
        timeline=dict(start=meta["timestamp"].min().isoformat(), end=meta["timestamp"].max().isoformat(),
                      synthesized=notes["timeline_synthesized"], rows_per_minute=notes.get("rows_per_minute"),
                      segments=[dict(id=d["id"], start=d["start"], end=d["end"], minutes=d["minutes"],
                                     flows=d.get("flows"), status=d["status"],
                                     peak_risk=(d.get("forecast") or {}).get("peak_risk")) for d in details],
                      segments_total=len(segs)),
        labels=dict(source="file" if has_truth else "predicted", column=report.get("label_column"),
                    predicted_counts={str(k): int(v) for k, v in counts.items()}),
        summary=dict(flagged_flows=int(flagged.sum()), attack_share=_f(flagged.mean()),
                     sessions=int(sess["session"].nunique()), max_prob=_f(pred["attack_prob"].max()),
                     first_flagged=(ts[flagged].min().isoformat() if flagged.any() else None)),
        evaluation=_flow_evaluation(truth_beh, pred, flagged) if has_truth else None,
        segments=details, top_sessions=top[:20], notes=notes_out,
        model=dict(flow_classifier=dict(version=cfg["version"], threshold=clf.threshold,
                                        trained_on=cfg["trained_on"], held_out_test=held),
                   network_model=live_tracker.model_info()),
    ))


def convert_to_garud_csv(path: str) -> pd.DataFrame:
    """The uploaded file in this project's own layout: 22 features, identity, time, and labels."""
    steps = Steps()
    feats, meta, report, notes, _, _ = prepare(path, steps)
    pred = get_classifier().predict(feats)
    out = pd.concat([meta[["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]], feats], axis=1)
    out["timestamp"] = out["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if meta["label"].notna().any():
        out["label"] = meta["label"].fillna("")
        out["label_behaviour"] = meta["label"].map(lambda v: behaviour_of(v) if isinstance(v, str) else "")
    out["predicted_behaviour"] = pred["behaviour"]
    out["attack_probability"] = pred["attack_prob"].round(5)
    out["confidence"] = pred["confidence"].round(5)
    return out


def remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
