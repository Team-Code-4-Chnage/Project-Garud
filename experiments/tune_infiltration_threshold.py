"""
The shipped infiltration head is scored at a fixed 0.5 cutoff (experiments/evaluate_model.py).
ROC-AUC there is 0.955/0.948 (all/de-duplicated), well above what F1@0.5 (0.862/0.838) suggests --
meaning 0.5 is very unlikely to be the F1-optimal cutoff. This script finds the threshold that
maximises F1 on VALIDATION sessions only, then reports it once, honestly, on the untouched held-out
test split (all windows and de-duplicated). No retraining, no test-set tuning.

Result (measured): the validation-optimal threshold is 0.6973. It raises de-duplicated F1 from
0.838 to 0.847 (still short of 0.85) and all-windows F1 from 0.862 to 0.868, but recall drops from
0.830 to 0.796 (de-duplicated) -- moving the operating point along the same ROC curve, not improving
it. This traded away real detections for a marginally better summary number: at this threshold,
backend/tests/test_model_quality.py's TestForecastEscalation::test_rollout_from_attack_window_
triggers_alert[90002-Reconnaissance] fails, meaning a genuine held-out Reconnaissance session that
the current 0.5 threshold correctly alerts on is missed. NOT deployed for that reason -- see
docs/model_card.md for the disclosure. Kept here as a reusable, honest measurement of what threshold
tuning alone can and cannot buy.

Run: python experiments/tune_infiltration_threshold.py
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import f1_score, precision_recall_fscore_support, roc_auc_score, average_precision_score

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "experiments"))
from pipeline_fixed import three_way_split  # noqa: E402
from calibrate_stage_logits import FLOW_FEATURES, WINDOW, WorldModel  # noqa: E402

SEED = 42


def scaled_sessions(df, sids, mean, scale):
    d = df[df["session_id"].isin(sids)].copy()
    d[FLOW_FEATURES] = (d[FLOW_FEATURES].values - mean) / scale
    return d.sort_values(["session_id", "timestamp"]).reset_index(drop=True)


def windows(d):
    X, y, last_raw = [], [], []
    for _sid, g in d.groupby("session_id"):
        f = g[FLOW_FEATURES].values.astype(np.float32)
        m = g["is_malicious"].values
        for i in range(len(g) - WINDOW):
            X.append(f[i:i + WINDOW])
            y.append(m[i + WINDOW])
            last_raw.append(f[i + WINDOW - 1].tobytes())
    return np.array(X), np.array(y), last_raw


def probs(model, X):
    out = []
    with torch.no_grad():
        for i in range(0, len(X), 1024):
            _, logit, _ = model(torch.tensor(X[i:i + 1024]))
            out.append(torch.sigmoid(logit).numpy())
    return np.concatenate(out)


def report(y, p, thr, label):
    pred = (p >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    fpr = float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1))
    print(f"{label:<24} thr={thr:.4f}  P={pr:.4f} R={rc:.4f} F1={f1:.4f} FPR={fpr:.4f}  "
          f"ROC-AUC={roc_auc_score(y, p):.4f} PR-AUC={average_precision_score(y, p):.4f}  n={len(y)}")
    return f1


def main():
    art = REPO_ROOT / "backend" / "artifacts"
    df = pd.read_csv(REPO_ROOT / "real_flows.csv", low_memory=False)
    train_s, val_s, test_s = three_way_split(df["session_id"].unique(), val_size=0.1, test_size=0.2,
                                             random_state=SEED)
    raw = pickle.load(open(art / "scaler.pkl", "rb"))
    mean, scale = np.asarray(raw["mean"], np.float32), np.asarray(raw["scale"], np.float32)
    cfg = json.load(open(art / "config.json"))
    model = WorldModel(22, cfg["hidden_size"], 6, cfg["num_layers"], cfg["lstm_dropout"])
    model.load_state_dict(torch.load(art / "world_model.pt", map_location="cpu", weights_only=True))
    model.eval()

    train_rows = {r.astype(np.float32).tobytes() for r in scaled_sessions(df, train_s, mean, scale)[FLOW_FEATURES].values}

    Xv, yv, _ = windows(scaled_sessions(df, val_s, mean, scale))
    pv = probs(model, Xv)
    candidates = np.unique(np.quantile(pv, np.linspace(0.01, 0.99, 400)))
    best_thr, best_f1 = 0.5, f1_score(yv, (pv >= 0.5).astype(int))
    for t in candidates:
        f1 = f1_score(yv, (pv >= t).astype(int))
        if f1 > best_f1:
            best_f1, best_thr = f1, t
    print(f"Validation: best threshold {best_thr:.4f} gives F1 {best_f1:.4f} "
          f"(0.5 gives {f1_score(yv, (pv >= 0.5).astype(int)):.4f}) on {len(yv)} windows")

    Xt, yt, last_raw = windows(scaled_sessions(df, test_s, mean, scale))
    pt = probs(model, Xt)
    keep = np.array([b not in train_rows for b in last_raw])

    print("\n== Held-out test, reported once, chosen threshold applied ==")
    report(yt, pt, 0.5, "all windows @0.5 (current)")
    report(yt, pt, best_thr, f"all windows @{best_thr:.3f} (tuned)")
    report(yt[keep], pt[keep], 0.5, "de-dup @0.5 (current)")
    f1_dedup_tuned = report(yt[keep], pt[keep], best_thr, f"de-dup @{best_thr:.3f} (tuned)")

    print(f"\nde-duplicated F1 at the tuned threshold: {f1_dedup_tuned:.4f} "
          f"({'>' if f1_dedup_tuned > 0.85 else '<='} 0.85)")


if __name__ == "__main__":
    main()
