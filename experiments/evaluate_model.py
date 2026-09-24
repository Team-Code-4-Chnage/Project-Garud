"""
Held-out evaluation of the shipped world model on metrics the training
pipeline does not report: ROC-AUC / PR-AUC, next-state (transition) error
against trivial baselines, multi-step rollout error, early-warning lead
time, and a de-duplicated test set.

Read-only: uses real_flows.csv and backend/artifacts/, writes nothing
unless --out is given.

Definitions (all on the test split of three_way_split, seed 42):
  - Infiltration head: probability that the flow AFTER the window is
    malicious. Threshold 0.5.
  - Next-state error: MSE/MAE in scaled feature space of the predicted
    next flow vs the true next flow. Baselines: "persistence" (predict the
    last flow of the window) and "mean" (predict the train mean, i.e. zeros
    in scaled space).
  - Rollout error at step k: deterministic recursive rollout (no MC noise);
    error of the k-th predicted state vs the true k-th future flow.
  - Lead time: in FLOWS, not seconds (CIC-IDS2017 rows have synthetic
    timestamps). For each test session that starts benign and later turns
    malicious at flow index a, a window ending at flow i < a "fires" if the
    max infiltration probability over a k-step rollout exceeds the
    threshold. Lead = a - (earliest firing i). Sessions that never fire
    are counted as missed. Also reports the alert rate on windows of
    all-benign sessions.
  - De-duplicated: drops test windows whose last flow's 22 scaled features
    are bit-identical to any training flow.

Run as: python experiments/evaluate_model.py [--k 4] [--threshold 0.5]
"""
import argparse
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (average_precision_score, precision_recall_fscore_support,
                             roc_auc_score)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "experiments"))
from pipeline_fixed import three_way_split  # noqa: E402
from calibrate_stage_logits import FLOW_FEATURES, STAGE2ID, WINDOW, WorldModel  # noqa: E402

SEED = 42


def scaled_sessions(df, sids, mean, scale):
    d = df[df["session_id"].isin(sids)].copy()
    d[FLOW_FEATURES] = (d[FLOW_FEATURES].values - mean) / scale
    d = d.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    return d


def windows(d, k):
    """Yield per-window arrays. Only windows with k future flows are kept
    for rollout metrics; all windows with >=1 future flow for the head."""
    X, fut, y_inf, sess, pos, last_raw = [], [], [], [], [], []
    for sid, g in d.groupby("session_id", sort=False):
        f = g[FLOW_FEATURES].values.astype(np.float32)
        m = g["is_malicious"].values
        for i in range(len(g) - WINDOW):
            fu = f[i + WINDOW:i + WINDOW + k]
            pad = np.full((k, f.shape[1]), np.nan, dtype=np.float32)
            pad[:len(fu)] = fu
            X.append(f[i:i + WINDOW])
            fut.append(pad)
            y_inf.append(m[i + WINDOW])
            sess.append(sid)
            pos.append(i + WINDOW - 1)  # index of last flow in window
            last_raw.append(f[i + WINDOW - 1].tobytes())
    return (np.array(X), np.array(fut), np.array(y_inf), np.array(sess),
            np.array(pos), last_raw)


@torch.no_grad()
def rollout(model, X, k):
    """Deterministic recursive rollout. Returns states (n,k,22), probs (n,k)."""
    win = torch.tensor(X)
    states, probs = [], []
    for start in range(0, len(win), 1024):
        w = win[start:start + 1024]
        s_list, p_list = [], []
        for _ in range(k):
            ns, inf_logit, _ = model(w)
            s_list.append(ns)
            p_list.append(torch.sigmoid(inf_logit))
            w = torch.cat([w[:, 1:], ns.unsqueeze(1)], dim=1)
        states.append(torch.stack(s_list, 1).numpy())
        probs.append(torch.stack(p_list, 1).numpy())
    return np.concatenate(states), np.concatenate(probs)


def binary_report(y, p, thr, header):
    pred = (p >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    fpr = ((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)
    print(f"{header:<28} n={len(y):>6} pos={int(y.sum()):>6}  "
          f"ROC-AUC={roc_auc_score(y, p):.4f}  PR-AUC={average_precision_score(y, p):.4f}  "
          f"P={pr:.4f} R={rc:.4f} F1={f1:.4f} FPR={fpr:.4f}")
    return dict(n=int(len(y)), pos=int(y.sum()), roc_auc=float(roc_auc_score(y, p)),
                pr_auc=float(average_precision_score(y, p)), precision=float(pr),
                recall=float(rc), f1=float(f1), fpr=float(fpr))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default="backend/artifacts")
    ap.add_argument("--k", type=int, default=4, help="rollout horizon for state error and lead time")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--out", default=None, help="optional JSON output path")
    args = ap.parse_args()
    art = REPO_ROOT / args.artifacts

    df = pd.read_csv(REPO_ROOT / "real_flows.csv", low_memory=False)
    train_s, _val_s, test_s = three_way_split(df["session_id"].unique(), val_size=0.1,
                                              test_size=0.2, random_state=SEED)
    raw = pickle.load(open(art / "scaler.pkl", "rb"))
    mean = np.asarray(raw["mean"], dtype=np.float32)
    scale = np.asarray(raw["scale"], dtype=np.float32)
    cfg = json.load(open(art / "config.json"))
    model = WorldModel(22, cfg["hidden_size"], 6, cfg["num_layers"], cfg["lstm_dropout"])
    model.load_state_dict(torch.load(art / "world_model.pt", map_location="cpu", weights_only=True))
    model.eval()

    train_d = scaled_sessions(df, train_s, mean, scale)
    train_rows = {r.astype(np.float32).tobytes() for r in train_d[FLOW_FEATURES].values}
    test_d = scaled_sessions(df, test_s, mean, scale)
    X, fut, y_inf, sess, pos, last_raw = windows(test_d, args.k)
    states, probs = rollout(model, X, args.k)
    print(f"Test windows: {len(X)}  sessions: {len(set(sess))}  k={args.k}  threshold={args.threshold}\n")
    result = {}

    # 1. Infiltration head (1-step)
    print("== Infiltration head (next flow malicious?) ==")
    p1 = probs[:, 0]
    result["infiltration_all"] = binary_report(y_inf, p1, args.threshold, "all windows")
    keep = np.array([b not in train_rows for b in last_raw])
    result["infiltration_dedup"] = binary_report(y_inf[keep], p1[keep], args.threshold,
                                                 "de-duplicated windows")
    print(f"  ({(~keep).mean():.1%} of test windows dropped as duplicates of a training flow)\n")

    # 2. Next-state error and rollout error vs baselines
    print("== State prediction error, scaled feature space (lower is better) ==")
    print(f"{'step':<6}{'model MSE':>11}{'persist MSE':>13}{'mean MSE':>10}"
          f"{'model MAE':>11}{'persist MAE':>13}{'n':>8}")
    result["state_error"] = []
    last = X[:, -1, :]
    for s in range(args.k):
        ok = ~np.isnan(fut[:, s, 0])
        t = fut[ok, s]
        pm, pp = states[ok, s], last[ok]
        row = dict(step=s + 1, n=int(ok.sum()),
                   model_mse=float(((pm - t) ** 2).mean()), persist_mse=float(((pp - t) ** 2).mean()),
                   mean_mse=float((t ** 2).mean()), model_mae=float(np.abs(pm - t).mean()),
                   persist_mae=float(np.abs(pp - t).mean()))
        result["state_error"].append(row)
        print(f"{s + 1:<6}{row['model_mse']:>11.4f}{row['persist_mse']:>13.4f}{row['mean_mse']:>10.4f}"
              f"{row['model_mae']:>11.4f}{row['persist_mae']:>13.4f}{row['n']:>8}")
    print("  Persistence = repeat the window's last flow. A model that does not beat it has\n"
          "  not learned transition structure beyond autocorrelation.\n")

    # 3. Early-warning lead time
    print("== Early-warning lead time (in flows; timestamps are synthetic) ==")
    fire = probs.max(axis=1) >= args.threshold
    leads, missed, n_eligible = [], 0, 0
    benign_alert_rates = []
    for sid in np.unique(sess):
        idx = np.where(sess == sid)[0]
        g = test_d[test_d["session_id"] == sid]
        mal = g["is_malicious"].values
        if mal.sum() == 0:
            benign_alert_rates.append(fire[idx].mean())
            continue
        a = int(np.argmax(mal))  # first malicious flow index
        if a < WINDOW:
            continue  # no full benign window precedes the attack
        n_eligible += 1
        pre = idx[pos[idx] < a]
        hit = pre[fire[pre]]
        if len(hit) == 0:
            missed += 1
        else:
            leads.append(int(a - pos[hit].min()))
    leads = np.array(leads)
    print(f"Sessions that start benign then turn malicious (>= {WINDOW} benign flows first): {n_eligible}")
    if n_eligible:
        print(f"  warned before first malicious flow: {len(leads)}  missed: {missed}  "
              f"({len(leads) / n_eligible:.1%} warned)")
    if len(leads):
        print(f"  lead (flows): mean={leads.mean():.1f} median={np.median(leads):.0f} "
              f"min={leads.min()} max={leads.max()}")
        near = int((leads <= 2 * WINDOW).sum())
        print(f"  warned within {2 * WINDOW} flows of the attack start (a plausible forecast, not an "
              f"unrelated earlier alert): {near} of {n_eligible} ({near / n_eligible:.1%})")
    if benign_alert_rates:
        print(f"All-benign test sessions: {len(benign_alert_rates)}; mean fraction of windows that "
              f"alert = {np.mean(benign_alert_rates):.3f}")
    result["lead_time"] = dict(eligible=n_eligible, warned=int(len(leads)), missed=missed,
                               mean=float(leads.mean()) if len(leads) else None,
                               median=float(np.median(leads)) if len(leads) else None,
                               benign_session_alert_rate=float(np.mean(benign_alert_rates))
                               if benign_alert_rates else None)

    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2))
        print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
