"""
Train the network-state world model that the backend serves (backend/artifacts_v3/).

Feature set: "net_nodir" (45 features: per-minute flow statistics plus network context, without the
direction and single-host-concentration features, which encode the CIC testbed layout; see
docs/world_model_v3_report.md, ablation).

Split: chronological inside every capture day (Monday to Friday): first 60% of minutes train, next 15%
validation, last 25% test. Windows never cross a segment boundary. The scaler is fit on training minutes,
the checkpoint is chosen on validation loss, and the alert rule (threshold and consecutive-window count N)
is chosen on validation with the same procedure as the leave-one-day-out study. The test segment is
scored once, with everything frozen, and the model saved is exactly the one that was tested.

Test-segment results are in-distribution (attack families seen in training, later in the same day). The
unseen-family numbers are the leave-one-day-out results in the report.

Run: python -m worldmodel_v3.train_production --out backend/artifacts_v3
"""
import argparse
import json
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

from worldmodel_v3.lib import (BEHAVIOURS, H, LOOKBACK, REPO_ROOT, STEP_W, W, choose_operating_point,
                               evaluate_alerts, fit_scaler, input_windows, load, rollout, train, windows)
from worldmodel_v3.run_behaviour import CUT, segment_seqs, seg_fn

FEATURE_SET = "net_nodir"
SEED = 42


def segment_scores(model, segs, mean, std):
    scores, ys = {}, {}
    for date, d in segs.items():
        s = np.full(len(d["y"]), np.nan)
        if len(d["y"]) >= W:
            _, R, _ = rollout(model, input_windows(d, mean, std))
            s[W - 1:] = R.max(axis=1)
        scores[date], ys[date] = s, d["y"]
    return scores, ys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="backend/artifacts_v3")
    args = ap.parse_args()
    days, cols = load(FEATURE_SET)
    tr_seg, va_seg, te_seg = (segment_seqs(days, k) for k in ("train", "val", "test"))
    mean, std = fit_scaler(tr_seg)
    tr = windows(days, mean, std, seg_fn(days, "train"))
    va = windows(days, mean, std, seg_fn(days, "val"))
    te = windows(days, mean, std, seg_fn(days, "test"))
    print(f"{FEATURE_SET}: {len(cols)} features; windows train {len(tr['X'])} val {len(va['X'])} test {len(te['X'])}")
    model = train(tr, va, len(cols), SEED)

    vs, vy = segment_scores(model, va_seg, mean, std)
    thr, N, val_warn, val_fa = choose_operating_point(vs, vy)
    print(f"operating point (validation): threshold {thr:.4f}, N {N}, val warned {val_warn:.2f}, val FA/h {val_fa:.2f}")

    ts, ty = segment_scores(model, te_seg, mean, std)
    alerts = evaluate_alerts(ts, ty, thr, N)
    S_hat, R, C = rollout(model, te["X"])
    y1 = te["yr"][:, 0]
    pred = (R[:, 0] >= 0.5).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y1, pred, average="binary", zero_division=0)
    last = te["X"][:, -1, :]
    test = dict(
        windows=int(len(te["X"])), attack_windows=int(y1.sum()),
        detection=dict(precision=float(p), recall=float(r), f1=float(f1),
                       fpr=float(((pred == 1) & (y1 == 0)).sum() / max((y1 == 0).sum(), 1)),
                       roc_auc=float(roc_auc_score(y1, R[:, 0])) if 0 < y1.sum() < len(y1) else None,
                       pr_auc=float(average_precision_score(y1, R[:, 0])) if y1.sum() else None),
        transition=[dict(step=k + 1, model_mse=float(((S_hat[:, k] - te["F"][:, k]) ** 2).mean()),
                         persist_mse=float(((last - te["F"][:, k]) ** 2).mean())) for k in range(H)],
        early_warning=dict(episodes=alerts["eligible"], warned_within_20=len(alerts["leads"]),
                           within={str(k): v for k, v in alerts["within"].items()},
                           median_lead_min=float(np.median(alerts["leads"])) if alerts["leads"] else None,
                           false_alarm_events=alerts["fa_events"],
                           quiet_hours=alerts["quiet_windows"] / 60.0,
                           false_alarms_per_quiet_hour=alerts["fa_events"] / max(alerts["quiet_windows"] / 60.0, 1e-9)),
    )
    print(json.dumps(test, indent=1))

    out = REPO_ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), out / "network_world_model.pt")
    cfg = dict(
        version="v3_network_state_world_model", feature_set=FEATURE_SET, features=cols, window=W, horizon=H,
        state_interval_seconds=60, transform="log1p(max(x,0)) then standardize", mean=mean.tolist(), std=std.tolist(),
        hidden=128, layers=2, dropout=0.3, behaviours=BEHAVIOURS, step_weights=STEP_W, seed=SEED,
        alert_rule=dict(score="max predicted risk over the next 4 minutes", threshold=thr, consecutive_windows=N,
                        chosen_on="validation segments only", false_alarm_budget_per_quiet_hour=1.0,
                        lookback_minutes=LOOKBACK),
        split=dict(kind="chronological within each capture day", cut=list(CUT),
                   note="test = last 25% of each day; attack families seen in training"),
        test_results=test,
        unseen_family_results="docs/world_model_v3_report.md (leave-one-day-out, feature set net_nodir)",
        data="data/netwin_1min.csv.gz (CIC-IDS2017 labelled flows, 5 capture days)",
    )
    json.dump(cfg, open(out / "config.json", "w"), indent=1)
    print("saved", out)


if __name__ == "__main__":
    main()
