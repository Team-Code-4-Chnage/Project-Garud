"""
Primary V3 experiment: leave-one-day-out (LODO) over the four CIC-IDS2017 attack days.

For each held-out day D: validation = the next attack day (cyclic), training = the remaining days
including the benign-only Monday. Every attack family in D is therefore unseen in training
(DoS on Wednesday is related to DDoS on Friday; noted in the report). Scaler, early stopping,
alert threshold and persistence N are all fit on train/validation only and frozen before the test day.

Compares feature sets ("flow" = window flow statistics only, "net" = plus network context),
against persistence and Logistic Regression, over 5 seeds.

Run: python -m worldmodel_v3.run_lodo --out experiments/v3_lodo.json
"""
import argparse
import json
import time

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

from worldmodel_v3.lib import (DAYS, H, W, WITHIN, choose_operating_point, evaluate_alerts, fit_scaler,
                               input_windows, load, rollout, train, windows)

SEEDS = [42, 123, 456, 789, 2026]


def day_scores(fn, seqs, mean, std):
    """score array per day aligned to minute index (NaN before the first full window)."""
    out, ys = {}, {}
    for date, d in seqs.items():
        Xw = input_windows(d, mean, std)
        s = np.full(len(d["y"]), np.nan)
        s[W - 1:] = fn(Xw)
        out[date], ys[date] = s, d["y"]
    return out, ys


def binary(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    fpr = float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1))
    out = dict(precision=float(pr), recall=float(rc), f1=float(f1), fpr=fpr, n=int(len(y)), pos=int(y.sum()))
    if 0 < y.sum() < len(y):
        out.update(roc_auc=float(roc_auc_score(y, p)), pr_auc=float(average_precision_score(y, p)))
    return out


def run_fold(days, cols, test_day, seed, use_lr=False):
    val_day = DAYS[(DAYS.index(test_day) + 1) % len(DAYS)]
    tr_days = [d for d in days if d not in (test_day, val_day)]
    trs = {d: days[d] for d in tr_days}
    vas, tes = {val_day: days[val_day]}, {test_day: days[test_day]}
    mean, std = fit_scaler(trs)
    tr, va, te = (windows(trs, mean, std), windows(vas, mean, std), windows(tes, mean, std))
    if use_lr:
        lr = LogisticRegression(max_iter=500, class_weight="balanced").fit(
            tr["X"].reshape(len(tr["X"]), -1), tr["yr"][:, 0])
        score_fn = lambda Xw: lr.predict_proba(Xw.reshape(len(Xw), -1))[:, 1]  # noqa: E731
        p1 = score_fn(te["X"])
        fut = None
    else:
        model = train(tr, va, tr["X"].shape[-1], seed)
        score_fn = lambda Xw: rollout(model, Xw)[1].max(axis=1)  # noqa: E731
        S_hat, R, _ = rollout(model, te["X"])
        p1 = R[:, 0]
        fut = S_hat
    vs, vy = day_scores(score_fn, vas, mean, std)
    thr, N, val_warn, val_fa = choose_operating_point(vs, vy)
    ts, ty = day_scores(score_fn, tes, mean, std)
    alerts = evaluate_alerts(ts, ty, thr, N)
    out = dict(test_day=test_day, val_day=val_day, thr=thr, N=N, val_warned=val_warn, val_fa_per_hour=val_fa,
               alerts=alerts, detect=dict(p=p1.tolist(), y=te["yr"][:, 0].tolist(),
                                          cur=[int(ty[test_day][e]) for e in te["end"]]))
    if fut is not None:
        last = te["X"][:, -1, :]
        out["transition"] = [dict(step=k + 1, model_mse=float(((fut[:, k] - te["F"][:, k]) ** 2).mean()),
                                  persist_mse=float(((last - te["F"][:, k]) ** 2).mean()),
                                  model_mae=float(np.abs(fut[:, k] - te["F"][:, k]).mean()),
                                  persist_mae=float(np.abs(last - te["F"][:, k]).mean()), n=int(len(last)))
                             for k in range(H)]
    return out


def pool(folds):
    """Pool per-fold results of one (model, seed) run."""
    a = [f["alerts"] for f in folds]
    elig = sum(x["eligible"] for x in a)
    leads = [l for x in a for l in x["leads"]]
    r = dict(eligible=elig, warned_20=len(leads),
             quiet_windows=sum(x["quiet_windows"] for x in a), fa_windows=sum(x["fa_windows"] for x in a),
             fa_events=sum(x["fa_events"] for x in a), quiet_blocks=sum(x["quiet_hours_blocks"] for x in a),
             fa_blocks=sum(x["fa_hours_blocks"] for x in a),
             attack_windows=sum(x["attack_windows"] for x in a), benign_windows=sum(x["benign_windows"] for x in a),
             operating_points=[(f["test_day"], round(f["thr"], 4), f["N"]) for f in folds])
    for n in WITHIN:
        r[f"warned_within_{n}"] = sum(x["within"][n] for x in a)
    r["pct_warned_20"] = r["warned_20"] / max(elig, 1)
    for n in WITHIN:
        r[f"pct_within_{n}"] = r[f"warned_within_{n}"] / max(elig, 1)
    r["fa_events_per_quiet_hour"] = r["fa_events"] / max(r["quiet_windows"] / 60.0, 1e-9)
    r["fa_window_rate"] = r["fa_windows"] / max(r["quiet_windows"], 1)
    r["fa_hour_block_rate"] = r["fa_blocks"] / max(r["quiet_blocks"], 1)
    r["lead_mean"] = float(np.mean(leads)) if leads else None
    r["lead_median"] = float(np.median(leads)) if leads else None
    p = np.concatenate([f["detect"]["p"] for f in folds])
    y = np.concatenate([f["detect"]["y"] for f in folds]).astype(int)
    cur = np.concatenate([f["detect"]["cur"] for f in folds]).astype(int)
    r["detect"] = binary(y, p)
    pr, rc, f1, _ = precision_recall_fscore_support(y, cur, average="binary", zero_division=0)
    r["detect_persistence"] = dict(precision=float(pr), recall=float(rc), f1=float(f1))
    if "transition" in folds[0]:
        r["transition"] = []
        for k in range(H):
            ws = np.array([f["transition"][k]["n"] for f in folds], float)
            def wavg(key):  # noqa: E306
                return float(np.average([f["transition"][k][key] for f in folds], weights=ws))
            r["transition"].append(dict(step=k + 1, model_mse=wavg("model_mse"), persist_mse=wavg("persist_mse"),
                                        model_mae=wavg("model_mae"), persist_mae=wavg("persist_mae")))
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="experiments/v3_lodo.json")
    ap.add_argument("--seeds", type=int, nargs="*", default=SEEDS)
    ap.add_argument("--feature-sets", nargs="*", default=["flow", "net"])
    args = ap.parse_args()
    results = {}
    for fs in args.feature_sets:
        days, cols = load(fs)
        print(f"== feature set {fs}: {len(cols)} features", flush=True)
        results[fs] = dict(n_features=len(cols), seeds={}, lr=None)
        for seed in args.seeds:
            t0 = time.time()
            folds = [run_fold(days, cols, d, seed) for d in DAYS]
            results[fs]["seeds"][seed] = pool(folds)
            r = results[fs]["seeds"][seed]
            print(f"  seed {seed}: warned<=20m {r['pct_warned_20']:.0%} ({r['warned_20']}/{r['eligible']}) "
                  f"within5 {r['pct_within_5']:.0%} FA/h {r['fa_events_per_quiet_hour']:.2f} "
                  f"detF1 {r['detect']['f1']:.3f} ({time.time() - t0:.0f}s)", flush=True)
        folds = [run_fold(days, cols, d, 0, use_lr=True) for d in DAYS]
        results[fs]["lr"] = pool(folds)
        r = results[fs]["lr"]
        print(f"  LogReg: warned<=20m {r['pct_warned_20']:.0%} within5 {r['pct_within_5']:.0%} "
              f"FA/h {r['fa_events_per_quiet_hour']:.2f} detF1 {r['detect']['f1']:.3f}", flush=True)
    json.dump(results, open(args.out, "w"), indent=1, default=float)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
