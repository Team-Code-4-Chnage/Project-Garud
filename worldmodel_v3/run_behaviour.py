"""
Secondary V3 experiment: attack-BEHAVIOUR forecasting under a chronological within-day split.

Why a second protocol: under leave-one-day-out the held-out day's attack families are unseen, so a
behaviour class can never be predicted. Here each day is cut in time: first 60% train, next 15%
validation, last 25% test. Windows lie entirely inside one segment (this purges any overlap of inputs
or targets across the boundary). Test segments therefore contain whatever behaviours happen late in
each day, some of which have training support and some of which do not; support is reported per class.

The dataset has no campaign/stage timeline (each family occupies its own time block, and there is no
Recon -> Access -> Lateral -> C2 -> Exfil chain), so this forecasts attack BEHAVIOUR classes at t+k, not
MITRE stages. Baseline is persistence: predicted behaviour(t+k) = behaviour at the last input minute.

Run: python -m worldmodel_v3.run_behaviour --out experiments/v3_behaviour.json
"""
import argparse
import json

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support

from worldmodel_v3.lib import BEHAVIOURS, H, W, fit_scaler, load, rollout, train, windows

SEEDS = [42, 123, 456, 789, 2026]
CUT = (0.60, 0.75)
MIN_TRAIN_SUPPORT = 30  # a class needs this many training windows to count as learnable


def seg_fn(days, which):
    n = {d: len(v["y"]) for d, v in days.items()}

    def fn(date, i):
        a, b = int(CUT[0] * n[date]), int(CUT[1] * n[date])
        end = i + W + H
        if which == "train":
            return end <= a
        if which == "val":
            return i >= a and end <= b
        return i >= b
    return fn


def segment_seqs(days, which):
    """Days restricted to a segment, used for scaler fitting (train only)."""
    out = {}
    for d, v in days.items():
        n = len(v["y"])
        a, b = int(CUT[0] * n), int(CUT[1] * n)
        sl = slice(0, a) if which == "train" else slice(a, b) if which == "val" else slice(b, n)
        out[d] = {k: (x[sl] if hasattr(x, "__len__") else x) for k, x in v.items()}
    return out


def run(days, seed, dim):
    trs = segment_seqs(days, "train")
    mean, std = fit_scaler(trs)
    tr = windows(days, mean, std, seg_fn(days, "train"))
    va = windows(days, mean, std, seg_fn(days, "val"))
    te = windows(days, mean, std, seg_fn(days, "test"))
    model = train(tr, va, dim, seed)
    _, _, C = rollout(model, te["X"])
    cur = np.array([days[d]["beh"][e] for d, e in zip(te["day"], te["end"])])
    return tr, te, C, cur


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="experiments/v3_behaviour.json")
    ap.add_argument("--seeds", type=int, nargs="*", default=SEEDS)
    args = ap.parse_args()
    res = {}
    for fs in ("flow", "net"):
        days, cols = load(fs)
        dim = len(cols)
        res[fs] = dict(seeds={})
        for seed in args.seeds:
            tr, te, C, cur = run(days, seed, dim)
            per_k = []
            for k in range(H):
                y = te["yb"][:, k]
                pred = C[:, k].argmax(1)
                present = sorted(set(y))
                row = dict(step=k + 1,
                           acc=float(accuracy_score(y, pred)), persist_acc=float(accuracy_score(y, cur)),
                           macro_f1=float(f1_score(y, pred, labels=present, average="macro", zero_division=0)),
                           persist_macro_f1=float(f1_score(y, cur, labels=present, average="macro", zero_division=0)))
                sup = np.bincount(tr["yb"][:, 0], minlength=len(BEHAVIOURS))
                supported = [c for c in present if sup[c] >= MIN_TRAIN_SUPPORT]
                row["supported_classes"] = [BEHAVIOURS[c] for c in supported]
                row["macro_f1_supported"] = float(f1_score(y, pred, labels=supported, average="macro", zero_division=0))
                row["persist_macro_f1_supported"] = float(f1_score(y, cur, labels=supported, average="macro",
                                                                   zero_division=0))
                p, r, f, s = precision_recall_fscore_support(y, pred, labels=range(len(BEHAVIOURS)), zero_division=0)
                pp, pr_, pf, _ = precision_recall_fscore_support(y, cur, labels=range(len(BEHAVIOURS)), zero_division=0)
                row["per_class"] = {BEHAVIOURS[i]: dict(precision=float(p[i]), recall=float(r[i]), f1=float(f[i]),
                                                         support=int(s[i]), persist_f1=float(pf[i]))
                                    for i in range(len(BEHAVIOURS))}
                if k in (0, H - 1):
                    row["confusion"] = confusion_matrix(y, pred, labels=range(len(BEHAVIOURS))).tolist()
                per_k.append(row)
            train_support = np.bincount(tr["yb"][:, 0], minlength=len(BEHAVIOURS)).tolist()
            res[fs]["seeds"][seed] = dict(per_k=per_k, train_support_step1=train_support,
                                          test_windows=int(len(te["X"])))
            print(fs, seed, "macroF1 k=1..4:", [round(x["macro_f1"], 3) for x in per_k],
                  "persist:", [round(x["persist_macro_f1"], 3) for x in per_k], flush=True)
    res["classes"] = BEHAVIOURS
    json.dump(res, open(args.out, "w"), indent=1, default=float)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
