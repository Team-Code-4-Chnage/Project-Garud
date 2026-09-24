"""Aggregate experiments/v3_lodo.json and v3_behaviour.json into mean/std/min/max tables."""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent
lodo = json.load(open(ROOT / "v3_lodo.json"))
if (ROOT / "v3_lodo_nodir.json").exists():  # ablation: network context without direction/host features
    lodo.update(json.load(open(ROOT / "v3_lodo_nodir.json")))
beh = json.load(open(ROOT / "v3_behaviour.json"))


def stat(vals):
    v = np.array([x for x in vals if x is not None], float)
    return f"{v.mean():.3f} +/- {v.std():.3f} [{v.min():.3f}, {v.max():.3f}]"


def wilson(k, n, z=1.96):
    if n == 0:
        return (0, 0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


print("== LODO, 5 seeds, mean +/- std [min, max] ==")
rows = [("warned <=20 min", "pct_warned_20"), ("within 5 min", "pct_within_5"), ("within 10 min", "pct_within_10"),
        ("within 12 min", "pct_within_12"), ("within 20 min", "pct_within_20"),
        ("median lead (min)", "lead_median"), ("mean lead (min)", "lead_mean"),
        ("false alarms / quiet hour", "fa_events_per_quiet_hour"), ("alert rate, quiet windows", "fa_window_rate"),
        ("false-alarm 60-min blocks", "fa_hour_block_rate")]
for fs in [k for k in ("flow", "net", "net_nodir") if k in lodo]:
    S = list(lodo[fs]["seeds"].values())
    print(f"\n-- feature set {fs} ({lodo[fs]['n_features']} features) --")
    print(f"episodes eligible: {S[0]['eligible']}  quiet windows: {S[0]['quiet_windows']}  quiet 60-min blocks: "
          f"{S[0]['quiet_blocks']}  attack windows: {S[0]['attack_windows']}  benign windows: {S[0]['benign_windows']}")
    for name, key in rows:
        print(f"{name:<28}{stat([s[key] for s in S])}")
    for key in ("f1", "precision", "recall", "fpr", "roc_auc", "pr_auc"):
        print(f"detect {key:<21}{stat([s['detect'].get(key) for s in S])}")
    print(f"persistence detect F1        {S[0]['detect_persistence']['f1']:.3f}")
    for k in range(4):
        m = [s["transition"][k]["model_mse"] for s in S]
        p = [s["transition"][k]["persist_mse"] for s in S]
        ma = [s["transition"][k]["model_mae"] for s in S]
        pa = [s["transition"][k]["persist_mae"] for s in S]
        print(f"transition +{k + 1}: MSE {np.mean(m):.3f} (persist {np.mean(p):.3f})  "
              f"MAE {np.mean(ma):.3f} (persist {np.mean(pa):.3f})")
    L = lodo[fs]["lr"]
    print(f"LogReg: warned<=20 {L['pct_warned_20']:.2f} within5 {L['pct_within_5']:.2f} within12 "
          f"{L['pct_within_12']:.2f} FA/h {L['fa_events_per_quiet_hour']:.2f} detect F1 {L['detect']['f1']:.3f} "
          f"ROC {L['detect'].get('roc_auc', float('nan')):.3f}")
    counts = [s["warned_20"] for s in S]
    lo, hi = wilson(np.mean(counts), S[0]["eligible"])
    print(f"mean warned {np.mean(counts):.1f}/{S[0]['eligible']} episodes; 95% Wilson interval on that proportion "
          f"{lo:.2f}-{hi:.2f}")
    print("operating points (seed 42):", S[0]["operating_points"])

print("\n== Behaviour forecasting, chronological within-day split, 5 seeds ==")
for fs in ("flow", "net"):
    print(f"\n-- {fs} --")
    seeds = list(beh[fs]["seeds"].values())
    print("train support (step 1) seed 42:", dict(zip(beh["classes"], seeds[0]["train_support_step1"])))
    for k in range(4):
        pk = [s["per_k"][k] for s in seeds]
        print(f"+{k + 1}: acc {stat([p['acc'] for p in pk])} persist {pk[0]['persist_acc']:.3f} | "
              f"macroF1(present) {stat([p['macro_f1'] for p in pk])} persist {pk[0]['persist_macro_f1']:.3f} | "
              f"macroF1(supported {pk[0]['supported_classes']}) {stat([p['macro_f1_supported'] for p in pk])} "
              f"persist {pk[0]['persist_macro_f1_supported']:.3f}")
    print("per-class F1 at +1 (mean over seeds; support; persistence):")
    for c in beh["classes"]:
        f = [s["per_k"][0]["per_class"][c]["f1"] for s in seeds]
        sup = seeds[0]["per_k"][0]["per_class"][c]["support"]
        pf = seeds[0]["per_k"][0]["per_class"][c]["persist_f1"]
        pr = np.mean([s["per_k"][0]["per_class"][c]["precision"] for s in seeds])
        rc = np.mean([s["per_k"][0]["per_class"][c]["recall"] for s in seeds])
        print(f"  {c:<13} P {pr:.2f} R {rc:.2f} F1 {np.mean(f):.2f} test support {sup:>4} persistence F1 {pf:.2f}")
    print("confusion +1, seed 42 (rows true, cols pred):")
    print(np.array(seeds[0]["per_k"][0]["confusion"]))
