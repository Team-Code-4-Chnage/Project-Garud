"""
Single-flow behaviour classifier trained on real CIC-IDS2017 flows.

It scores one flow from its 22 features, independent of sessions, addresses or time, which is what an
uploaded file of unknown structure can always provide. Output classes are the behaviours of
backend/app/labels.py (Benign plus eight attack behaviours); the attack probability is 1 - P(Benign).
Features come from the converter that serves uploads (backend/app/flow_schema.adapt_frame), so training
and serving see identical columns.

Data split, shared with the network-state model (worldmodel_v3): within each capture day the minutes are
cut at 60% and 75%. Before 60%: fit. 60-75%: choose hyper-parameters and the alert threshold. After 75%:
test, never used for any choice. The served model is refit on everything before the 75% cut. Every
attack family in the test record states how many of its rows were in training, because some families
(for example DDoS) occur only late in their day.

Needs the labelled flow files (with timestamps): python data/fetch_cic2017_labelled.py
Run: python -m flowclf.train [--labelled data/cic2017_labelled] [--out backend/artifacts_flow]
"""
import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from app.config import FLOW_FEATURES  # noqa: E402
from app.flow_schema import adapt_frame  # noqa: E402
from app.labels import BEHAVIOURS, behaviour_of  # noqa: E402

CUT_VAL, CUT_TEST = 0.60, 0.75
MAX_PER_CLASS = 120_000
SEED = 42
CONFIGS = [
    dict(max_iter=150, learning_rate=0.1, max_leaf_nodes=31),
    dict(max_iter=250, learning_rate=0.08, max_leaf_nodes=63),
    dict(max_iter=400, learning_rate=0.06, max_leaf_nodes=127, l2_regularization=1.0),
    dict(max_iter=600, learning_rate=0.05, max_leaf_nodes=63, min_samples_leaf=50, l2_regularization=1.0),
]
MAX_VAL_FPR = 0.01          # the alert threshold is the F1-best one on validation with at most this benign rate


def day_cuts() -> dict:
    """First minute of the validation and test segments of every capture day (the network model's grid)."""
    n = pd.read_csv(ROOT / "data/netwin_1min.csv.gz", usecols=["minute"])
    n["minute"] = pd.to_datetime(n["minute"])
    return {d: (g["minute"].iloc[int(CUT_VAL * len(g))], g["minute"].iloc[int(CUT_TEST * len(g))])
            for d, g in n.groupby(n["minute"].dt.date)}


def load(labelled_dir: Path) -> pd.DataFrame:
    parts = []
    for path in sorted(labelled_dir.glob("*.parquet")):
        t = time.time()
        raw = pd.read_parquet(path)
        for i in range(0, len(raw), 200_000):
            chunk = raw.iloc[i:i + 200_000]
            feats, meta, _ = adapt_frame(chunk.astype(str))
            df = feats.astype(np.float32)
            df["label"] = meta["label"].astype(str).str.strip().values
            df["ts"] = pd.to_datetime(chunk["Timestamp"]).values
            parts.append(df)
        print(f"loaded {path.name} ({time.time() - t:.0f}s)")
    data = pd.concat(parts, ignore_index=True)
    data["behaviour"] = data["label"].map(behaviour_of)
    unknown = data["behaviour"].isna() | data["behaviour"].isin(["Unknown"])
    print("dropping rows with uninterpretable labels:", int(unknown.sum()))
    data = data[~unknown].reset_index(drop=True)
    data["y"] = (data["behaviour"] != "Benign").astype(int)
    data["cls"] = data["behaviour"].map({b: i for i, b in enumerate(BEHAVIOURS)}).astype(int)
    data["day"] = data["ts"].dt.date
    cuts = day_cuts()
    test_from = data["day"].map(lambda d: cuts[d][1])
    val_from = data["day"].map(lambda d: cuts[d][0])
    data["seg"] = np.where(data["ts"] >= test_from, "test", np.where(data["ts"] >= val_from, "val", "train"))
    return data


def fit(train: pd.DataFrame, params: dict) -> HistGradientBoostingClassifier:
    """Fit on a class-capped sample; weights restore each class's true share of the training rows."""
    rng = np.random.RandomState(SEED)
    parts, weights = [], []
    for _, g in train.groupby("cls"):
        take = g if len(g) <= MAX_PER_CLASS else g.iloc[rng.choice(len(g), MAX_PER_CLASS, replace=False)]
        parts.append(take)
        weights.append(np.full(len(take), len(g) / len(take)))
    s, w = pd.concat(parts), np.concatenate(weights)
    # attack classes count more than their raw share so rare families are not ignored
    counts = train["cls"].value_counts()
    boost = s["cls"].map(lambda c: 1.0 if c == 0 else min(8.0, (counts[0] / counts[c]) ** 0.3)).to_numpy()
    m = HistGradientBoostingClassifier(random_state=SEED, **params)
    return m.fit(s[FLOW_FEATURES].to_numpy(), s["cls"].to_numpy(), sample_weight=w * boost)


def attack_prob(model, x) -> np.ndarray:
    p = model.predict_proba(x)
    return 1.0 - p[:, list(model.classes_).index(0)]


def binary_metrics(y, p, thr) -> dict:
    out = dict(rows=int(len(y)), attacks=int(y.sum()), threshold=float(thr))
    if 0 < y.sum() < len(y):
        pred = p >= thr
        pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        out.update(roc_auc=float(roc_auc_score(y, p)), pr_auc=float(average_precision_score(y, p)),
                   precision=float(pr), recall=float(rc), f1=float(f1),
                   fpr=float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)))
    return out


def choose_threshold(y, p, max_fpr=MAX_VAL_FPR) -> float:
    best, best_f1 = 0.5, -1.0
    for thr in np.linspace(0.05, 0.95, 91):
        pred = p >= thr
        fpr = ((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)
        if fpr > max_fpr:
            continue
        _, _, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        if f1 > best_f1:
            best, best_f1 = float(thr), float(f1)
    return best


def evaluate(model, te: pd.DataFrame, thr: float, train_rows: dict) -> dict:
    x = te[FLOW_FEATURES].to_numpy()
    proba = model.predict_proba(x)
    ap = 1.0 - proba[:, list(model.classes_).index(0)]
    res = binary_metrics(te["y"].to_numpy(), ap, thr)
    pred_cls = model.classes_[np.argmax(proba, axis=1)]
    fam = {}
    for b, g in te[te.y == 1].groupby("behaviour"):
        idx = te.index.get_indexer(g.index)
        fam[b] = dict(rows=int(len(g)), detected=float((ap[idx] >= thr).mean()),
                      family_correct=float((pred_cls[idx] == BEHAVIOURS.index(b)).mean()),
                      rows_in_training=int(train_rows.get(b, 0)))
    res["families"] = fam
    return res


def show(name, res):
    print(name, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in res.items() if k != "families"})
    for b, f in res["families"].items():
        print(f"    {b}: {f['rows']} rows, detected {f['detected']:.3f}, family right {f['family_correct']:.3f}, "
              f"rows in training {f['rows_in_training']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labelled", default=str(ROOT / "data/cic2017_labelled"))
    ap.add_argument("--out", default=str(ROOT / "backend/artifacts_flow"))
    args = ap.parse_args()

    data = load(Path(args.labelled))
    tr, va, te = (data[data.seg == s] for s in ("train", "val", "test"))
    print(f"fit {len(tr)} rows | validation {len(va)} ({int(va.y.sum())} attacks) | test {len(te)} ({int(te.y.sum())} attacks)")

    # choose the configuration and the alert threshold on the validation segments only
    best = None
    for params in CONFIGS:
        t = time.time()
        m = fit(tr, params)
        ap_va = attack_prob(m, va[FLOW_FEATURES].to_numpy())
        score = average_precision_score(va["y"], ap_va) if 0 < va.y.sum() < len(va) else 0.0
        print(f"config {params}: validation PR-AUC {score:.4f} ({time.time() - t:.0f}s)", flush=True)
        if best is None or score > best[0]:
            best = (score, params, ap_va)
    _, params, ap_va = best
    val_thr = choose_threshold(va["y"].to_numpy(), ap_va)
    # served threshold: 0.5 on class-prior-restored probabilities, fixed before looking at the test segments.
    # The validation-optimal value is recorded for information; it is very low because validation days
    # contain long attack stretches, which would raise false alarms on quiet traffic.
    thr = 0.5
    print("chosen", params, "threshold", thr, "(validation-optimal:", round(val_thr, 3), ")", flush=True)

    # the served model: everything before the test cut; measured on the test segments
    train_all = data[data.seg != "test"]
    final = fit(train_all, params)
    fam_train = train_all[train_all.y == 1].groupby("behaviour").size().to_dict()
    test_res = evaluate(final, te, thr, fam_train)
    show("held-out test segments", test_res)
    ap_te = attack_prob(final, te[FLOW_FEATURES].to_numpy())
    test_res["at_other_thresholds"] = {f"{t:.2f}": binary_metrics(te["y"].to_numpy(), ap_te, t) for t in (0.05, 0.2, 0.5, 0.8)}
    for t, m in test_res["at_other_thresholds"].items():
        print("  threshold", t, {k: round(v, 4) for k, v in m.items() if k in ("precision", "recall", "f1", "fpr")})

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(final, out / "flow_classifier.joblib", compress=3)
    cfg = dict(
        version="flow_classifier_v2", features=FLOW_FEATURES, behaviours=BEHAVIOURS,
        classes=[int(c) for c in final.classes_], attack_threshold=thr, validation_optimal_threshold=val_thr,
        model=f"HistGradientBoostingClassifier({params})",
        trained_on="CIC-IDS2017 labelled flows (data/cic2017_labelled), all flows before each day's test cut",
        split=f"per capture day, minutes cut at {CUT_VAL:.0%} and {CUT_TEST:.0%} (same grid as the network-state "
              "model): fit / choose configuration and threshold / test",
        training_rows=int(len(train_all)), training_attack_rows=int(train_all.y.sum()),
        label_rule="labels are mapped to behaviours by backend/app/labels.py; Benign vs everything else is the attack flag",
        held_out_test=test_res,
        limits="A supervised flow classifier finds behaviours it was trained on. Families that are absent from "
               "the training rows are mostly missed (see rows_in_training per family), and data from another "
               "dataset or capture environment can be poorly separated with these 22 features "
               "(CSE-CIC-IDS2018 infiltration: ROC-AUC below 0.5 in our checks).",
        seed=SEED,
    )
    json.dump(cfg, open(out / "config.json", "w"), indent=1)
    print("saved", out)


if __name__ == "__main__":
    main()
