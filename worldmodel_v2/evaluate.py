"""
Full held-out evaluation: V1 (flow world model) vs V2 (network-state world model)
vs persistence vs Logistic Regression, on the SAME test sessions (seed-42 session split).

Sections: detection, state-transition error, future risk / stage, early warning,
data quality. Detection and forecasting are reported separately.

Warning threshold protocol (identical for every model, chosen on VALIDATION only):
the smallest threshold at which <= --fa of "quiet" validation windows alert. A quiet window
has no malicious flow in it or in the K flows / H states that follow. Test windows never
influence the threshold.

Early warning: a test session is eligible if its first malicious flow is preceded by at
least W states of traffic. A model warns if any window ending strictly before the first
malicious flow scores >= threshold. lead = first_malicious_flow_idx - window_end_flow_idx.
Lead is in FLOWS (timestamps are synthetic); no seconds are invented.

Run: python -m worldmodel_v2.evaluate --v2 backend/artifacts_v2 [--out results.json]
"""
import argparse
import json
import pickle
import sys

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, f1_score, precision_recall_fscore_support,
                             roc_auc_score)

from worldmodel_v2.data import REPO_ROOT, W, load_sessions, make_windows
from worldmodel_v2.model import NetStateWorldModel
from worldmodel_v2.state_features import STATE_DIM

sys.path.insert(0, str(REPO_ROOT / "experiments"))
from calibrate_stage_logits import WorldModel as V1Model  # noqa: E402
from evaluate_model import rollout as v1_rollout  # noqa: E402

WITHIN = [5, 10, 12, 20]


def binrep(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    fpr = float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1))
    return dict(n=int(len(y)), pos=int(y.sum()), precision=float(pr), recall=float(rc), f1=float(f1), fpr=fpr,
                roc_auc=float(roc_auc_score(y, p)), pr_auc=float(average_precision_score(y, p)))


@torch.no_grad()
def v2_full(model, X, H):
    S, R, C = [], [], []
    for i in range(0, len(X), 1024):
        s, r, c = model.rollout(torch.tensor(X[i:i + 1024]), H)
        S.append(s.numpy())
        R.append(torch.sigmoid(r).numpy())
        C.append(c.numpy())
    return np.concatenate(S), np.concatenate(R), np.concatenate(C)


def state_windows_all(d, mean, std):
    """All input windows of a session (no future requirement)."""
    S = (d["states"] - mean) / std
    if len(S) < W:
        return np.zeros((0, W, STATE_DIM), np.float32)
    return np.array([S[i - W + 1:i + 1] for i in range(W - 1, len(S))], np.float32)


def quiet_v2(d, H):
    yr, m = d["y_risk"], len(d["y_risk"])
    return np.array([i + H < m and yr[i - W + 1:i + H + 1].sum() == 0 for i in range(W - 1, m)], bool)


def select_threshold(scores_quiet, fa):
    s = np.sort(scores_quiet)
    if len(s) == 0:
        return 0.5
    k = int(np.ceil((1 - fa) * len(s))) - 1
    return float(min(1.0, s[min(max(k, 0), len(s) - 1)] + 1e-6))


def ew_report(per_sess, thr, benign_ids):
    """per_sess: {sid: dict(end=array of end-flow idx, score=array, first_mal=int or None)}"""
    leads, near = [], {n: 0 for n in WITHIN}
    elig = [s for s, v in per_sess.items() if v["first_mal"] is not None]
    for s in elig:
        v = per_sess[s]
        fired = (v["end"] < v["first_mal"]) & (v["score"] >= thr)
        if fired.any():
            lead = v["first_mal"] - v["end"][fired]
            leads.append(int(lead.max()))
            for n in WITHIN:
                near[n] += int((lead <= n).any())
    leads = np.array(leads)
    ben = float(np.mean([(per_sess[s]["score"] >= thr).any() for s in benign_ids])) if benign_ids else None
    r = dict(eligible=len(elig), warned=int(len(leads)), pct_warned=len(leads) / max(len(elig), 1),
             threshold=thr, benign_sessions=len(benign_ids), benign_session_false_alarm_rate=ben)
    for n in WITHIN:
        r[f"pct_within_{n}_flows"] = near[n] / max(len(elig), 1)
    if len(leads):
        r.update(lead_mean=float(leads.mean()), lead_median=float(np.median(leads)),
                 lead_p25=float(np.percentile(leads, 25)), lead_p75=float(np.percentile(leads, 75)),
                 lead_max=int(leads.max()))
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v2", default="backend/artifacts_v2")
    ap.add_argument("--v1", default="backend/artifacts")
    ap.add_argument("--fa", type=float, default=0.05, help="quiet-window alert-rate budget for threshold choice")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    cfg = json.load(open(REPO_ROOT / args.v2 / "config_v2.json"))
    G, H = cfg["G"], cfg["horizon"]
    res = {"config": dict(G=G, H=H, W=W, fa_budget=args.fa)}

    ss = load_sessions(G)
    sc = np.load(REPO_ROOT / args.v2 / "scaler_v2.npz")
    mean, std = sc["mean"], sc["std"]
    m2 = NetStateWorldModel(STATE_DIM)
    m2.load_state_dict(torch.load(REPO_ROOT / args.v2 / "world_model_v2.pt", weights_only=True))
    m2.eval()

    tr, te = make_windows(ss["train"], mean, std, H), make_windows(ss["test"], mean, std, H)
    print(f"V2 G={G} H={H}: test windows {len(te['X'])} from {len(set(te['sid']))} sessions "
          f"(sessions with >= {W + H} states)")

    # ---------- data quality: duplicates and overlap ----------
    train_flows = {r.tobytes() for d in ss["train"].values() for r in d["flows"]}
    dupstate = {}
    for sid, d in ss["test"].items():
        m = len(d["states"])
        if m == 0:
            continue
        fl = d["flows"][:m * G].reshape(m, G, -1)
        dupstate[sid] = np.array([all(r.tobytes() in train_flows for r in st) for st in fl], bool)
    dup = np.array([dupstate[s][e] or dupstate[s][e + 1] for s, e in zip(te["sid"], te["end"])])
    keep = ~dup
    overlap = len(set(ss["test"]) & set(ss["train"]))
    res["data_quality"] = dict(
        test_windows=int(len(dup)), duplicate_windows=int(dup.sum()), duplicate_pct=float(dup.mean()),
        session_id_overlap_train_test=overlap,
        note="duplicate = last input state or first target state has all G flows identical to a training flow")
    print(f"Duplicate test windows (all flows of last input or first target state seen in train): "
          f"{dup.mean():.1%}; session-id overlap train/test: {overlap}")

    S_hat, R, C = v2_full(m2, te["X"], H)

    # ---------- 1. detection (state t+1 contains malicious flows) ----------
    lr = LogisticRegression(max_iter=400, class_weight="balanced").fit(
        tr["X"].reshape(len(tr["X"]), -1), tr["yr"][:, 0])
    p_lr = lr.predict_proba(te["X"].reshape(len(te["X"]), -1))[:, 1]
    print("\n== Detection: does the NEXT state contain malicious flows? (threshold 0.5) ==")
    res["detection"] = {}
    for nm, mask in [("all", np.ones(len(keep), bool)), ("dedup", keep)]:
        y = te["yr"][mask, 0]
        pp, pr_, pf, _ = precision_recall_fscore_support(y, te["cur"][mask], average="binary", zero_division=0)
        rows = {"V2": binrep(y, R[mask, 0]), "LogReg": binrep(y, p_lr[mask]),
                "persistence(label)": dict(precision=float(pp), recall=float(pr_), f1=float(pf))}
        res["detection"][nm] = rows
        for k, v in rows.items():
            extra = f" ROC-AUC={v['roc_auc']:.3f} PR-AUC={v['pr_auc']:.3f} FPR={v['fpr']:.3f}" if "roc_auc" in v else ""
            print(f"{nm:<6}{k:<20} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f}{extra}")

    # ---------- 2. transition error vs persistence ----------
    print("\n== State transition error (scaled state space; lower is better) ==")
    print(f"{'step':<6}{'V2 MSE':>9}{'persist':>9}{'mean':>8}{'V2 MAE':>9}{'persist':>9}")
    last = te["X"][:, -1, :]
    res["transition"] = []
    for k in range(H):
        t = te["F"][:, k]
        row = dict(step=k + 1, v2_mse=float(((S_hat[:, k] - t) ** 2).mean()),
                   persist_mse=float(((last - t) ** 2).mean()), mean_mse=float((t ** 2).mean()),
                   v2_mae=float(np.abs(S_hat[:, k] - t).mean()), persist_mae=float(np.abs(last - t).mean()))
        res["transition"].append(row)
        print(f"{k + 1:<6}{row['v2_mse']:>9.4f}{row['persist_mse']:>9.4f}{row['mean_mse']:>8.4f}"
              f"{row['v2_mae']:>9.4f}{row['persist_mae']:>9.4f}")

    # ---------- 3. future risk / stage ----------
    print("\n== Future forecasting (V2 free-running rollout; de-duplicated windows) ==")
    print(f"{'step':<6}{'risk ROC':>9}{'PR-AUC':>8}{'persist F1':>11}{'V2 F1@.5':>9}{'stage mF1':>10}{'persist mF1':>12}")
    res["future"] = []
    for k in range(H):
        y = te["yr"][keep, k]
        b = binrep(y, R[keep, k])
        pf = f1_score(y, te["cur"][keep], zero_division=0)
        pred_s = C[keep, k].argmax(1)
        present = sorted(set(te["ys"][keep, k]))
        mf = f1_score(te["ys"][keep, k], pred_s, labels=present, average="macro", zero_division=0)
        pmf = f1_score(te["ys"][keep, k], te["curs"][keep], labels=present, average="macro", zero_division=0)
        res["future"].append(dict(step=k + 1, risk=b, persistence_f1=float(pf), stage_macro_f1=float(mf),
                                  stage_persistence_macro_f1=float(pmf), stage_classes=[int(x) for x in present]))
        print(f"{k + 1:<6}{b['roc_auc']:>9.3f}{b['pr_auc']:>8.3f}{pf:>11.3f}{b['f1']:>9.3f}{mf:>10.3f}{pmf:>12.3f}")
    print("  stage macro-F1 covers only classes present in the test targets; Exfiltration has no windows.")

    # ---------- 4. early warning ----------
    print("\n== Early warning (lead in flows; threshold from validation, quiet-window alert rate <= "
          f"{args.fa:.0%}) ==")
    ew = {}
    v1cfg = json.load(open(REPO_ROOT / args.v1 / "config.json"))
    raw = pickle.load(open(REPO_ROOT / args.v1 / "scaler.pkl", "rb"))
    m1mean, m1scale = np.asarray(raw["mean"], np.float32), np.asarray(raw["scale"], np.float32)
    m1 = V1Model(22, v1cfg["hidden_size"], 6, v1cfg["num_layers"], v1cfg["lstm_dropout"])
    m1.load_state_dict(torch.load(REPO_ROOT / args.v1 / "world_model.pt", map_location="cpu", weights_only=True))
    m1.eval()
    K1 = 4  # V1 shipped rollout horizon (flows)

    def per_session(split, kind):
        out, quiet = {}, []
        for sid, d in ss[split].items():
            m = len(d["states"])
            mal = d["mal"]
            fm = int(np.argmax(mal)) if mal.sum() else None
            if kind == "v1":
                f = ((d["flows"] - m1mean) / m1scale).astype(np.float32)
                n = len(f)
                if n < 6:
                    continue
                Xw = np.array([f[i - 5:i + 1] for i in range(5, n)])
                _, pr = v1_rollout(m1, Xw, K1)
                score, end = pr.max(1), np.arange(5, n)
                q = np.array([i + K1 < n and mal[i - 5:i + K1 + 1].sum() == 0 for i in range(5, n)])
                onset_ok = fm is not None and fm >= W * G
            else:
                if m < W:
                    continue
                Xw = state_windows_all(d, mean, std)
                if kind == "v2":
                    _, r, _ = v2_full(m2, Xw, H)
                    score = r.max(1)
                else:
                    score = lr.predict_proba(Xw.reshape(len(Xw), -1))[:, 1]
                end = (np.arange(W - 1, m) + 1) * G - 1
                q = quiet_v2(d, H)
                st_on = int(np.argmax(d["y_risk"])) if d["y_risk"].sum() else None
                onset_ok = fm is not None and st_on is not None and st_on >= W
            out[sid] = dict(end=end, score=score, first_mal=fm if onset_ok else None, benign=bool(mal.sum() == 0))
            quiet.append(score[q])
        return out, (np.concatenate(quiet) if quiet else np.array([]))

    for kind, label in [("v1", "V1 flow model"), ("v2", "V2 network-state model"), ("lr", "LogReg (V2 states)")]:
        _, vq = per_session("val", kind)
        thr = select_threshold(vq, args.fa)
        ps, tq = per_session("test", kind)
        elig_ids = [s for s, v in ps.items() if v["first_mal"] is not None]
        ben_ids = [s for s, v in ps.items() if v["benign"]]
        rep = ew_report({s: ps[s] for s in elig_ids + ben_ids}, thr, ben_ids)
        rep["test_quiet_window_alert_rate"] = float((tq >= thr).mean()) if len(tq) else None
        ew[kind] = rep
        print(f"{label:<24} eligible={rep['eligible']} warned={rep['warned']} ({rep['pct_warned']:.1%}) "
              f"thr={thr:.3f} quiet-alert(test)={rep['test_quiet_window_alert_rate']:.3f} "
              f"benign-session-FA={rep['benign_session_false_alarm_rate']:.2f}")
        if "lead_median" in rep:
            print(f"{'':<24} lead flows: mean={rep['lead_mean']:.1f} median={rep['lead_median']:.0f} "
                  f"p25={rep['lead_p25']:.0f} p75={rep['lead_p75']:.0f} max={rep['lead_max']}")
        print(f"{'':<24} warning within " + ", ".join(f"{n} flows: {rep[f'pct_within_{n}_flows']:.1%}"
                                                     for n in WITHIN))
    res["early_warning"] = ew
    if args.out:
        json.dump(res, open(REPO_ROOT / args.out, "w"), indent=2, default=float)
        print("wrote", args.out)


if __name__ == "__main__":
    main()
