"""
Per-class stage-logit bias calibration for the shipped world_model.pt.

Why: the trained model's raw argmax over the 6 MITRE stage logits is
imbalanced -- e.g. Initial Access recall was high but precision low,
because Benign traffic with unusual timing gets misclassified as an
attack stage more often than the reverse. Retraining with tighter
class-weight clipping helps but trades off against other stages (see
docs/model_card.md). Post-hoc logit-bias calibration (Menon et al.,
"Long-tail learning via logit adjustment", ICLR 2021) is a second,
independent, no-retraining lever: search for a per-class additive bias
on the stage logits that maximizes macro-F1 on the VALIDATION split,
then apply that fixed bias at inference time. Because it's fit on val
and only ever evaluated on test for reporting (never fit on test),
this is honest held-out evaluation, not test-set tuning.

This script only reads real_flows.csv and backend/artifacts/ -- it
never modifies them. It writes the calibrated bias to
backend/artifacts/config.json's "stage_logit_bias" key by hand (the
printed numbers were copied in manually after review); it does not
overwrite config.json itself, to keep a human decision point between
"the search found a bias" and "the shipped model uses it".

Run as: python experiments/calibrate_stage_logits.py
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import f1_score, precision_recall_fscore_support

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from pipeline_fixed import three_way_split  # noqa: E402

SEED = 42
WINDOW = 6
STAGES = ["Benign", "Reconnaissance", "Initial Access", "Lateral Movement", "C2", "Exfiltration"]
STAGE2ID = {s: i for i, s in enumerate(STAGES)}
FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]


class WorldModel(nn.Module):
    def __init__(self, n_features, hidden, n_stages, num_layers, dropout):
        super().__init__()
        self.lstm = nn.LSTM(n_features, hidden, num_layers=num_layers, batch_first=True,
                             dropout=dropout if num_layers > 1 else 0.0)
        self.next_state_head = nn.Linear(hidden, n_features)
        self.infiltration_head = nn.Sequential(nn.Linear(hidden, 64), nn.ReLU(), nn.Dropout(dropout),
                                                nn.Linear(64, 32), nn.ReLU(), nn.Linear(32, 1))
        self.stage_head = nn.Sequential(nn.Linear(hidden, 64), nn.ReLU(), nn.Linear(64, n_stages))

    def forward(self, x):
        out, (h_n, _) = self.lstm(x)
        h = h_n[-1]
        return self.next_state_head(h), self.infiltration_head(h).squeeze(-1), self.stage_head(h)


def build_sequences(d, window=WINDOW):
    X, ys = [], []
    for _sid, g in d.groupby("session_id"):
        feats = g[FLOW_FEATURES].values
        stage = g["stage_id"].values
        for i in range(len(g) - window):
            X.append(feats[i:i + window])
            ys.append(stage[i + window])
    return np.array(X, dtype=np.float32), np.array(ys, dtype=np.int64)


def load_split(df, sids, mean, scale):
    d = df[df["session_id"].isin(sids)].copy()
    d[FLOW_FEATURES] = (d[FLOW_FEATURES].values - mean) / scale
    d["stage_id"] = d["stage_label"].map(STAGE2ID)
    d = d.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    return build_sequences(d)


def get_logits(model, X):
    out = []
    with torch.no_grad():
        for i in range(0, len(X), 512):
            xb = torch.tensor(X[i:i + 512])
            _, _, stage_logits = model(xb)
            out.append(stage_logits.numpy())
    return np.concatenate(out)


def report(y_true, pred, header):
    p, r, f1, sup = precision_recall_fscore_support(y_true, pred, labels=range(6), zero_division=0)
    print(f"{header} macro-F1: {f1_score(y_true, pred, average='macro'):.4f}")
    for i, s in enumerate(STAGES):
        print(f"  {s:<18} P={p[i]:.3f} R={r[i]:.3f} F1={f1[i]:.3f} n={sup[i]}")


def main():
    df = pd.read_csv(REPO_ROOT / "real_flows.csv")
    uids = df["session_id"].unique()
    train_sids, val_sids, test_sids = three_way_split(uids, val_size=0.1, test_size=0.2, random_state=SEED)

    with open(REPO_ROOT / "backend/artifacts/scaler.pkl", "rb") as f:
        raw = pickle.load(f)
    mean = np.asarray(raw["mean"], dtype=np.float32)
    scale = np.asarray(raw["scale"], dtype=np.float32)

    cfg = json.load(open(REPO_ROOT / "backend/artifacts/config.json"))
    model = WorldModel(22, cfg["hidden_size"], 6, cfg["num_layers"], cfg["lstm_dropout"])
    model.load_state_dict(torch.load(REPO_ROOT / "backend/artifacts/world_model.pt",
                                      map_location="cpu", weights_only=True))
    model.eval()

    X_val, y_val = load_split(df, val_sids, mean, scale)
    print(f"Val sequences: {X_val.shape}")
    logits_val = get_logits(model, X_val)
    report(y_val, np.argmax(logits_val, axis=1), "Baseline (no bias) VAL")

    best_bias = np.zeros(6)
    best_f1 = f1_score(y_val, np.argmax(logits_val, axis=1), average="macro")
    rng_vals = np.arange(-3.0, 3.01, 0.25)
    for round_i in range(3):
        improved = False
        for c in range(6):
            best_c_val = best_bias[c]
            for v in rng_vals:
                trial = best_bias.copy()
                trial[c] = v
                f1m = f1_score(y_val, np.argmax(logits_val + trial, axis=1), average="macro")
                if f1m > best_f1:
                    best_f1, best_c_val, improved = f1m, v, True
            best_bias[c] = best_c_val
        print(f"Round {round_i + 1}: bias={np.round(best_bias, 2)} val_macro_f1={best_f1:.4f}")
        if not improved:
            break

    print(f"\nFinal bias: {dict(zip(STAGES, best_bias.tolist()))}")
    report(y_val, np.argmax(logits_val + best_bias, axis=1), "\nCalibrated VAL")

    X_test, y_test = load_split(df, test_sids, mean, scale)
    logits_test = get_logits(model, X_test)
    base_pred = np.argmax(logits_test, axis=1)
    cal_pred = np.argmax(logits_test + best_bias, axis=1)
    report(y_test, base_pred, "\nTEST (uncalibrated)")
    report(y_test, cal_pred, "\nTEST (calibrated)")

    print("\nNote: 'BINARY' below reweights stage!=Benign as a proxy metric for")
    print("reporting only. Production alerting uses the separate infiltration_head")
    print("sigmoid (unaffected by this stage-logit bias), not stage argmax.")
    y_bin = (y_test != STAGE2ID["Benign"]).astype(int)
    for name, pred in [("uncalibrated", base_pred), ("calibrated", cal_pred)]:
        pred_bin = (pred != STAGE2ID["Benign"]).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(y_bin, pred_bin, average="binary", zero_division=0)
        fpr = ((pred_bin == 1) & (y_bin == 0)).sum() / max((y_bin == 0).sum(), 1)
        print(f"BINARY (proxy) {name}: F1={f1:.4f} P={p:.4f} R={r:.4f} FPR={fpr:.4f}")


if __name__ == "__main__":
    main()
