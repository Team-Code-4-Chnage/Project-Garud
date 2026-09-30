"""
SIH 2026 — PS26153: AI-Based Network Attack Forecasting from Network Traffic Data
World-Model approach. FIXED for portability: no Colab-only calls, parameterized
paths, deterministic tie-breaks, curated demo sample.

Run as: python pipeline.py           (uses synthetic fallback)
        python pipeline.py --data path/to/real_flows.csv
"""
import argparse
import copy
import json
import os
import pickle
import random
import subprocess
import sys

import matplotlib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

matplotlib.use("Agg")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)


def ensure_packages():
    required = ["torch", "pandas", "numpy", "matplotlib", "shap", "tqdm"]
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])


if __name__ == "__main__" and os.environ.get("SKIP_INSTALL") != "1":
    ensure_packages()

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
os.environ["PYTHONHASHSEED"] = "0"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

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
WINDOW = 6


class StandardScaler:
    def __init__(self, mean=None, scale=None):
        self.mean_ = np.asarray(mean, dtype=np.float32) if mean is not None else None
        self.scale_ = np.asarray(scale, dtype=np.float32) if scale is not None else None
        self.n_features_in_ = len(self.mean_) if self.mean_ is not None else len(FLOW_FEATURES)

    def fit(self, X):
        X = np.asarray(X, dtype=np.float32)
        self.mean_ = np.mean(X, axis=0)
        self.scale_ = np.std(X, axis=0)
        self.scale_[self.scale_ == 0.0] = 1.0
        self.n_features_in_ = X.shape[1]
        return self

    def transform(self, X):
        X = np.asarray(X, dtype=np.float32)
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X):
        return self.fit(X).transform(X)


def train_test_split(unique_ids, test_size=0.2, random_state=42):
    rng = np.random.RandomState(random_state)
    shuffled = rng.permutation(unique_ids)
    split = int(len(shuffled) * (1 - test_size))
    return shuffled[:split], shuffled[split:]


def three_way_split(unique_ids, val_size=0.1, test_size=0.2, random_state=42):
    """
    Split session IDs into train/val/test with ONE deterministic permutation.

    Why this exists: the original pipeline picked its "best" checkpoint by
    evaluating on the same set it then reported final metrics on (test_loader
    was used for both). That's checkpoint selection leakage -- the reported
    number is optimistically biased toward whichever epoch happened to do
    best on the exact data being reported on, not a genuinely unseen set.

    The test boundary here is computed identically to train_test_split()
    above (same RNG, same permutation, same `int(n * (1-test_size))` cut),
    so for a given set of session ids the test split matches what the old
    2-way split produced; only the train/val boundary differs (val is carved
    out of what used to be "train"). Adding sessions to the dataset changes
    the permutation, so test sets are only identical across runs on the same
    data.
    """
    rng = np.random.RandomState(random_state)
    shuffled = rng.permutation(unique_ids)
    n = len(shuffled)
    test_start = int(n * (1 - test_size))
    val_start = int(n * (1 - test_size - val_size))
    return shuffled[:val_start], shuffled[val_start:test_start], shuffled[test_start:]


def compute_metrics(y_true, y_pred):
    y_t = np.asarray(y_true, dtype=int)
    y_p = np.asarray(y_pred, dtype=int)
    tp = int(np.sum((y_t == 1) & (y_p == 1)))
    tn = int(np.sum((y_t == 0) & (y_p == 0)))
    fp = int(np.sum((y_t == 0) & (y_p == 1)))
    fn = int(np.sum((y_t == 1) & (y_p == 0)))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "f1": round(float(f1), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "fpr": round(float(fpr), 4),
    }


class LogisticRegressionBaseline:
    def __init__(self, input_dim=WINDOW * len(FLOW_FEATURES)):
        self.linear = nn.Linear(input_dim, 1).to(DEVICE)

    def fit(self, X, y, epochs=15):
        opt = torch.optim.Adam(self.linear.parameters(), lr=0.01)
        loss_fn = nn.BCEWithLogitsLoss()
        X_t = torch.tensor(X, dtype=torch.float32).to(DEVICE)
        y_t = torch.tensor(y, dtype=torch.float32).to(DEVICE)
        for _ in range(epochs):
            opt.zero_grad()
            out = self.linear(X_t).squeeze(-1)
            loss = loss_fn(out, y_t)
            loss.backward()
            opt.step()

    def predict(self, X):
        with torch.no_grad():
            X_t = torch.tensor(X, dtype=torch.float32).to(DEVICE)
            probs = torch.sigmoid(self.linear(X_t).squeeze(-1)).cpu().numpy()
            return (probs > 0.5).astype(int)


class IsolationTree:
    def __init__(self, max_depth=8):
        self.max_depth = max_depth
        self.split_feat = None
        self.split_val = None
        self.left = None
        self.right = None
        self.size = 0

    def fit(self, X, depth=0):
        self.size = len(X)
        if depth >= self.max_depth or len(X) <= 1:
            return
        n_feats = X.shape[1]
        feat = np.random.randint(0, n_feats)
        feat_min, feat_max = X[:, feat].min(), X[:, feat].max()
        if feat_min == feat_max:
            return
        split = np.random.uniform(feat_min, feat_max)
        left_mask = X[:, feat] < split
        if np.sum(left_mask) == 0 or np.sum(~left_mask) == 0:
            return
        self.split_feat = feat
        self.split_val = split
        self.left = IsolationTree(self.max_depth)
        self.left.fit(X[left_mask], depth + 1)
        self.right = IsolationTree(self.max_depth)
        self.right.fit(X[~left_mask], depth + 1)

    def path_length(self, x, depth=0):
        if self.split_feat is None or depth >= self.max_depth or self.size <= 1:
            return depth
        if x[self.split_feat] < self.split_val:
            return self.left.path_length(x, depth + 1) if self.left else depth + 1
        else:
            return self.right.path_length(x, depth + 1) if self.right else depth + 1


class IsolationForestBaseline:
    def __init__(self, n_trees=50, max_samples=256, contamination=0.3):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.contamination = contamination
        self.trees = []

    def fit(self, X):
        n = len(X)
        sub_size = min(self.max_samples, n)
        self.trees = []
        for _ in range(self.n_trees):
            idx = np.random.choice(n, sub_size, replace=False)
            t = IsolationTree()
            t.fit(X[idx])
            self.trees.append(t)

    def predict(self, X):
        lengths = np.zeros(len(X))
        for t in self.trees:
            lengths += np.array([t.path_length(x) for x in X])
        avg_lengths = lengths / self.n_trees
        thresh = np.percentile(avg_lengths, self.contamination * 100)
        return (avg_lengths < thresh).astype(int)


STAGE_PROFILES_MEAN = {
    "Benign": [50000, 10, 8, 200, 180, 5000, 20, 50000, 30000, 60000, 70000, 1, 5, 1, 0, 2, 0, 1.0, 400, 5, 8192, 0],
    "Reconnaissance": [5000, 50, 2, 60, 20, 15000, 120, 3000, 2000, 4000, 8000, 8, 2, 0, 2, 1, 0, 0.2, 80, 3, 1024, 1],
    "Initial Access": [30000, 15, 10, 150, 120, 8000, 40, 20000, 15000, 25000, 30000, 2, 8, 2, 1, 6, 0, 0.8, 300, 4, 8192, 3],
    "Lateral Movement": [40000, 20, 18, 180, 200, 10000, 35, 30000, 20000, 35000, 40000, 1, 10, 1, 0, 4, 0, 2.5, 350, 6, 16384, 1],
    "C2": [80000, 8, 6, 100, 90, 3000, 15, 90000, 5000, 95000, 95000, 0, 12, 0, 0, 2, 0, 1.1, 200, 2, 8192, 0],
    "Exfiltration": [120000, 5, 30, 200, 1200, 80000, 25, 40000, 30000, 45000, 42000, 0, 15, 2, 0, 3, 0, 0.3, 1100, 2, 65535, 3],
}
STAGE_PROFILES_STD = {
    "Benign":         [30000, 8,  6,  150, 120, 4000, 15, 40000, 25000, 50000, 55000, 0.5, 3,  0.5, 0.2, 1.5, 0.1, 0.3, 200, 3, 4000, 0.2],
    "Reconnaissance": [3000,  30, 1,  40,  15,  8000, 60, 2000,  1500,  3000,  5000,  4,   1,  0.2, 1,   0.5, 0.1, 0.1, 40,  2, 500,  0.5],
    "Initial Access": [10000, 8,  6,  80,  60,  4000, 20, 10000, 8000,  12000, 15000, 1,   4,  1,   0.5, 3,   0.1, 0.3, 150, 2, 4000, 1.5],
    "Lateral Movement":[15000, 10, 8,  80,  80,  5000, 15, 15000, 10000, 18000, 20000, 0.5, 5,  0.5, 0.2, 2,   0.1, 0.5, 150, 3, 8000, 0.5],
    "C2":             [20000, 4,  3,  50,  45,  1500, 8,  10000, 2000,  12000, 12000, 0.2, 5,  0.1, 0.1, 1,   0.1, 0.2, 80,  1, 4000, 0.2],
    "Exfiltration":   [40000, 3,  15, 100, 400, 30000, 10, 20000, 15000, 22000, 20000, 0.2, 6,  1,   0.2, 1.5, 0.1, 0.1, 400, 1, 10000, 1.5],
}


def augment_rare_stages(stages, n_sessions_per_stage=300, session_len=12, start_sid=-1):
    """
    Generate synthetic TRAIN-ONLY sessions for stages that real_flows.csv has
    too few (or zero) real examples of to learn from (Lateral Movement,
    Exfiltration). Sampled from the same calibrated per-stage feature profiles
    used by generate_synthetic_flows()/traffic_simulator.py — real magnitude
    scale, not learned from real Lateral Movement/Exfiltration traffic because
    there isn't enough of it to learn a profile from in the first place.

    Caller MUST only append this to the train split, never test — mixing
    synthetic rows into the held-out set would make evaluation meaningless.
    Session IDs are negative so they can never collide with real (>=0) ones.
    """
    rows = []
    sid = start_sid
    for stage in stages:
        means_base = np.array(STAGE_PROFILES_MEAN[stage], dtype=np.float64)
        stds_base = np.array(STAGE_PROFILES_STD[stage], dtype=np.float64)
        for _ in range(n_sessions_per_stage):
            t0 = pd.Timestamp("2026-01-01") + pd.Timedelta(minutes=abs(sid) * 5)
            for t in range(session_len):
                base = np.maximum(0, np.random.normal(means_base, stds_base))
                row = dict(zip(FLOW_FEATURES, base))
                row["session_id"] = sid
                row["timestamp"] = t0 + pd.Timedelta(seconds=t * 2)
                row["stage_label"] = stage
                row["is_malicious"] = 1
                rows.append(row)
            sid -= 1
    print(f"  Synthetic augmentation: +{len(rows)} rows across "
          f"{len(stages)} stage(s) x {n_sessions_per_stage} sessions "
          f"(train-only, session_len={session_len})", flush=True)
    return pd.DataFrame(rows)


def generate_synthetic_flows(n_sessions=400, session_len=30):
    """
    Generate synthetic flow sessions with REALISTIC CIC-IDS-scale feature magnitudes.

    BUG-01a fix: the original generator used np.random.normal(0, 1) base values,
    producing a scaler with mean≈0 and scale≈1 that is incompatible with real
    traffic (flow_duration in 10k-100k µs, tcp_win_size up to 65535, etc.).

    These profiles match traffic_simulator.py's STAGE_PROFILES so that the
    scaler trained here will correctly normalise both simulated and live-captured flows.
    """
    PROFILES = STAGE_PROFILES_MEAN
    STDS = STAGE_PROFILES_STD
    rows = []
    for sid in range(n_sessions):
        is_attack_session = random.random() < 0.4
        t0 = pd.Timestamp("2026-01-01") + pd.Timedelta(minutes=sid * 5)
        if is_attack_session:
            stage_sequence = (["Benign"] * random.randint(2, 5) +
                               ["Reconnaissance"] * random.randint(2, 4) +
                               ["Initial Access"] * random.randint(1, 3) +
                               ["Lateral Movement"] * random.randint(1, 3) +
                               ["C2"] * random.randint(1, 3) +
                               ["Exfiltration"] * random.randint(1, 3))
        else:
            stage_sequence = ["Benign"] * session_len
        stage_sequence = (stage_sequence * (session_len // max(1, len(stage_sequence)) + 1))[:session_len]
        for t, stage in enumerate(stage_sequence):
            means = np.array(PROFILES[stage], dtype=np.float64)
            stds  = np.array(STDS[stage],    dtype=np.float64)
            base  = np.maximum(0, np.random.normal(means, stds))
            row = dict(zip(FLOW_FEATURES, base))
            row["session_id"] = sid
            row["timestamp"] = t0 + pd.Timedelta(seconds=t * 2)
            row["stage_label"] = stage
            row["is_malicious"] = int(stage != "Benign")
            rows.append(row)
    return pd.DataFrame(rows)


STAGE_TARGET = "current"


def build_sequences(df, window=WINDOW):
    # "current": stage label of the window's last flow -- the flow that
    # backend/app/ingestion.py actually annotates with predicted_stage when it
    # runs the model on the window ending at a newly-arrived flow.
    # "next": label of the unseen flow after the window (the original setup).
    X_seq, y_next_state, y_malicious, y_stage = [], [], [], []
    stage_offset = window - 1 if STAGE_TARGET == "current" else window
    for _sid, g in df.groupby("session_id"):
        feats = g[FLOW_FEATURES].values
        mal = g["is_malicious"].values
        stage = g["stage_id"].values
        for i in range(len(g) - window):
            X_seq.append(feats[i:i + window])
            y_next_state.append(feats[i + window])
            y_malicious.append(mal[i + window])
            y_stage.append(stage[i + stage_offset])
    return (np.array(X_seq, dtype=np.float32), np.array(y_next_state, dtype=np.float32),
            np.array(y_malicious, dtype=np.float32), np.array(y_stage, dtype=np.int64))


class FlowSeqDataset(Dataset):
    def __init__(self, X, y_next, y_mal, y_stage):
        self.X, self.y_next, self.y_mal, self.y_stage = X, y_next, y_mal, y_stage
    def __len__(self): return len(self.X)
    def __getitem__(self, idx):
        return (torch.tensor(self.X[idx]), torch.tensor(self.y_next[idx]),
                torch.tensor(self.y_mal[idx]), torch.tensor(self.y_stage[idx]))


class FocalLoss(nn.Module):
    """
    Focal loss (Lin et al., 2017) for the MITRE stage head, generalizing
    class-weighted cross-entropy: FL(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t).

    Why: pure inverse-frequency class weighting (the previous approach) blanket-
    boosts the gradient for rare classes regardless of whether the model is
    already confident or not, which is what caused Initial Access to over-fire
    (13.6% precision, drowning out Benign with false positives -- see
    docs/model_card.md). Focal loss's (1-p_t)^gamma term instead down-weights
    already-easy/confident examples and concentrates gradient on genuinely hard
    examples, which should reduce the "confidently wrong" false-positive
    pattern rather than the "not learned at all" pattern. gamma=0 reduces
    exactly to the previous weighted CrossEntropyLoss, so this is a strict
    generalization, not a regression risk.
    """
    def __init__(self, alpha: torch.Tensor, gamma: float = 2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        log_probs = torch.log_softmax(logits, dim=1)
        log_pt = log_probs.gather(1, targets.unsqueeze(1)).squeeze(1)
        pt = log_pt.exp()
        alpha_t = self.alpha[targets]
        loss = -alpha_t * (1.0 - pt).pow(self.gamma) * log_pt
        return loss.sum() / alpha_t.sum()


class WorldModel(nn.Module):
    def __init__(self, n_features, hidden=128, n_stages=len(STAGES), num_layers=2, dropout=0.2):
        super().__init__()
        self.lstm = nn.LSTM(
            n_features, hidden, num_layers=num_layers,
            batch_first=True, dropout=dropout if num_layers > 1 else 0.0,
        )
        self.next_state_head = nn.Linear(hidden, n_features)
        self.infiltration_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 32), nn.ReLU(),
            nn.Linear(32, 1),
        )
        self.stage_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(),
            nn.Linear(64, n_stages),
        )

    def forward(self, x):
        out, (h_n, _) = self.lstm(x)
        h = h_n[-1]
        next_state = self.next_state_head(h)
        infiltration_logit = self.infiltration_head(h).squeeze(-1)
        stage_logits = self.stage_head(h)
        return next_state, infiltration_logit, stage_logits





def forward_simulate(model, initial_window, k_steps=5, noise_std=0.0, device=None):
    device = device or DEVICE
    model.eval()
    window = torch.tensor(initial_window, dtype=torch.float32).unsqueeze(0).to(device)
    if noise_std > 0:
        window = window + torch.randn_like(window) * noise_std
    timeline = []
    with torch.no_grad():
        for step in range(k_steps):
            next_state, inf_logit, stage_logits = model(window)
            prob = torch.sigmoid(inf_logit).item()
            stage = STAGES[torch.argmax(stage_logits, dim=1).item()]
            timeline.append({"step": step + 1, "infiltration_prob": prob, "predicted_stage": stage})
            window = torch.cat([window[:, 1:, :], next_state.unsqueeze(1)], dim=1)
    return timeline


def ema_smooth(probs, alpha=0.4):
    smoothed = [probs[0]]
    for p in probs[1:]:
        smoothed.append(alpha * p + (1 - alpha) * smoothed[-1])
    return smoothed


def monte_carlo_rollout(model, initial_window, k_steps=5, n_samples=20, noise_std=0.05, device=None):
    all_probs = np.zeros((n_samples, k_steps))
    all_stages = [[None] * k_steps for _ in range(n_samples)]
    for i in range(n_samples):
        run = forward_simulate(model, initial_window, k_steps=k_steps, noise_std=noise_std, device=device)
        for step in run:
            all_probs[i, step["step"] - 1] = step["infiltration_prob"]
            all_stages[i][step["step"] - 1] = step["predicted_stage"]
    mean_probs = all_probs.mean(axis=0)
    std_probs = all_probs.std(axis=0)
    mode_stages = []
    for col in zip(*all_stages):
        counts = {s: col.count(s) for s in set(col)}
        best = sorted(counts.items(), key=lambda kv: (-kv[1], STAGES.index(kv[0])))[0][0]
        mode_stages.append(best)
    return mean_probs, std_probs, mode_stages


def pick_demo_session(df, ym_test_idx_map=None):
    """
    FIX 2: pick the session with the richest stage progression (preferring Exfiltration).
    Falls back gracefully if Exfiltration is not in train split.
    """
    best_sid, best_score = None, -1
    for sid, g in df.groupby("session_id"):
        stages_present = set(g["stage_label"])
        score = len(stages_present) + (10 if "Exfiltration" in stages_present else 0)
        if score > best_score:
            best_score, best_sid = score, sid
    if best_sid is None and len(df) > 0:
        best_sid = df["session_id"].iloc[0]
    return best_sid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None, help="path to real flow CSV (session_id, timestamp, stage_label, is_malicious + FLOW_FEATURES columns)")
    ap.add_argument("--out", default="./outputs", help="output directory (FIX 3: no hardcoded /content path)")
    ap.add_argument("--epochs", type=int, default=20, help="Number of training epochs")
    ap.add_argument("--batch-size", type=int, default=128, help="Batch size for training and testing")
    ap.add_argument("--hidden-size", type=int, default=256, help="LSTM hidden state dimension")
    ap.add_argument("--num-layers", type=int, default=2, help="Number of stacked LSTM layers")
    ap.add_argument("--dropout", type=float, default=0.25, help="Dropout probability")
    ap.add_argument("--lr", type=float, default=1e-3, help="Initial learning rate")
    ap.add_argument("--weight-decay", type=float, default=1e-4, help="AdamW weight decay")
    ap.add_argument("--augment-stages", default="Exfiltration",
                     help="Comma-separated stage names to oversample with synthetic train-only "
                          "sessions (real_flows.csv has ~2 real Exfiltration examples — not "
                          "enough to learn from; Lateral Movement now has real CIC-IDS2018 data "
                          "instead, see data/augment_lateral_movement.py). Empty string disables.")
    ap.add_argument("--augment-sessions-per-stage", type=int, default=300,
                     help="Synthetic sessions to generate per augmented stage")
    ap.add_argument("--class-weight-max", type=float, default=15.0,
                     help="Upper clip for inverse-frequency class weights (was 50.0 — that "
                          "aggressive a weight was overshooting and collapsing Initial Access "
                          "precision to ~6%%)")
    ap.add_argument("--stage-loss", choices=["weighted_ce", "focal"], default="focal",
                     help="Loss for the MITRE stage head. 'focal' (default) generalizes "
                          "weighted_ce and targets the false-positive over-firing pattern "
                          "specifically (see FocalLoss docstring); 'weighted_ce' reproduces "
                          "the previous behavior exactly for comparison.")
    ap.add_argument("--focal-gamma", type=float, default=2.0,
                     help="Focusing parameter for --stage-loss focal. 0 reduces to weighted_ce.")
    ap.add_argument("--stage-target", choices=["current", "next"], default="current",
                     help="Which flow's stage the stage head learns: 'current' (last flow in the "
                          "window, what production annotates) or 'next' (the unseen following flow, "
                          "the original setup).")
    args = ap.parse_args()

    global STAGE_TARGET
    STAGE_TARGET = args.stage_target

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    if args.data and os.path.exists(args.data):
        print(f"Loading real dataset from {args.data}", flush=True)
        df = pd.read_csv(args.data, parse_dates=["timestamp"])
        missing_features = [c for c in FLOW_FEATURES if c not in df.columns]
        missing_meta = [c for c in ["session_id", "timestamp", "stage_label", "is_malicious"] if c not in df.columns]
        if missing_features or missing_meta:
            raise ValueError(f"Missing feature columns: {missing_features or 'none'}; "
                              f"missing meta columns: {missing_meta or 'none'}")
    else:
        print("No --data provided or file not found — generating synthetic flow sessions.", flush=True)
        df = generate_synthetic_flows()

    data_source = args.data if (args.data and os.path.exists(args.data)) else "synthetic"
    print(f"Dataset shape: {df.shape}", flush=True)

    unique_sids = df["session_id"].unique()
    train_sids, val_sids, test_sids = three_way_split(
        unique_sids, val_size=0.1, test_size=0.2, random_state=SEED
    )
    train_mask = df["session_id"].isin(train_sids)
    val_mask = df["session_id"].isin(val_sids)
    test_mask = df["session_id"].isin(test_sids)
    train_df = df[train_mask].copy()
    val_df = df[val_mask].copy()
    test_df = df[test_mask].copy()

    augment_stages = [s.strip() for s in args.augment_stages.split(",") if s.strip()]
    if augment_stages:
        synth_df = augment_rare_stages(augment_stages, n_sessions_per_stage=args.augment_sessions_per_stage)
        train_df = pd.concat([train_df, synth_df], ignore_index=True)
        print(f"Train shape after augmentation: {train_df.shape}", flush=True)

    scaler = StandardScaler()
    train_df[FLOW_FEATURES] = scaler.fit_transform(train_df[FLOW_FEATURES])
    val_df[FLOW_FEATURES]   = scaler.transform(val_df[FLOW_FEATURES])
    test_df[FLOW_FEATURES]  = scaler.transform(test_df[FLOW_FEATURES])

    train_df["stage_id"] = train_df["stage_label"].map(STAGE2ID)
    val_df["stage_id"]   = val_df["stage_label"].map(STAGE2ID)
    test_df["stage_id"]  = test_df["stage_label"].map(STAGE2ID)

    train_sorted = train_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    val_sorted   = val_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    test_sorted  = test_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)

    X_train, yn_train, ym_train, ys_train = build_sequences(train_sorted)
    X_val,   yn_val,   ym_val,   ys_val   = build_sequences(val_sorted)
    X_test,  yn_test,  ym_test,  ys_test  = build_sequences(test_sorted)
    print(f"Train sequences: {X_train.shape}  Val sequences: {X_val.shape}  Test sequences: {X_test.shape}", flush=True)

    X_train_flat = X_train.reshape(X_train.shape[0], -1)
    X_test_flat = X_test.reshape(X_test.shape[0], -1)

    lr_baseline = LogisticRegressionBaseline(input_dim=X_train_flat.shape[1])
    lr_baseline.fit(X_train_flat, ym_train)
    lr_pred = lr_baseline.predict(X_test_flat)
    lr_metrics = compute_metrics(ym_test, lr_pred)
    print("LOGISTIC REGRESSION BASELINE:", lr_metrics, flush=True)

    iso_forest = IsolationForestBaseline(contamination=0.3)
    iso_forest.fit(X_train_flat)
    iso_pred = iso_forest.predict(X_test_flat)
    iso_metrics = compute_metrics(ym_test, iso_pred)
    print("ISOLATION FOREST BASELINE:", iso_metrics, flush=True)

    train_loader = DataLoader(FlowSeqDataset(X_train, yn_train, ym_train, ys_train), batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(FlowSeqDataset(X_val, yn_val, ym_val, ys_val), batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(FlowSeqDataset(X_test, yn_test, ym_test, ys_test), batch_size=args.batch_size, shuffle=False)

    stage_counts = np.bincount(ys_train, minlength=len(STAGES))
    total_samples = len(ys_train)
    raw_weights = total_samples / (len(STAGES) * np.maximum(stage_counts, 1).astype(np.float32))
    class_weights = np.clip(raw_weights, 0.2, args.class_weight_max)
    stage_weight_t = torch.tensor(class_weights, dtype=torch.float32).to(DEVICE)
    if args.stage_loss == "focal":
        ce_loss = FocalLoss(alpha=stage_weight_t, gamma=args.focal_gamma)
    else:
        ce_loss = nn.CrossEntropyLoss(weight=stage_weight_t)

    num_pos = np.sum(ym_train == 1)
    num_neg = np.sum(ym_train == 0)
    pos_weight_val = float(num_neg) / max(float(num_pos), 1.0)
    pos_weight = torch.tensor([pos_weight_val], dtype=torch.float32).to(DEVICE)
    bce_loss = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    mse_loss = nn.MSELoss()

    print(f"Class weighting enabled: stage_weights={np.round(class_weights, 2)}, pos_weight={pos_weight_val:.2f}", flush=True)
    print(f"Stage loss: {args.stage_loss}" + (f" (gamma={args.focal_gamma})" if args.stage_loss == "focal" else ""), flush=True)

    model = WorldModel(
        n_features=len(FLOW_FEATURES),
        hidden=args.hidden_size,
        num_layers=args.num_layers,
        dropout=args.dropout
    ).to(DEVICE)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs, eta_min=1e-5)

    print(f"World Model architecture: {args.num_layers}-layer LSTM, hidden={args.hidden_size}, dropout={args.dropout}", flush=True)
    print(f"Training for {args.epochs} epochs with AdamW + CosineAnnealingLR...", flush=True)

    best_val_f1 = -1.0
    best_model_state = None

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0.0
        for xb, yn_b, ym_b, ys_b in train_loader:
            xb, yn_b, ym_b, ys_b = xb.to(DEVICE), yn_b.to(DEVICE), ym_b.to(DEVICE), ys_b.to(DEVICE)
            opt.zero_grad()
            pred_next, inf_logit, stage_logits = model(xb)
            loss = mse_loss(pred_next, yn_b) + bce_loss(inf_logit, ym_b) + ce_loss(stage_logits, ys_b)
            loss.backward()
            opt.step()
            total_loss += loss.item() * xb.size(0)

        epoch_loss = total_loss / len(train_loader.dataset)

        model.eval()
        val_preds, val_true = [], []
        with torch.no_grad():
            for xb, _yn_b, ym_b, _ys_b in val_loader:
                _, inf_logit, _ = model(xb.to(DEVICE))
                probs = torch.sigmoid(inf_logit).cpu().numpy()
                val_preds.extend((probs > 0.5).astype(int))
                val_true.extend(ym_b.numpy().astype(int))

        val_metrics = compute_metrics(np.array(val_true), np.array(val_preds))
        val_f1 = val_metrics["f1"]
        scheduler.step()
        curr_lr = opt.param_groups[0]["lr"]

        print(
            f"Epoch {epoch+1:2d}/{args.epochs} — loss: {epoch_loss:.4f} | "
            f"val_f1: {val_f1:.4f}  val_prec: {val_metrics['precision']:.4f}  "
            f"val_rec: {val_metrics['recall']:.4f}  val_fpr: {val_metrics['fpr']:.4f} "
            f"(lr: {curr_lr:.6f})",
            flush=True,
        )

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_model_state = copy.deepcopy(model.state_dict())
            print(f"  [CHECKPOINT] New best validation F1: {val_f1:.4f} — saved weights.", flush=True)

    if best_model_state is not None:
        print(f"\nLoading best checkpoint with validation F1: {best_val_f1:.4f}", flush=True)
        model.load_state_dict(best_model_state)

    model.eval()
    all_preds, all_true = [], []
    with torch.no_grad():
        for xb, _yn_b, ym_b, _ys_b in test_loader:
            _, inf_logit, _ = model(xb.to(DEVICE))
            probs = torch.sigmoid(inf_logit).cpu().numpy()
            all_preds.extend((probs > 0.5).astype(int))
            all_true.extend(ym_b.numpy().astype(int))
    world_model_metrics = compute_metrics(np.array(all_true), np.array(all_preds))
    print("\nFINAL WORLD MODEL TEST METRICS:", world_model_metrics, flush=True)

    comparison = pd.DataFrame(
        [lr_metrics, iso_metrics, world_model_metrics],
        index=[
            "Logistic Regression (baseline)",
            "Isolation Forest (baseline)",
            "LSTM World Model (proposed)",
        ]
    )
    comparison.to_csv(f"{out_dir}/benchmark_comparison.csv")
    print("\n" + "=" * 60)
    print("BENCHMARK COMPARISON TABLE:")
    print(comparison)
    print("=" * 60, flush=True)

    demo_sid = pick_demo_session(train_sorted)
    demo_session = train_sorted[train_sorted["session_id"] == demo_sid]
    demo_feats = demo_session[FLOW_FEATURES].values
    if len(demo_feats) >= WINDOW:
        initial_window = demo_feats[:WINDOW]
        raw_timeline = forward_simulate(model, initial_window, k_steps=6)
        raw_probs = [s["infiltration_prob"] for s in raw_timeline]
        ema_probs = ema_smooth(raw_probs)
        mc_mean, mc_std, mc_stages = monte_carlo_rollout(model, initial_window, k_steps=6, n_samples=20)
        print(f"\nDemo session {demo_sid} (stages present: {sorted(set(demo_session['stage_label']))})")
        for i in range(6):
            print(f"step {i+1}: raw={raw_probs[i]:.3f} ema={ema_probs[i]:.3f} "
                  f"mc_mean={mc_mean[i]:.3f}+-{mc_std[i]:.3f} stage={mc_stages[i]}")

    torch.save(model.state_dict(), f"{out_dir}/world_model.pt")
    with open(f"{out_dir}/scaler.pkl", "wb") as f:
        pickle.dump({"mean": scaler.mean_, "scale": scaler.scale_}, f)

    import subprocess
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        git_commit = "unknown"

    with open(f"{out_dir}/config.json", "w") as f:
        json.dump({
            "window": WINDOW,
            "features": FLOW_FEATURES,
            "stages": STAGES,
            "hidden_size": args.hidden_size,
            "num_layers": args.num_layers,
            "lstm_dropout": args.dropout,
            "provenance": {
                "trained_on": data_source,
                "train_sessions": int(len(train_sids)),
                "val_sessions": int(len(val_sids)),
                "test_sessions": int(len(test_sids)),
                "train_rows": int(len(train_df)),
                "val_rows": int(len(val_df)),
                "test_rows": int(len(test_df)),
                "git_commit": git_commit,
                "leakage_fix": "session-level 3-way train/val/test split, scaler fit on "
                               "train only, checkpoint selection uses val (never test)",
                "synthetic_augmentation": {
                    "stages": augment_stages,
                    "sessions_per_stage": args.augment_sessions_per_stage if augment_stages else 0,
                    "note": "train-only synthetic oversampling from calibrated per-stage "
                            "feature profiles; test set is 100% real flows (CIC-IDS2017 "
                            "and, if present, CIC-IDS2018), untouched by synthetic augmentation",
                },
                "class_weight_max": args.class_weight_max,
                "stage_loss": args.stage_loss,
                "focal_gamma": args.focal_gamma if args.stage_loss == "focal" else None,
                "stage_target": args.stage_target,
                "best_val_f1": best_val_f1,
                "optimization": "AdamW + CosineAnnealingLR + ClassWeighting",
            }
        }, f, indent=2)

    print("DONE — all artifacts saved to", out_dir, flush=True)


if __name__ == "__main__":
    main()
