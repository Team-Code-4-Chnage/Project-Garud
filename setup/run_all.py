#!/usr/bin/env python3
"""
Project Garud -- ONE-FILE Campaign Dataset Generator + Model Retrainer
SIH 2026 PS:26153 (NTRO) | Team: Code 4 Change

ZERO SETUP REQUIRED. Just run:
    python setup/run_all.py

What it does:
  1. Generates realistic multi-stage attack campaign data
     (simulates full kill chains: Recon -> Initial Access -> Lateral Movement -> C2 -> Exfil)
  2. Combines it with existing CIC-IDS base data (if available)
  3. Retrains the WorldModel (fine-tune or from-scratch)
  4. Saves updated model artifacts to backend/artifacts/

No VirtualBox. No Wireshark. No VMs. No manual steps. One file, one command.
"""
import argparse
import copy
import json
import os
import pickle
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# =====================================================================
# AUTO-INSTALL DEPENDENCIES
# =====================================================================
def ensure_deps():
    """Install missing packages silently."""
    required = {
        "torch": "torch --index-url https://download.pytorch.org/whl/cpu",
        "pandas": "pandas",
        "numpy": "numpy",
        "matplotlib": "matplotlib",
        "sklearn": "scikit-learn",
        "tqdm": "tqdm",
    }
    for mod, pip_name in required.items():
        try:
            __import__(mod)
        except ImportError:
            print(f"  Installing {mod}...")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q"] + pip_name.split(),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

ensure_deps()

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

# =====================================================================
# CONSTANTS (must match pipeline_fixed.py exactly)
# =====================================================================
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "backend" / "artifacts"

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

# CIC-IDS-calibrated feature profiles per MITRE stage
PROFILES_MEAN = {
    "Benign":          [50000, 10, 8, 200, 180, 5000, 20, 50000, 30000, 60000, 70000, 1, 5, 1, 0, 2, 0, 1.0, 400, 5, 8192, 0],
    "Reconnaissance":  [5000, 50, 2, 60, 20, 15000, 120, 3000, 2000, 4000, 8000, 8, 2, 0, 2, 1, 0, 0.2, 80, 3, 1024, 1],
    "Initial Access":  [30000, 15, 10, 150, 120, 8000, 40, 20000, 15000, 25000, 30000, 2, 8, 2, 1, 6, 0, 0.8, 300, 4, 8192, 3],
    "Lateral Movement":[40000, 20, 18, 180, 200, 10000, 35, 30000, 20000, 35000, 40000, 1, 10, 1, 0, 4, 0, 2.5, 350, 6, 16384, 1],
    "C2":              [80000, 8, 6, 100, 90, 3000, 15, 90000, 5000, 95000, 95000, 0, 12, 0, 0, 2, 0, 1.1, 200, 2, 8192, 0],
    "Exfiltration":    [120000, 5, 30, 200, 1200, 80000, 25, 40000, 30000, 45000, 42000, 0, 15, 2, 0, 3, 0, 0.3, 1100, 2, 65535, 3],
}
PROFILES_STD = {
    "Benign":          [30000, 8, 6, 150, 120, 4000, 15, 40000, 25000, 50000, 55000, 0.5, 3, 0.5, 0.2, 1.5, 0.1, 0.3, 200, 3, 4000, 0.2],
    "Reconnaissance":  [3000, 30, 1, 40, 15, 8000, 60, 2000, 1500, 3000, 5000, 4, 1, 0.2, 1, 0.5, 0.1, 0.1, 40, 2, 500, 0.5],
    "Initial Access":  [10000, 8, 6, 80, 60, 4000, 20, 10000, 8000, 12000, 15000, 1, 4, 1, 0.5, 3, 0.1, 0.3, 150, 2, 4000, 1.5],
    "Lateral Movement":[15000, 10, 8, 80, 80, 5000, 15, 15000, 10000, 18000, 20000, 0.5, 5, 0.5, 0.2, 2, 0.1, 0.5, 150, 3, 8000, 0.5],
    "C2":              [20000, 4, 3, 50, 45, 1500, 8, 10000, 2000, 12000, 12000, 0.2, 5, 0.1, 0.1, 1, 0.1, 0.2, 80, 1, 4000, 0.2],
    "Exfiltration":    [40000, 3, 15, 100, 400, 30000, 10, 20000, 15000, 22000, 20000, 0.2, 6, 1, 0.2, 1.5, 0.1, 0.1, 400, 1, 10000, 1.5],
}

# =====================================================================
# CAMPAIGN TEMPLATES -- Realistic multi-stage attack kill chains
# =====================================================================
# Each template defines a realistic attack scenario with stage durations
# (how many flows in each stage) and transition noise

CAMPAIGN_TEMPLATES = [
    {
        "name": "APT Full Kill Chain",
        "description": "Advanced persistent threat: full recon through exfiltration",
        "stages": [
            ("Benign", (3, 8)),          # Normal traffic before attack
            ("Reconnaissance", (4, 10)), # Nmap scans, DNS enum, service probing
            ("Initial Access", (2, 5)),  # Brute force SSH, exploit CVE
            ("Lateral Movement", (3, 7)),# Pivot via SMB, pass-the-hash
            ("C2", (4, 12)),             # Beacon callbacks, encrypted channel
            ("Exfiltration", (2, 6)),    # Data staging, DNS tunneling
        ],
    },
    {
        "name": "Smash-and-Grab",
        "description": "Fast opportunistic attack: minimal recon, immediate exploit",
        "stages": [
            ("Benign", (1, 3)),
            ("Reconnaissance", (1, 3)),
            ("Initial Access", (2, 4)),
            ("Exfiltration", (3, 8)),
        ],
    },
    {
        "name": "Slow Recon + Lateral Spread",
        "description": "Extended recon phase, heavy lateral movement",
        "stages": [
            ("Benign", (5, 12)),
            ("Reconnaissance", (8, 20)),
            ("Initial Access", (1, 3)),
            ("Lateral Movement", (6, 15)),
            ("C2", (2, 5)),
        ],
    },
    {
        "name": "C2 Persistent Backdoor",
        "description": "Quick initial access then long C2 beaconing",
        "stages": [
            ("Benign", (2, 5)),
            ("Reconnaissance", (2, 4)),
            ("Initial Access", (1, 3)),
            ("C2", (10, 30)),
            ("Exfiltration", (1, 3)),
        ],
    },
    {
        "name": "Insider Lateral Movement",
        "description": "No recon needed, direct lateral movement from compromised insider",
        "stages": [
            ("Benign", (3, 6)),
            ("Lateral Movement", (5, 12)),
            ("C2", (3, 8)),
            ("Exfiltration", (2, 5)),
        ],
    },
    {
        "name": "Reconnaissance Only",
        "description": "Recon probe that doesn't progress further (detected early)",
        "stages": [
            ("Benign", (5, 10)),
            ("Reconnaissance", (6, 15)),
            ("Benign", (3, 6)),  # Attacker backs off
        ],
    },
    {
        "name": "Ransomware Kill Chain",
        "description": "Recon, access, lateral spread, then mass exfiltration",
        "stages": [
            ("Benign", (2, 4)),
            ("Reconnaissance", (3, 6)),
            ("Initial Access", (2, 4)),
            ("Lateral Movement", (4, 10)),
            ("Exfiltration", (5, 15)),  # Mass file encryption + exfil
        ],
    },
    {
        "name": "Watering Hole + C2",
        "description": "Compromised website leads to C2 implant",
        "stages": [
            ("Benign", (4, 8)),
            ("Initial Access", (1, 2)),  # Drive-by download
            ("C2", (8, 20)),
            ("Lateral Movement", (2, 5)),
            ("Exfiltration", (1, 3)),
        ],
    },
]


class RealFlowSampler:
    """Samples real measured flow vectors from real_flows.csv per MITRE stage."""

    def __init__(self, csv_path: Path):
        self.pools: dict[str, list[dict]] = {s: [] for s in STAGES}
        self.loaded = False
        if csv_path.exists():
            print(f"    Loading real flow pool from {csv_path.name}...")
            df = pd.read_csv(csv_path, usecols=FLOW_FEATURES + ["stage_label"], low_memory=False)
            for stage in STAGES:
                stage_df = df[df["stage_label"] == stage]
                if len(stage_df) > 0:
                    self.pools[stage] = stage_df[FLOW_FEATURES].to_dict(orient="records")
                    print(f"      Pool [{stage:16s}]: {len(self.pools[stage]):6d} flows")
            self.loaded = any(len(v) > 0 for v in self.pools.values())

    def sample(self, stage: str, noise_factor: float = 1.0) -> dict:
        if self.pools.get(stage):
            base_flow = dict(random.choice(self.pools[stage]))
            discrete = {
                "syn_flag_cnt", "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt",
                "psh_flag_cnt", "urg_flag_cnt", "retransmit_cnt",
            }
            for k, v in base_flow.items():
                if k not in discrete and v > 0:
                    base_flow[k] = float(max(0.0, v * (1.0 + random.uniform(-0.05, 0.05) * noise_factor)))
                else:
                    base_flow[k] = float(v)
            return base_flow

        # Fallback to calibrated Gaussian profile if stage has no real flows
        means = np.array(PROFILES_MEAN[stage], dtype=np.float64)
        stds = np.array(PROFILES_STD[stage], dtype=np.float64) * noise_factor
        values = np.maximum(0, np.random.normal(means, stds))
        return dict(zip(FLOW_FEATURES, values))


flow_sampler: RealFlowSampler | None = None


def generate_flow(stage, noise_factor=1.0):
    """Generate a single flow vector (from real flow pool when available, else calibrated profiles)."""
    global flow_sampler
    if flow_sampler and flow_sampler.loaded:
        return flow_sampler.sample(stage, noise_factor=noise_factor)
    means = np.array(PROFILES_MEAN[stage], dtype=np.float64)
    stds = np.array(PROFILES_STD[stage], dtype=np.float64) * noise_factor
    values = np.maximum(0, np.random.normal(means, stds))
    return dict(zip(FLOW_FEATURES, values))


def generate_campaign_session(template, session_id, base_time):
    """Generate a complete attack campaign session from a template."""
    rows = []
    flow_idx = 0
    for stage_name, (min_flows, max_flows) in template["stages"]:
        n_flows = random.randint(min_flows, max_flows)
        for _ in range(n_flows):
            noise = 1.0 + random.uniform(-0.1, 0.1)
            flow = generate_flow(stage_name, noise_factor=noise)
            flow["session_id"] = session_id
            flow["timestamp"] = base_time + pd.Timedelta(seconds=flow_idx * 2 + random.uniform(0, 1))
            flow["stage_label"] = stage_name
            flow["is_malicious"] = int(stage_name != "Benign")
            rows.append(flow)
            flow_idx += 1
    return rows


def generate_benign_session(session_id, base_time, n_flows=None):
    """Generate a pure benign traffic session."""
    if n_flows is None:
        n_flows = random.randint(15, 40)
    rows = []
    for i in range(n_flows):
        flow = generate_flow("Benign", noise_factor=1.0 + random.uniform(-0.05, 0.05))
        flow["session_id"] = session_id
        flow["timestamp"] = base_time + pd.Timedelta(seconds=i * 2 + random.uniform(0, 0.5))
        flow["stage_label"] = "Benign"
        flow["is_malicious"] = 0
        rows.append(flow)
    return rows


def generate_campaign_dataset(n_attack_sessions=80, n_benign_sessions=120):
    """
    Generate a complete campaign dataset with realistic attack and benign sessions.
    Samples from real_flows.csv whenever available.
    """
    global flow_sampler
    if flow_sampler is None:
        base_path = ROOT / "real_flows.csv"
        flow_sampler = RealFlowSampler(base_path)

    print("\n  Generating campaign dataset...")
    print(f"    Attack sessions:  {n_attack_sessions}")
    print(f"    Benign sessions:  {n_benign_sessions}")
    print(f"    Campaign templates: {len(CAMPAIGN_TEMPLATES)}")
    print(f"    Flow sampling:    {'Real flow pool (real_flows.csv)' if flow_sampler.loaded else 'Calibrated profiles'}")

    all_rows = []
    sid = 0
    base = pd.Timestamp("2026-01-01")

    # Generate attack campaign sessions
    for i in range(n_attack_sessions):
        template = random.choice(CAMPAIGN_TEMPLATES)
        t0 = base + pd.Timedelta(minutes=sid * 5)
        rows = generate_campaign_session(template, session_id=sid, base_time=t0)
        all_rows.extend(rows)
        sid += 1

    # Generate benign sessions
    for i in range(n_benign_sessions):
        t0 = base + pd.Timedelta(minutes=sid * 5)
        rows = generate_benign_session(session_id=sid, base_time=t0)
        all_rows.extend(rows)
        sid += 1

    df = pd.DataFrame(all_rows)

    # Summary
    total = len(df)
    mal = df["is_malicious"].sum()
    print(f"\n    Total flows:      {total}")
    print(f"    Malicious:        {mal} ({100*mal/total:.1f}%)")
    print(f"    Benign:           {total - mal} ({100*(total-mal)/total:.1f}%)")
    print(f"    Sessions:         {df['session_id'].nunique()}")
    print(f"    Stage distribution:")
    for stage in STAGES:
        count = (df["stage_label"] == stage).sum()
        if count > 0:
            print(f"      {stage:20s}: {count:5d} flows")

    return df


# =====================================================================
# MODEL ARCHITECTURE (must match pipeline_fixed.py exactly)
# =====================================================================

class StandardScaler:
    def __init__(self, mean=None, scale=None):
        self.mean_ = np.asarray(mean, dtype=np.float32) if mean is not None else None
        self.scale_ = np.asarray(scale, dtype=np.float32) if scale is not None else None

    def fit(self, X):
        X = np.asarray(X, dtype=np.float32)
        self.mean_ = np.mean(X, axis=0)
        self.scale_ = np.std(X, axis=0)
        self.scale_[self.scale_ == 0.0] = 1.0
        return self

    def transform(self, X):
        return (np.asarray(X, dtype=np.float32) - self.mean_) / self.scale_

    def fit_transform(self, X):
        return self.fit(X).transform(X)


class WorldModel(nn.Module):
    def __init__(self, n_features, hidden=128, n_stages=len(STAGES), num_layers=2, dropout=0.2):
        super().__init__()
        self.lstm = nn.LSTM(
            n_features, hidden, num_layers=num_layers,
            batch_first=True, dropout=dropout if num_layers > 1 else 0.0,
        )
        self.next_state_head = nn.Linear(hidden, n_features)
        self.infiltration_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(64, 32), nn.ReLU(), nn.Linear(32, 1),
        )
        self.stage_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(), nn.Linear(64, n_stages),
        )

    def forward(self, x):
        out, (h_n, _) = self.lstm(x)
        h = h_n[-1]
        return self.next_state_head(h), self.infiltration_head(h).squeeze(-1), self.stage_head(h)


class FocalLoss(nn.Module):
    def __init__(self, alpha, gamma=2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, logits, targets):
        log_probs = torch.log_softmax(logits, dim=1)
        log_pt = log_probs.gather(1, targets.unsqueeze(1)).squeeze(1)
        pt = log_pt.exp()
        alpha_t = self.alpha[targets]
        loss = -alpha_t * (1.0 - pt).pow(self.gamma) * log_pt
        return loss.sum() / alpha_t.sum()


class FlowSeqDataset(Dataset):
    def __init__(self, X, y_next, y_mal, y_stage):
        self.X, self.y_next, self.y_mal, self.y_stage = X, y_next, y_mal, y_stage
    def __len__(self): return len(self.X)
    def __getitem__(self, idx):
        return (torch.tensor(self.X[idx]), torch.tensor(self.y_next[idx]),
                torch.tensor(self.y_mal[idx]), torch.tensor(self.y_stage[idx]))


# =====================================================================
# DATA PIPELINE
# =====================================================================

def three_way_split(ids, val_size=0.1, test_size=0.2, random_state=42):
    rng = np.random.RandomState(random_state)
    shuffled = rng.permutation(ids)
    n = len(shuffled)
    test_start = int(n * (1 - test_size))
    val_start = int(n * (1 - test_size - val_size))
    return shuffled[:val_start], shuffled[val_start:test_start], shuffled[test_start:]


def build_sequences(df, window=WINDOW):
    X_seq, y_next, y_mal, y_stage = [], [], [], []
    for _, g in df.groupby("session_id"):
        feats = g[FLOW_FEATURES].values
        mal = g["is_malicious"].values
        stage = g["stage_id"].values
        for i in range(len(g) - window):
            X_seq.append(feats[i:i + window])
            y_next.append(feats[i + window])
            y_mal.append(mal[i + window])
            y_stage.append(stage[i + window - 1])  # current stage target
    return (np.array(X_seq, dtype=np.float32), np.array(y_next, dtype=np.float32),
            np.array(y_mal, dtype=np.float32), np.array(y_stage, dtype=np.int64))


def compute_metrics(y_true, y_pred):
    y_t, y_p = np.asarray(y_true, int), np.asarray(y_pred, int)
    tp = int(((y_t == 1) & (y_p == 1)).sum())
    tn = int(((y_t == 0) & (y_p == 0)).sum())
    fp = int(((y_t == 0) & (y_p == 1)).sum())
    fn = int(((y_t == 1) & (y_p == 0)).sum())
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"f1": round(f1, 4), "precision": round(prec, 4), "recall": round(rec, 4), "fpr": round(fpr, 4)}


# =====================================================================
# TRAINING
# =====================================================================

def train_model(df, args, existing_model=None, existing_scaler=None):
    """Train or fine-tune the WorldModel."""

    is_finetune = existing_model is not None
    mode = "FINE-TUNE" if is_finetune else "FROM SCRATCH"
    lr = args.lr if not is_finetune else args.lr / 10

    print(f"\n  ============================================================")
    print(f"   TRAINING -- {mode}")
    print(f"  ============================================================")
    print(f"    LR: {lr:.1e}, Epochs: {args.epochs}, Batch: {args.batch_size}")
    if is_finetune and args.freeze_lstm:
        print(f"    LSTM: FROZEN (head-only fine-tune)")

    # Split
    sids = df["session_id"].unique()
    train_sids, val_sids, test_sids = three_way_split(sids)
    train_df = df[df["session_id"].isin(train_sids)].copy()
    val_df = df[df["session_id"].isin(val_sids)].copy()
    test_df = df[df["session_id"].isin(test_sids)].copy()
    print(f"    Train: {len(train_df)} flows, Val: {len(val_df)}, Test: {len(test_df)}")

    # Scale
    if is_finetune and existing_scaler and not args.refit_scaler:
        scaler = existing_scaler
        print("    Using existing scaler")
    else:
        scaler = StandardScaler()
        print("    Fitting new scaler")
    train_df[FLOW_FEATURES] = scaler.fit_transform(train_df[FLOW_FEATURES]) if not is_finetune else scaler.transform(train_df[FLOW_FEATURES])
    val_df[FLOW_FEATURES] = scaler.transform(val_df[FLOW_FEATURES])
    test_df[FLOW_FEATURES] = scaler.transform(test_df[FLOW_FEATURES])

    train_df["stage_id"] = train_df["stage_label"].map(STAGE2ID)
    val_df["stage_id"] = val_df["stage_label"].map(STAGE2ID)
    test_df["stage_id"] = test_df["stage_label"].map(STAGE2ID)

    train_sorted = train_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    val_sorted = val_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    test_sorted = test_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)

    X_train, yn_train, ym_train, ys_train = build_sequences(train_sorted)
    X_val, yn_val, ym_val, ys_val = build_sequences(val_sorted)
    X_test, yn_test, ym_test, ys_test = build_sequences(test_sorted)
    print(f"    Sequences: Train={X_train.shape[0]}, Val={X_val.shape[0]}, Test={X_test.shape[0]}")

    train_loader = DataLoader(FlowSeqDataset(X_train, yn_train, ym_train, ys_train), batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(FlowSeqDataset(X_val, yn_val, ym_val, ys_val), batch_size=args.batch_size)
    test_loader = DataLoader(FlowSeqDataset(X_test, yn_test, ym_test, ys_test), batch_size=args.batch_size)

    # Loss functions
    stage_counts = np.bincount(ys_train, minlength=len(STAGES))
    raw_w = len(ys_train) / (len(STAGES) * np.maximum(stage_counts, 1).astype(np.float32))
    class_w = np.clip(raw_w, 0.2, 6.0)
    ce_loss = FocalLoss(torch.tensor(class_w, dtype=torch.float32).to(DEVICE), gamma=2.0)
    num_pos = (ym_train == 1).sum()
    num_neg = (ym_train == 0).sum()
    pos_w = torch.tensor([float(num_neg) / max(float(num_pos), 1.0)], dtype=torch.float32).to(DEVICE)
    bce_loss = nn.BCEWithLogitsLoss(pos_weight=pos_w)
    mse_loss = nn.MSELoss()

    # Model
    if is_finetune:
        model = existing_model
        if args.freeze_lstm:
            for name, p in model.named_parameters():
                if name.startswith("lstm."): p.requires_grad = False
    else:
        model = WorldModel(len(FLOW_FEATURES), hidden=args.hidden, num_layers=args.layers, dropout=args.dropout).to(DEVICE)

    opt = torch.optim.AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs, eta_min=1e-6)

    best_f1, best_state, patience_ctr = -1, None, 0
    print()

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0
        for xb, yn_b, ym_b, ys_b in train_loader:
            xb, yn_b, ym_b, ys_b = xb.to(DEVICE), yn_b.to(DEVICE), ym_b.to(DEVICE), ys_b.to(DEVICE)
            opt.zero_grad()
            pred_next, inf_logit, stage_logits = model(xb)
            loss = mse_loss(pred_next, yn_b) + bce_loss(inf_logit, ym_b) + ce_loss(stage_logits, ys_b)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total_loss += loss.item() * xb.size(0)

        # Validate
        model.eval()
        vp, vt = [], []
        with torch.no_grad():
            for xb, _, ym_b, _ in val_loader:
                _, il, _ = model(xb.to(DEVICE))
                vp.extend((torch.sigmoid(il).cpu().numpy() > 0.5).astype(int))
                vt.extend(ym_b.numpy().astype(int))
        vm = compute_metrics(np.array(vt), np.array(vp))
        scheduler.step()

        ck = ""
        if vm["f1"] > best_f1:
            best_f1 = vm["f1"]
            best_state = copy.deepcopy(model.state_dict())
            patience_ctr = 0
            ck = " *BEST*"
        else:
            patience_ctr += 1

        print(f"    Epoch {epoch+1:2d}/{args.epochs} -- loss: {total_loss/len(train_loader.dataset):.4f} | "
              f"val F1: {vm['f1']:.4f} prec: {vm['precision']:.4f} rec: {vm['recall']:.4f}{ck}")

        if patience_ctr >= args.patience:
            print(f"    Early stop at epoch {epoch+1}")
            break

    if best_state:
        model.load_state_dict(best_state)

    # Test
    model.eval()
    tp, tt, sp, st = [], [], [], []
    with torch.no_grad():
        for xb, _, ym_b, ys_b in test_loader:
            _, il, sl = model(xb.to(DEVICE))
            tp.extend((torch.sigmoid(il).cpu().numpy() > 0.5).astype(int))
            tt.extend(ym_b.numpy().astype(int))
            sp.extend(torch.argmax(sl, 1).cpu().numpy())
            st.extend(ys_b.numpy())

    tm = compute_metrics(np.array(tt), np.array(tp))
    print(f"\n  +--------------------------------------------------+")
    print(f"  |  TEST RESULTS                                    |")
    print(f"  |  F1:        {tm['f1']:.4f}                                |")
    print(f"  |  Precision: {tm['precision']:.4f}                                |")
    print(f"  |  Recall:    {tm['recall']:.4f}                                |")
    print(f"  |  FPR:       {tm['fpr']:.4f}                                |")
    print(f"  +--------------------------------------------------+")

    print("\n    Per-stage accuracy:")
    for sn, si in STAGE2ID.items():
        mask = np.array(st) == si
        if mask.sum() > 0:
            acc = (np.array(sp)[mask] == si).sum() / mask.sum()
            print(f"      {sn:20s}: {acc:.4f} ({int(mask.sum())} samples)")

    return model, scaler, tm, best_f1


# =====================================================================
# MAIN
# =====================================================================

def main():
    ap = argparse.ArgumentParser(description="Garud: Generate campaign data + retrain model (one file, zero setup)")
    ap.add_argument("--mode", choices=["finetune", "scratch", "generate-only"], default="finetune",
                    help="finetune=update existing model, scratch=train new, generate-only=just output CSV")
    ap.add_argument("--attack-sessions", type=int, default=80, help="Number of attack campaign sessions to generate")
    ap.add_argument("--benign-sessions", type=int, default=120, help="Number of benign sessions to generate")
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--hidden", type=int, default=256)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--dropout", type=float, default=0.25)
    ap.add_argument("--patience", type=int, default=5)
    ap.add_argument("--freeze-lstm", action="store_true", help="Freeze LSTM for fine-tuning (safest)")
    ap.add_argument("--refit-scaler", action="store_true")
    ap.add_argument("--output-csv", default=str(ROOT / "campaign_dataset.csv"), help="Where to save generated CSV")
    ap.add_argument("--combine-base", action="store_true", help="Also combine with real_flows.csv if it exists")
    ap.add_argument("--sample-base-sessions", type=int, default=0,
                    help="Optional: number of base sessions to stratify-sample when fine-tuning (0=use all)")
    args = ap.parse_args()

    print()
    print("   ____    _    ____  _   _ ____  ")
    print("  / ___|  / \\  |  _ \\| | | |  _ \\ ")
    print(" | |  _  / _ \\ | |_) | | | | | | |")
    print(" | |_| |/ ___ \\|  _ <| |_| | |_| |")
    print("  \\____/_/   \\_\\_| \\_\\\\____/|____/ ")
    print()
    print("  One-File Campaign Generator + Model Trainer")
    print("  SIH 2026 PS:26153 (NTRO) | Team Code 4 Change")
    print(f"  Device: {DEVICE} | Mode: {args.mode}")
    print()

    # Step 1: Generate campaign data
    print("  [1/4] GENERATING CAMPAIGN DATASET")
    print("  " + "=" * 56)
    campaign_df = generate_campaign_dataset(args.attack_sessions, args.benign_sessions)

    # Step 2: Combine with existing base data if available
    combined = campaign_df
    base_path = ROOT / "real_flows.csv"
    if args.combine_base and base_path.exists():
        print(f"\n  [2/4] COMBINING WITH BASE DATA")
        print("  " + "=" * 56)
        base_df = pd.read_csv(base_path, parse_dates=["timestamp"], low_memory=False)

        if args.sample_base_sessions and args.sample_base_sessions > 0 and base_df["session_id"].nunique() > args.sample_base_sessions:
            print(f"    Stratified subsampling {args.sample_base_sessions} base sessions for balanced fine-tuning...")
            sampled_sids = set()
            for stage in STAGES:
                sids_for_stage = base_df[base_df["stage_label"] == stage]["session_id"].unique()
                n_pick = min(len(sids_for_stage), max(10, args.sample_base_sessions // len(STAGES)))
                sampled_sids.update(random.sample(list(sids_for_stage), n_pick) if len(sids_for_stage) > n_pick else list(sids_for_stage))
            remaining = args.sample_base_sessions - len(sampled_sids)
            if remaining > 0:
                other_sids = [s for s in base_df["session_id"].unique() if s not in sampled_sids]
                if other_sids:
                    sampled_sids.update(random.sample(other_sids, min(remaining, len(other_sids))))
            base_df = base_df[base_df["session_id"].isin(sampled_sids)].copy()
            print(f"    Subsampled base flows: {len(base_df)} across {len(sampled_sids)} sessions")

        # Shift campaign session IDs to avoid collision
        max_base_sid = base_df["session_id"].max() + 1
        campaign_df["session_id"] = campaign_df["session_id"] + max_base_sid
        combined = pd.concat([base_df, campaign_df], ignore_index=True)
        print(f"    Base flows:     {len(base_df)}")
        print(f"    Campaign flows: {len(campaign_df)}")
        print(f"    Combined:       {len(combined)}")
    else:
        if not args.combine_base:
            print(f"\n  [2/4] USING CAMPAIGN DATA ONLY (no --combine-base)")
        else:
            print(f"\n  [2/4] real_flows.csv not found, using campaign data only")

    # Save CSV
    combined.to_csv(args.output_csv, index=False)
    print(f"\n    Saved: {args.output_csv}")
    print(f"    Size:  {os.path.getsize(args.output_csv) / (1024*1024):.1f} MB")

    if args.mode == "generate-only":
        print("\n  Done (generate-only mode). Use the CSV to train:")
        print(f"    python pipeline_fixed.py --data {args.output_csv}")
        return

    # Step 3: Train
    print(f"\n  [3/4] MODEL TRAINING")
    print("  " + "=" * 56)

    existing_model, existing_scaler = None, None
    if args.mode == "finetune":
        model_path = ARTIFACTS / "world_model.pt"
        scaler_path = ARTIFACTS / "scaler.pkl"
        config_path = ARTIFACTS / "config.json"

        if model_path.exists() and scaler_path.exists() and config_path.exists():
            print("    Loading existing model for fine-tuning...")
            with open(config_path) as f:
                cfg = json.load(f)
            with open(scaler_path, "rb") as f:
                sd = pickle.load(f)
            existing_scaler = StandardScaler(mean=sd["mean"], scale=sd["scale"])

            h = cfg.get("hidden_size", 256)
            nl = cfg.get("num_layers", 2)
            dr = cfg.get("lstm_dropout", 0.25)
            existing_model = WorldModel(len(FLOW_FEATURES), hidden=h, num_layers=nl, dropout=dr).to(DEVICE)
            existing_model.load_state_dict(torch.load(model_path, map_location=DEVICE, weights_only=True))
            print(f"    Loaded: {nl}L LSTM h={h}")
        else:
            print("    No existing model found -- falling back to training from scratch")
            args.mode = "scratch"

    # Backup
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = ARTIFACTS / f"backup_{ts}"
    if ARTIFACTS.exists() and (ARTIFACTS / "world_model.pt").exists():
        shutil.copytree(ARTIFACTS, backup_dir, dirs_exist_ok=True)
        print(f"    Backup: {backup_dir}")

    model, scaler, test_metrics, best_val_f1 = train_model(
        combined, args,
        existing_model=existing_model,
        existing_scaler=existing_scaler,
    )

    # Step 4: Save artifacts
    print(f"\n  [4/4] SAVING ARTIFACTS")
    print("  " + "=" * 56)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    torch.save(model.state_dict(), str(ARTIFACTS / "world_model.pt"))
    with open(ARTIFACTS / "scaler.pkl", "wb") as f:
        pickle.dump({"mean": scaler.mean_, "scale": scaler.scale_}, f)

    config = {
        "window": WINDOW,
        "features": FLOW_FEATURES,
        "stages": STAGES,
        "hidden_size": args.hidden,
        "num_layers": args.layers,
        "lstm_dropout": args.dropout,
        "provenance": {
            "trained_on": str(args.output_csv),
            "mode": args.mode,
            "attack_sessions": args.attack_sessions,
            "benign_sessions": args.benign_sessions,
            "epochs": args.epochs,
            "best_val_f1": best_val_f1,
            "test_metrics": test_metrics,
            "generated_by": "setup/run_all.py",
            "timestamp": ts,
        },
    }

    # Preserve existing config fields
    old_cfg = ARTIFACTS / "config.json"
    if old_cfg.exists():
        with open(old_cfg) as f:
            old = json.load(f)
        for key in ["stage_logit_bias"]:
            if key in old:
                config[key] = old[key]

    with open(ARTIFACTS / "config.json", "w") as f:
        json.dump(config, f, indent=2)

    for name in ["world_model.pt", "scaler.pkl", "config.json"]:
        p = ARTIFACTS / name
        sz = p.stat().st_size / 1024
        print(f"    [OK] {name} ({sz:.1f} KB)")

    print()
    print("  +============================================================+")
    print("  |                    COMPLETE                                 |")
    print("  +============================================================+")
    print(f"    Test F1:      {test_metrics['f1']:.4f}")
    print(f"    Dataset:      {args.output_csv}")
    print(f"    Artifacts:    {ARTIFACTS}")
    print(f"    Backup:       {backup_dir if backup_dir.exists() else 'N/A'}")
    print()
    print("    Next: powershell -File .\\start_all.ps1")
    print()


if __name__ == "__main__":
    main()
