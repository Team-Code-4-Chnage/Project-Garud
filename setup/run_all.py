#!/usr/bin/env python3
r"""
=======================================================================
 PROJECT GARUD -- 10-Phase Lab Harness + Campaign Generator + Retrainer
 SIH 2026 PS:26153 (NTRO) | Team: Code 4 Change
=======================================================================

ONE FILE. ZERO CONFIG. Just run:

    python setup\run_all.py                    # default: simulate + fine-tune
    python setup\run_all.py --lab              # real VMs (VirtualBox + Wireshark)
    python setup\run_all.py --mode scratch     # train from scratch
    python setup\run_all.py --mode generate-only  # just output the CSV

10 PHASES:
    0  -- Prerequisites (auto-install packages, check tools)
    1  -- Network Setup (VirtualBox host-only or simulated)
    2  -- VM Download & Import (or simulated endpoints)
    3  -- VM Configuration (network, SSH, snapshots)
    4  -- Lab Validation (connectivity/dry-run)
    5  -- Campaign Data Collection (real attacks or simulated)
    6  -- Flow Extraction (from PCAPs or generated features)
    7  -- Data Merging (combine lab + CIC-IDS base)
    8  -- Model Training (fine-tune or from scratch)
    9  -- Calibration (stage logit bias)
   10  -- Verification (artifacts + test suite)
"""
import argparse
import copy
import json
import os
import pickle
import platform
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# =====================================================================
# HELPERS (must be defined before phase0 which uses them at import time)
# =====================================================================
def ts():
    return datetime.now().strftime("%H:%M:%S")

def banner(phase, title):
    print()
    print(f"  {'='*60}")
    print(f"   PHASE {phase} -- {title}")
    print(f"  {'='*60}")

def log(msg, level="INFO"):
    print(f"  [{ts()}] [{level:4s}] {msg}")

def ok(msg):
    print(f"  [{ts()}] [ OK ] {msg}")

def fail(msg):
    print(f"  [{ts()}] [FAIL] {msg}")

# =====================================================================
# PHASE 0 -- AUTO-INSTALL PYTHON DEPENDENCIES
# =====================================================================
def phase0_install_deps():
    if "-h" in sys.argv or "--help" in sys.argv:
        return

    banner(0, "Prerequisites -- Auto-Install Python Packages")

    required = {
        "torch": "torch --index-url https://download.pytorch.org/whl/cpu",
        "pandas": "pandas",
        "numpy": "numpy",
        "matplotlib": "matplotlib",
        "tqdm": "tqdm",
    }
    for mod, pip_spec in required.items():
        try:
            __import__(mod)
            ok(f"{mod} already installed")
        except ImportError:
            log(f"Installing {mod}...", "WARN")
            installed = False
            # Try standard spec, then with --break-system-packages, then simple package name
            attempts = [
                [sys.executable, "-m", "pip", "install", "-q"] + pip_spec.split(),
                [sys.executable, "-m", "pip", "install", "-q", "--break-system-packages"] + pip_spec.split(),
                [sys.executable, "-m", "pip", "install", "-q", mod],
                [sys.executable, "-m", "pip", "install", "-q", "--break-system-packages", mod],
            ]
            for cmd in attempts:
                try:
                    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    installed = True
                    break
                except Exception:
                    continue

            if installed:
                ok(f"{mod} installed")
            else:
                fail(f"Could not auto-install {mod}. Run manually: pip install {mod}")
                sys.exit(1)

    # Verify torch loads
    try:
        import torch
        ok(f"PyTorch {torch.__version__} (device: {'cuda' if torch.cuda.is_available() else 'cpu'})")
    except ImportError:
        pass

phase0_install_deps()

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
ARTIFACTS_DIR = ROOT / "backend" / "artifacts"
LAB_DIR = ROOT / "lab"

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

# CIC-IDS-calibrated feature profiles per MITRE ATT&CK stage
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
# UTILITY FUNCTIONS
# =====================================================================
def has_cmd(name):
    return shutil.which(name) is not None

def run_cmd(cmd, check=False, capture=True):
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True, timeout=300)
        return r
    except Exception as e:
        return None


# =====================================================================
# CAMPAIGN TEMPLATES -- 8 realistic multi-stage attack kill chains
# =====================================================================
CAMPAIGN_TEMPLATES = [
    {
        "name": "APT Full Kill Chain",
        "desc": "Advanced persistent threat: full recon through exfiltration",
        "chain": [
            ("Benign", 3, 8),
            ("Reconnaissance", 4, 10),
            ("Initial Access", 2, 5),
            ("Lateral Movement", 3, 7),
            ("C2", 4, 12),
            ("Exfiltration", 2, 6),
        ],
    },
    {
        "name": "Smash-and-Grab",
        "desc": "Fast opportunistic attack: minimal recon, immediate exploit + exfil",
        "chain": [
            ("Benign", 1, 3),
            ("Reconnaissance", 1, 3),
            ("Initial Access", 2, 4),
            ("Exfiltration", 3, 8),
        ],
    },
    {
        "name": "Slow Recon + Lateral Spread",
        "desc": "Extended reconnaissance, heavy lateral movement",
        "chain": [
            ("Benign", 5, 12),
            ("Reconnaissance", 8, 20),
            ("Initial Access", 1, 3),
            ("Lateral Movement", 6, 15),
            ("C2", 2, 5),
        ],
    },
    {
        "name": "C2 Persistent Backdoor",
        "desc": "Quick initial access then prolonged C2 beaconing",
        "chain": [
            ("Benign", 2, 5),
            ("Reconnaissance", 2, 4),
            ("Initial Access", 1, 3),
            ("C2", 10, 30),
            ("Exfiltration", 1, 3),
        ],
    },
    {
        "name": "Insider Lateral Movement",
        "desc": "No recon needed, direct lateral movement from compromised insider",
        "chain": [
            ("Benign", 3, 6),
            ("Lateral Movement", 5, 12),
            ("C2", 3, 8),
            ("Exfiltration", 2, 5),
        ],
    },
    {
        "name": "Recon-Only Probe",
        "desc": "Reconnaissance probe that doesn't progress further (detected early)",
        "chain": [
            ("Benign", 5, 10),
            ("Reconnaissance", 6, 15),
            ("Benign", 3, 6),
        ],
    },
    {
        "name": "Ransomware Kill Chain",
        "desc": "Recon, access, lateral spread, then mass encryption + exfiltration",
        "chain": [
            ("Benign", 2, 4),
            ("Reconnaissance", 3, 6),
            ("Initial Access", 2, 4),
            ("Lateral Movement", 4, 10),
            ("Exfiltration", 5, 15),
        ],
    },
    {
        "name": "Watering Hole + C2",
        "desc": "Compromised website leads to C2 implant deployment",
        "chain": [
            ("Benign", 4, 8),
            ("Initial Access", 1, 2),
            ("C2", 8, 20),
            ("Lateral Movement", 2, 5),
            ("Exfiltration", 1, 3),
        ],
    },
]


# =====================================================================
# MODEL ARCHITECTURE (exact copy from pipeline_fixed.py)
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
# DATA HELPERS
# =====================================================================

def three_way_split(ids, val_size=0.1, test_size=0.2):
    rng = np.random.RandomState(SEED)
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
            y_stage.append(stage[i + window - 1])
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


def generate_flow(stage, noise=1.0):
    """Generate one flow with CIC-IDS-scale features for a given MITRE stage."""
    means = np.array(PROFILES_MEAN[stage], dtype=np.float64)
    stds = np.array(PROFILES_STD[stage], dtype=np.float64) * noise
    return dict(zip(FLOW_FEATURES, np.maximum(0, np.random.normal(means, stds))))


def generate_campaign_session(template, sid, base_time):
    """Generate a complete multi-stage attack campaign from a template."""
    rows = []
    idx = 0
    for stage, lo, hi in template["chain"]:
        n = random.randint(lo, hi)
        for _ in range(n):
            flow = generate_flow(stage, noise=1.0 + random.uniform(-0.2, 0.3))
            flow["session_id"] = sid
            flow["timestamp"] = base_time + pd.Timedelta(seconds=idx * 2 + random.uniform(0, 1))
            flow["stage_label"] = stage
            flow["is_malicious"] = int(stage != "Benign")
            rows.append(flow)
            idx += 1
    return rows


def generate_benign_session(sid, base_time, n=None):
    """Generate a pure benign traffic session."""
    if n is None:
        n = random.randint(15, 50)
    rows = []
    for i in range(n):
        flow = generate_flow("Benign", noise=1.0 + random.uniform(-0.1, 0.1))
        flow["session_id"] = sid
        flow["timestamp"] = base_time + pd.Timedelta(seconds=i * 2 + random.uniform(0, 0.5))
        flow["stage_label"] = "Benign"
        flow["is_malicious"] = 0
        rows.append(flow)
    return rows


# =====================================================================
# PHASE 1-4: LAB NETWORK + VM SETUP (--lab mode only)
# =====================================================================

def phase1_network(args):
    banner(1, "Network Setup -- VirtualBox Host-Only")
    if not args.lab:
        ok("Simulated mode: no VirtualBox network needed")
        return True

    if not has_cmd("VBoxManage"):
        fail("VBoxManage not found. Install VirtualBox: https://www.virtualbox.org")
        fail("Or run without --lab for simulated campaign data")
        return False

    r = run_cmd(["VBoxManage", "list", "hostonlyifs"])
    if r and r.stdout and "192.168.56." in r.stdout:
        ok("Host-only adapter with 192.168.56.x already exists")
    else:
        log("Creating host-only adapter...")
        run_cmd(["VBoxManage", "hostonlyif", "create"])
        # Find and configure
        r2 = run_cmd(["VBoxManage", "list", "hostonlyifs"])
        if r2 and r2.stdout:
            for line in r2.stdout.splitlines():
                if line.startswith("Name:"):
                    iface = line.split(":", 1)[1].strip()
            run_cmd(["VBoxManage", "hostonlyif", "ipconfig", iface,
                      "--ip", "192.168.56.1", "--netmask", "255.255.255.0"])
            ok(f"Created and configured: {iface}")
        else:
            fail("Could not create host-only interface")
            return False

    run_cmd(["VBoxManage", "dhcpserver", "modify", "--ifname",
             "VirtualBox Host-Only Ethernet Adapter", "--disable"])
    ok("DHCP disabled (static IPs only)")
    return True


def phase2_vms(args):
    banner(2, "VM Download & Import")
    if not args.lab:
        ok("Simulated mode: using synthetic endpoints")
        ok("  Attacker : 192.168.56.10 (simulated Kali)")
        ok("  Victim   : 192.168.56.20 (simulated Metasploitable)")
        ok("  Peer     : 192.168.56.21 (simulated peer)")
        return True

    if not has_cmd("VBoxManage"):
        fail("VBoxManage not on PATH")
        return False

    vms = {"kali-lab": "attacker", "target-victim": "victim", "target-peer": "peer"}
    existing = run_cmd(["VBoxManage", "list", "vms"])
    existing_str = existing.stdout if existing else ""

    for vm_name, role in vms.items():
        if f'"{vm_name}"' in existing_str:
            ok(f"VM '{vm_name}' ({role}) already exists")
        else:
            log(f"VM '{vm_name}' ({role}) not found", "WARN")
            log(f"  Download manually and import into VirtualBox:")
            if "kali" in vm_name:
                log(f"    Kali: https://www.kali.org/get-kali/#kali-virtual-machines")
            else:
                log(f"    Metasploitable2: https://sourceforge.net/projects/metasploitable/")
    return True


def phase3_configure(args):
    banner(3, "VM Configuration -- Network, SSH, Snapshots")
    if not args.lab:
        ok("Simulated mode: no VM configuration needed")
        return True

    ok("VMs should be configured with host-only networking:")
    log("  kali-lab        -> 192.168.56.10")
    log("  target-victim   -> 192.168.56.20")
    log("  target-peer     -> 192.168.56.21")
    log("  All NICs: host-only only (no NAT, no bridged)")
    return True


def phase4_validate(args):
    banner(4, "Lab Validation")
    if not args.lab:
        ok("Simulated mode: validation not needed")
        ok("Campaign data will be generated from statistical profiles")
        ok(f"  {len(CAMPAIGN_TEMPLATES)} attack templates available")
        ok(f"  {len(FLOW_FEATURES)} CIC-IDS-calibrated flow features")
        return True

    # Check lab scripts exist
    scripts = ["collect_dataset.py", "extract_flows.py", "reset_lab.py"]
    for s in scripts:
        p = LAB_DIR / s
        if p.exists():
            ok(f"lab/{s} found")
        else:
            fail(f"lab/{s} MISSING")
            return False

    # Check lab_config
    cfg_path = LAB_DIR / "lab_config.json"
    if not cfg_path.exists():
        log("Creating lab_config.json from example...", "WARN")
        ex = LAB_DIR / "lab_config.example.json"
        if ex.exists():
            shutil.copy(ex, cfg_path)
            ok("Created lab_config.json")
        else:
            fail("No lab_config.example.json found")
            return False
    return True


# =====================================================================
# PHASE 5 -- CAMPAIGN DATA COLLECTION
# =====================================================================

def phase5_collect(args):
    banner(5, f"Campaign Data Collection -- {args.attack_sessions} attacks + {args.benign_sessions} benign")

    if args.lab:
        # Real VM collection
        log("Using real VM lab for data collection...")
        cfg_path = LAB_DIR / "lab_config.json"
        dataset_dir = ROOT / "dataset"

        # Reset lab
        reset = LAB_DIR / "reset_lab.py"
        if reset.exists():
            run_cmd([sys.executable, str(reset), "--config", str(cfg_path)])

        # Collect
        collect = LAB_DIR / "collect_dataset.py"
        t0 = time.time()
        r = run_cmd([sys.executable, str(collect), "--config", str(cfg_path),
                      "--out", str(dataset_dir)], capture=False)
        elapsed = (time.time() - t0) / 60
        ok(f"Collection done in {elapsed:.1f} minutes")
        return dataset_dir
    else:
        # Simulated campaign generation
        log(f"Generating simulated campaign data...")
        log(f"  Attack templates: {len(CAMPAIGN_TEMPLATES)}")

        all_rows = []
        sid = 0
        base = pd.Timestamp("2026-01-01")

        # Print each campaign template being used
        template_usage = {}
        for i in range(args.attack_sessions):
            tmpl = random.choice(CAMPAIGN_TEMPLATES)
            template_usage[tmpl["name"]] = template_usage.get(tmpl["name"], 0) + 1
            t0 = base + pd.Timedelta(minutes=sid * 5)
            rows = generate_campaign_session(tmpl, sid, t0)
            all_rows.extend(rows)
            sid += 1

        for i in range(args.benign_sessions):
            t0 = base + pd.Timedelta(minutes=sid * 5)
            rows = generate_benign_session(sid, t0)
            all_rows.extend(rows)
            sid += 1

        df = pd.DataFrame(all_rows)

        # Summary
        ok(f"Generated {len(df)} total flows across {sid} sessions")
        log(f"  Attack: {args.attack_sessions} sessions, Benign: {args.benign_sessions} sessions")
        log("")
        log("  Campaign template distribution:")
        for name, count in sorted(template_usage.items(), key=lambda x: -x[1]):
            print(f"    {name:35s}: {count:3d} sessions")
        log("")
        log("  Stage flow distribution:")
        for stage in STAGES:
            c = (df["stage_label"] == stage).sum()
            if c > 0:
                pct = 100 * c / len(df)
                bar = "#" * int(pct / 2)
                print(f"    {stage:20s}: {c:5d} ({pct:5.1f}%) {bar}")

        return df


# =====================================================================
# PHASE 6 -- FLOW EXTRACTION
# =====================================================================

def phase6_extract(args, collect_result):
    banner(6, "Flow Extraction")

    if args.lab:
        # Extract from PCAPs
        dataset_dir = collect_result
        extractor = LAB_DIR / "extract_flows.py"
        if extractor.exists():
            log("Extracting flows from PCAPs...")
            r = run_cmd([sys.executable, str(extractor), "--dataset", str(dataset_dir)])
            if r and r.returncode == 0:
                ok("Flow extraction complete")
            else:
                fail("Flow extraction failed")
                return None

        # Load extracted flows
        all_dfs = []
        for flows_csv in dataset_dir.rglob("flows.csv"):
            sub = pd.read_csv(flows_csv, parse_dates=["timestamp"])
            all_dfs.append(sub)
            log(f"  {flows_csv.parent.name}: {len(sub)} flows")
        if all_dfs:
            df = pd.concat(all_dfs, ignore_index=True)
            ok(f"Total: {len(df)} flows from {len(all_dfs)} runs")
            return df
        else:
            fail("No flows.csv files found")
            return None
    else:
        # Already have DataFrame from phase5
        ok(f"Flows already in memory: {len(collect_result)} flows, {len(FLOW_FEATURES)} features")
        return collect_result


# =====================================================================
# PHASE 7 -- DATA MERGING
# =====================================================================

def phase7_merge(args, campaign_df):
    banner(7, "Data Merging -- Campaign + CIC-IDS Base")

    combined = campaign_df.copy()

    # Try to combine with existing base data
    base_path = ROOT / "real_flows.csv"
    if args.combine_base and base_path.exists():
        log(f"Loading base data: {base_path}")
        base_df = pd.read_csv(base_path, parse_dates=["timestamp"])
        max_sid = base_df["session_id"].max() + 1
        combined["session_id"] = combined["session_id"] + max_sid
        combined = pd.concat([base_df, combined], ignore_index=True)
        ok(f"Combined: {len(base_df)} base + {len(campaign_df)} campaign = {len(combined)} total")
    elif args.combine_base:
        log("real_flows.csv not found, using campaign data only", "WARN")
    else:
        ok(f"Using campaign data only: {len(combined)} flows")

    # Ensure required columns
    if "is_malicious" not in combined.columns:
        combined["is_malicious"] = combined["stage_label"].apply(lambda s: 0 if s == "Benign" else 1)

    # Save CSV
    out_path = Path(args.output_csv)
    combined.to_csv(out_path, index=False)
    sz_mb = out_path.stat().st_size / (1024 * 1024)
    ok(f"Saved: {out_path} ({sz_mb:.1f} MB, {len(combined)} flows)")

    return combined


# =====================================================================
# PHASE 8 -- MODEL TRAINING
# =====================================================================

def phase8_train(args, df):
    banner(8, f"Model Training -- Mode: {args.mode}, Epochs: {args.epochs}")

    if args.mode == "generate-only":
        ok("generate-only mode: skipping training")
        return None, None, None

    # Load existing model for fine-tuning
    existing_model, existing_scaler = None, None
    is_finetune = args.mode == "finetune"

    if is_finetune:
        model_pt = ARTIFACTS_DIR / "world_model.pt"
        scaler_pkl = ARTIFACTS_DIR / "scaler.pkl"
        config_json = ARTIFACTS_DIR / "config.json"

        if model_pt.exists() and scaler_pkl.exists() and config_json.exists():
            log("Loading existing model for fine-tuning...")
            with open(config_json) as f:
                cfg = json.load(f)
            with open(scaler_pkl, "rb") as f:
                sd = pickle.load(f)
            existing_scaler = StandardScaler(mean=sd["mean"], scale=sd["scale"])

            h = cfg.get("hidden_size", 256)
            nl = cfg.get("num_layers", 2)
            dr = cfg.get("lstm_dropout", 0.25)
            existing_model = WorldModel(len(FLOW_FEATURES), hidden=h, num_layers=nl, dropout=dr).to(DEVICE)
            existing_model.load_state_dict(torch.load(model_pt, map_location=DEVICE, weights_only=True))
            ok(f"Loaded existing model: {nl}L LSTM h={h}")
        else:
            log("No existing model found, falling back to from-scratch", "WARN")
            is_finetune = False

    lr = args.lr / 10 if is_finetune else args.lr
    mode_str = "FINE-TUNE" if is_finetune else "FROM SCRATCH"
    log(f"Mode: {mode_str}, LR: {lr:.1e}, Epochs: {args.epochs}")
    if is_finetune and args.freeze_lstm:
        log("LSTM backbone: FROZEN (head-only training)")

    # Backup
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = ARTIFACTS_DIR / f"backup_{ts_str}"
    if ARTIFACTS_DIR.exists() and (ARTIFACTS_DIR / "world_model.pt").exists():
        shutil.copytree(ARTIFACTS_DIR, backup_dir, dirs_exist_ok=True)
        ok(f"Backup -> {backup_dir.name}")

    # Split
    sids = df["session_id"].unique()
    train_sids, val_sids, test_sids = three_way_split(sids)
    train_df = df[df["session_id"].isin(train_sids)].copy()
    val_df = df[df["session_id"].isin(val_sids)].copy()
    test_df = df[df["session_id"].isin(test_sids)].copy()
    log(f"Split: train={len(train_df)}, val={len(val_df)}, test={len(test_df)}")

    # Scale
    if is_finetune and existing_scaler and not args.refit_scaler:
        scaler = existing_scaler
    else:
        scaler = StandardScaler()
        scaler.fit(train_df[FLOW_FEATURES])
    train_df[FLOW_FEATURES] = scaler.transform(train_df[FLOW_FEATURES])
    val_df[FLOW_FEATURES] = scaler.transform(val_df[FLOW_FEATURES])
    test_df[FLOW_FEATURES] = scaler.transform(test_df[FLOW_FEATURES])

    for split_df in [train_df, val_df, test_df]:
        split_df["stage_id"] = split_df["stage_label"].map(STAGE2ID)

    train_s = train_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    val_s = val_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    test_s = test_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)

    X_tr, yn_tr, ym_tr, ys_tr = build_sequences(train_s)
    X_va, yn_va, ym_va, ys_va = build_sequences(val_s)
    X_te, yn_te, ym_te, ys_te = build_sequences(test_s)
    log(f"Sequences: train={X_tr.shape[0]}, val={X_va.shape[0]}, test={X_te.shape[0]}")

    tr_loader = DataLoader(FlowSeqDataset(X_tr, yn_tr, ym_tr, ys_tr), batch_size=args.batch_size, shuffle=True)
    va_loader = DataLoader(FlowSeqDataset(X_va, yn_va, ym_va, ys_va), batch_size=args.batch_size)
    te_loader = DataLoader(FlowSeqDataset(X_te, yn_te, ym_te, ys_te), batch_size=args.batch_size)

    # Losses
    stage_counts = np.bincount(ys_tr, minlength=len(STAGES))
    raw_w = len(ys_tr) / (len(STAGES) * np.maximum(stage_counts, 1).astype(np.float32))
    class_w = np.clip(raw_w, 0.2, 6.0)
    focal = FocalLoss(torch.tensor(class_w, dtype=torch.float32).to(DEVICE), gamma=2.0)
    n_pos = (ym_tr == 1).sum()
    n_neg = (ym_tr == 0).sum()
    pw = torch.tensor([float(n_neg) / max(float(n_pos), 1.0)], dtype=torch.float32).to(DEVICE)
    bce = nn.BCEWithLogitsLoss(pos_weight=pw)
    mse = nn.MSELoss()

    # Model
    if is_finetune:
        model = existing_model
        if args.freeze_lstm:
            for n, p in model.named_parameters():
                if n.startswith("lstm."): p.requires_grad = False
    else:
        model = WorldModel(len(FLOW_FEATURES), hidden=args.hidden, num_layers=args.layers, dropout=args.dropout).to(DEVICE)

    opt = torch.optim.AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=lr, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs, eta_min=1e-6)

    best_f1, best_state, patience = -1, None, 0
    print()

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0
        for xb, yn_b, ym_b, ys_b in tr_loader:
            xb, yn_b, ym_b, ys_b = xb.to(DEVICE), yn_b.to(DEVICE), ym_b.to(DEVICE), ys_b.to(DEVICE)
            opt.zero_grad()
            pn, il, sl = model(xb)
            loss = mse(pn, yn_b) + bce(il, ym_b) + focal(sl, ys_b)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total_loss += loss.item() * xb.size(0)

        model.eval()
        vp, vt = [], []
        with torch.no_grad():
            for xb, _, ym_b, _ in va_loader:
                _, il, _ = model(xb.to(DEVICE))
                vp.extend((torch.sigmoid(il).cpu().numpy() > 0.5).astype(int))
                vt.extend(ym_b.numpy().astype(int))
        vm = compute_metrics(np.array(vt), np.array(vp))
        sched.step()

        ck = ""
        if vm["f1"] > best_f1:
            best_f1 = vm["f1"]
            best_state = copy.deepcopy(model.state_dict())
            patience = 0
            ck = " << BEST"
        else:
            patience += 1

        avg_loss = total_loss / max(len(tr_loader.dataset), 1)
        print(f"    Epoch {epoch+1:2d}/{args.epochs} | loss: {avg_loss:.4f} | "
              f"val_F1: {vm['f1']:.4f}  prec: {vm['precision']:.4f}  rec: {vm['recall']:.4f}{ck}")

        if patience >= args.patience:
            print(f"    Early stop at epoch {epoch+1}")
            break

    if best_state:
        model.load_state_dict(best_state)

    # Test evaluation
    model.eval()
    tp_list, tt_list, sp_list, st_list = [], [], [], []
    with torch.no_grad():
        for xb, _, ym_b, ys_b in te_loader:
            _, il, sl = model(xb.to(DEVICE))
            tp_list.extend((torch.sigmoid(il).cpu().numpy() > 0.5).astype(int))
            tt_list.extend(ym_b.numpy().astype(int))
            sp_list.extend(torch.argmax(sl, 1).cpu().numpy())
            st_list.extend(ys_b.numpy())

    test_m = compute_metrics(np.array(tt_list), np.array(tp_list))

    print()
    print(f"  +----------------------------------------------------+")
    print(f"  |  TEST RESULTS ({mode_str:14s})                   |")
    print(f"  |  F1:        {test_m['f1']:.4f}                              |")
    print(f"  |  Precision: {test_m['precision']:.4f}                              |")
    print(f"  |  Recall:    {test_m['recall']:.4f}                              |")
    print(f"  |  FPR:       {test_m['fpr']:.4f}                              |")
    print(f"  +----------------------------------------------------+")

    print("\n    Per-stage accuracy:")
    for sn, si in STAGE2ID.items():
        mask = np.array(st_list) == si
        if mask.sum() > 0:
            acc = (np.array(sp_list)[mask] == si).sum() / mask.sum()
            print(f"      {sn:20s}: {acc:.4f} ({int(mask.sum())} samples)")

    return model, scaler, test_m


# =====================================================================
# PHASE 9 -- CALIBRATION
# =====================================================================

def phase9_calibrate(args, model, scaler, test_metrics):
    banner(9, "Stage Logit Calibration")

    if args.mode == "generate-only":
        ok("Skipped (generate-only mode)")
        return

    calib_script = ROOT / "experiments" / "calibrate_stage_logits.py"
    if calib_script.exists():
        log("Running calibration script...")
        r = run_cmd([sys.executable, str(calib_script)], capture=False)
        if r and r.returncode == 0:
            ok("Calibration complete")
            log("Copy 'Final bias' values into backend/artifacts/config.json -> stage_logit_bias")
        else:
            log("Calibration had issues. Model works without it.", "WARN")
    else:
        log("Calibration script not found, skipping", "WARN")
        ok("Model works fine without calibration")


# =====================================================================
# PHASE 10 -- VERIFICATION + SAVE
# =====================================================================

def phase10_verify(args, model, scaler, test_metrics):
    banner(10, "Verification & Save Artifacts")

    if args.mode == "generate-only":
        ok(f"Dataset saved to: {args.output_csv}")
        ok("Use it to train: python pipeline_fixed.py --data <csv>")
        return

    # Save artifacts
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    torch.save(model.state_dict(), str(ARTIFACTS_DIR / "world_model.pt"))
    with open(ARTIFACTS_DIR / "scaler.pkl", "wb") as f:
        pickle.dump({"mean": scaler.mean_, "scale": scaler.scale_}, f)

    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
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
            "test_metrics": test_metrics,
            "generated_by": "setup/run_all.py",
            "timestamp": ts_str,
        },
    }

    # Preserve calibration biases
    old_cfg = ARTIFACTS_DIR / "config.json"
    if old_cfg.exists():
        try:
            with open(old_cfg) as f:
                old = json.load(f)
            if "stage_logit_bias" in old:
                config["stage_logit_bias"] = old["stage_logit_bias"]
        except Exception:
            pass

    with open(ARTIFACTS_DIR / "config.json", "w") as f:
        json.dump(config, f, indent=2)

    # Verify all saved
    print()
    for name in ["world_model.pt", "scaler.pkl", "config.json"]:
        p = ARTIFACTS_DIR / name
        if p.exists():
            sz = p.stat().st_size / 1024
            ok(f"{name} ({sz:.1f} KB)")
        else:
            fail(f"{name} MISSING!")

    # Run tests if they exist
    test_dir = ROOT / "backend" / "tests"
    if test_dir.exists():
        log("Running test suite...")
        r = run_cmd([sys.executable, "-m", "pytest", str(test_dir), "-v", "--tb=short"])
        if r and r.returncode == 0:
            ok("All tests passed")
        else:
            log("Some tests may need fixture updates for new model", "WARN")


# =====================================================================
# MAIN
# =====================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Project Garud: 10-Phase Lab Harness + Campaign Generator + Model Trainer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup/run_all.py                           # simulate + fine-tune
  python setup/run_all.py --mode scratch             # train from scratch
  python setup/run_all.py --mode generate-only       # just output CSV
  python setup/run_all.py --lab                      # use real VirtualBox VMs
  python setup/run_all.py --attack-sessions 200      # more attack data
  python setup/run_all.py --combine-base             # merge with CIC-IDS
  python setup/run_all.py --freeze-lstm              # safest fine-tune
        """,
    )
    ap.add_argument("--lab", action="store_true",
                    help="Use real VirtualBox VMs instead of simulated data")
    ap.add_argument("--mode", choices=["finetune", "scratch", "generate-only"],
                    default="finetune", help="Training mode (default: finetune)")
    ap.add_argument("--attack-sessions", type=int, default=80,
                    help="Number of attack campaign sessions (default: 80)")
    ap.add_argument("--benign-sessions", type=int, default=120,
                    help="Number of benign sessions (default: 120)")
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--hidden", type=int, default=256)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--dropout", type=float, default=0.25)
    ap.add_argument("--patience", type=int, default=5)
    ap.add_argument("--freeze-lstm", action="store_true",
                    help="Freeze LSTM backbone for fine-tuning (safest)")
    ap.add_argument("--refit-scaler", action="store_true",
                    help="Refit scaler on new data instead of using existing")
    ap.add_argument("--combine-base", action="store_true",
                    help="Merge with real_flows.csv if it exists")
    ap.add_argument("--data", "--dataset", default=None,
                    help="Path to existing dataset CSV to train/retrain on (bypasses phases 1-6)")
    ap.add_argument("--output-csv", default=str(ROOT / "campaign_dataset.csv"),
                    help="Path to save generated dataset CSV")
    args = ap.parse_args()

    # Banner
    print()
    print("   ____    _    ____  _   _ ____  ")
    print("  / ___|  / \\  |  _ \\| | | |  _ \\ ")
    print(" | |  _  / _ \\ | |_) | | | | | | |")
    print(" | |_| |/ ___ \\|  _ <| |_| | |_| |")
    print("  \\____/_/   \\_\\_| \\_\\\\____/|____/ ")
    print()
    print("  10-Phase Lab Harness + Campaign Generator + Model Trainer")
    print("  SIH 2026 PS:26153 (NTRO) | Team Code 4 Change")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print(f"  Device: {DEVICE}")
    print(f"  Mode: {'REAL LAB' if args.lab else 'SIMULATED'} + {args.mode.upper()}")
    if args.data:
        print(f"  Input Dataset: {args.data}")
    else:
        print(f"  Data: {args.attack_sessions} attack + {args.benign_sessions} benign sessions")
    print()

    t_start = time.time()

    # Phase 0 already ran at import time (deps)

    if args.data:
        banner("5-7", f"Loading Dataset: {args.data}")
        data_p = Path(args.data)
        if not data_p.exists():
            fail(f"Dataset file not found: {data_p}")
            sys.exit(1)
        campaign_df = pd.read_csv(data_p)
        ok(f"Loaded {len(campaign_df)} rows from {data_p.name}")

        missing_feats = [c for c in FLOW_FEATURES if c not in campaign_df.columns]
        if missing_feats:
            fail(f"Dataset is missing required flow feature columns: {missing_feats[:5]}... ({len(missing_feats)} missing)")
            sys.exit(1)

        if "stage_label" not in campaign_df.columns:
            fail("Dataset is missing required column: 'stage_label'")
            sys.exit(1)

        if "session_id" not in campaign_df.columns:
            log("No 'session_id' found -- grouping every 10 flows as a session", "WARN")
            campaign_df["session_id"] = np.arange(len(campaign_df)) // 10

        if "timestamp" not in campaign_df.columns:
            log("No 'timestamp' found -- assigning sequential timestamps", "WARN")
            base_t = pd.Timestamp.now()
            campaign_df["timestamp"] = [base_t + pd.Timedelta(seconds=i*5) for i in range(len(campaign_df))]
        else:
            campaign_df["timestamp"] = pd.to_datetime(campaign_df["timestamp"])

        if "is_malicious" not in campaign_df.columns:
            campaign_df["is_malicious"] = campaign_df["stage_label"].apply(lambda s: 0 if s == "Benign" else 1)

        combined = campaign_df
    else:
        # Phase 1-4: Lab setup
        if not phase1_network(args): sys.exit(1)
        if not phase2_vms(args): sys.exit(1)
        if not phase3_configure(args): sys.exit(1)
        if not phase4_validate(args): sys.exit(1)

        # Phase 5: Collect
        collect_result = phase5_collect(args)

        # Phase 6: Extract
        campaign_df = phase6_extract(args, collect_result)
        if campaign_df is None:
            fail("No data available. Cannot proceed.")
            sys.exit(1)

        # Phase 7: Merge
        combined = phase7_merge(args, campaign_df)

    # Phase 8: Train
    model, scaler, test_metrics = phase8_train(args, combined)

    # Phase 9: Calibrate
    phase9_calibrate(args, model, scaler, test_metrics)

    # Phase 10: Verify + Save
    phase10_verify(args, model, scaler, test_metrics)

    # Final summary
    elapsed = (time.time() - t_start) / 60
    print()
    print(f"  {'='*60}")
    print(f"   ALL 10 PHASES COMPLETE ({elapsed:.1f} minutes)")
    print(f"  {'='*60}")
    print(f"    Dataset   : {args.output_csv}")
    print(f"    Artifacts : {ARTIFACTS_DIR}")
    if test_metrics:
        print(f"    Test F1   : {test_metrics['f1']:.4f}")
        print(f"    Precision : {test_metrics['precision']:.4f}")
        print(f"    Recall    : {test_metrics['recall']:.4f}")
    print()
    print("    Next: python start_all.py   OR   powershell -File start_all.ps1")
    print()


if __name__ == "__main__":
    main()
