"""
Augment real_flows.csv with real Initial Access (Web Attack) examples from
CIC-IDS2018.

Why: real_flows.csv (CIC-IDS2017-derived) has 2,180 real Initial Access rows
(Web Attack Brute Force/XSS/SQL Injection from Thursday-WorkingHours-Morning-
WebAttacks.pcap_ISCX.csv). That's enough to learn from, but the shipped
model's precision on this stage was still weak (17-19%) -- it over-fires,
confusing Benign HTTP traffic for web-attack traffic. Held-out evaluation
confirmed the confusion is concentrated on Benign flows, not other attack
stages, so more real diversity of what "real web attack traffic" looks like
(as opposed to more tuning of the same 2,180 examples) is the most direct
lever left to pull, following the same principle that fixed Lateral
Movement: real data beats more hyperparameter tuning on scarce data.

CIC-IDS2018 dedicates two days to web attacks (Thursday-22-02-2018,
Friday-23-02-2018), combined ~928 real Brute Force-Web / Brute Force-XSS /
SQL Injection flow rows. Smaller than the Lateral Movement fix's 161,934
available rows, but still genuinely new, independently-captured real
examples -- not more synthetic data and not more of the same 2,180 rows.

Same caveats as data/augment_lateral_movement.py: no Src/Dst IP columns in
CIC-IDS2018's public CSVs (session boundaries are synthetic, chunked by
timestamp order; feature VALUES are 100% real), and ttl_variance/
retransmit_cnt aren't in this CICFlowMeter version's output (filled 0.0).

Run as:
    python data/augment_initial_access.py                    # download + merge
    python data/augment_initial_access.py --skip-download    # merge only
"""
import argparse
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

S3_BASE = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
WEBATTACK_DAYS = [
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
]

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]

COLUMN_MAP = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Tot Fwd Pkts",
    "tot_bwd_pkts": "Tot Bwd Pkts",
    "fwd_pkt_len_mean": "Fwd Pkt Len Mean",
    "bwd_pkt_len_mean": "Bwd Pkt Len Mean",
    "flow_bytes_s": "Flow Byts/s",
    "flow_pkts_s": "Flow Pkts/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "fwd_iat_mean": "Fwd IAT Mean",
    "bwd_iat_mean": "Bwd IAT Mean",
    "syn_flag_cnt": "SYN Flag Cnt",
    "ack_flag_cnt": "ACK Flag Cnt",
    "fin_flag_cnt": "FIN Flag Cnt",
    "rst_flag_cnt": "RST Flag Cnt",
    "psh_flag_cnt": "PSH Flag Cnt",
    "urg_flag_cnt": "URG Flag Cnt",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Pkt Size Avg",
    "tcp_win_size": "Init Fwd Win Byts",
}
MISSING_FEATURES = ["ttl_variance", "retransmit_cnt"]
NEEDED_COLS = list(COLUMN_MAP.values()) + ["Timestamp", "Label"]

LABEL_MAP = {
    "Brute Force -Web": "Web Attack Brute Force",
    "Brute Force -XSS": "Web Attack XSS",
    "SQL Injection": "Web Attack SQL Injection",
}


def download(raw_dir: Path):
    raw_dir.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": "Mozilla/5.0"}
    for fname in WEBATTACK_DAYS:
        dest = raw_dir / fname.replace("_TrafficForML_CICFlowMeter", "")
        if dest.exists():
            print(f"  Already downloaded: {dest.name}")
            continue
        url = S3_BASE + fname.replace(" ", "%20")
        print(f"  Downloading {fname} ...")
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as resp, open(dest, "wb") as out:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
        print(f"  Saved {dest} ({dest.stat().st_size / 1e6:.1f} MB)")


def extract_web_attacks(raw_dir: Path) -> pd.DataFrame:
    frames = []
    for fname in WEBATTACK_DAYS:
        path = raw_dir / fname.replace("_TrafficForML_CICFlowMeter", "")
        df = pd.read_csv(path, usecols=NEEDED_COLS, low_memory=False)
        df["Label"] = df["Label"].astype(str).str.strip()
        df = df[df["Label"].isin(LABEL_MAP.keys())].copy()
        print(f"  {path.name}: {len(df)} web attack rows")
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def build_sessions(df: pd.DataFrame, session_len: int, start_session_id: int, seed: int) -> pd.DataFrame:
    df = df.copy()
    df["_ts"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.sort_values("_ts").reset_index(drop=True)

    out_rows = []
    n_sessions = 0
    base_time = pd.Timestamp("2026-02-22 00:00:00")
    for chunk_start in range(0, len(df), session_len):
        chunk = df.iloc[chunk_start:chunk_start + session_len]
        if len(chunk) < 3:
            continue
        sid = start_session_id + n_sessions
        n_sessions += 1
        for t, (_, row) in enumerate(chunk.iterrows()):
            out_row = {feat: float(row[COLUMN_MAP[feat]]) for feat in COLUMN_MAP}
            for feat in MISSING_FEATURES:
                out_row[feat] = 0.0
            out_row["session_id"] = sid
            out_row["timestamp"] = base_time + pd.Timedelta(seconds=(chunk_start + t) * 2)
            out_row["stage_label"] = "Initial Access"
            out_row["is_malicious"] = 1
            out_rows.append(out_row)

    new_df = pd.DataFrame(out_rows)
    new_df = new_df[FLOW_FEATURES + ["session_id", "timestamp", "stage_label", "is_malicious"]]
    bad = ~np.isfinite(new_df[FLOW_FEATURES].values)
    if bad.any():
        n_bad = bad.any(axis=1).sum()
        print(f"  Dropping {n_bad} rows with non-finite feature values")
        new_df = new_df[~bad.any(axis=1)].copy()
    print(f"  Built {len(new_df)} rows across {new_df['session_id'].nunique()} synthetic-boundary sessions")
    return new_df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", default="data/raw_cicids2018")
    ap.add_argument("--target", default="real_flows.csv")
    ap.add_argument("--session-len", type=int, default=8)
    ap.add_argument("--start-session-id", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-download", action="store_true")
    args = ap.parse_args()

    raw_dir = Path(args.raw_dir)
    if not args.skip_download:
        print("Downloading CIC-IDS2018 Web Attack day CSVs...")
        download(raw_dir)

    print("Extracting web attack rows...")
    attacks = extract_web_attacks(raw_dir)
    attacks["family"] = attacks["Label"].map(LABEL_MAP)
    print(f"Total available: {len(attacks)}")
    print(attacks["family"].value_counts().to_string())

    print("Chunking into sessions...")
    new_df = build_sessions(attacks, args.session_len, args.start_session_id, args.seed)

    target_path = Path(args.target)
    existing = pd.read_csv(target_path, parse_dates=["timestamp"])
    print(f"Existing {target_path}: {existing.shape}, session_id range "
          f"{existing['session_id'].min()}-{existing['session_id'].max()}")
    assert new_df["session_id"].min() > existing["session_id"].max(), "session_id collision!"

    backup_path = target_path.with_suffix(target_path.suffix + ".pre_initial_access_backup")
    if not backup_path.exists():
        existing.to_csv(backup_path, index=False)
        print(f"Backed up original to {backup_path}")

    merged = pd.concat([existing, new_df], ignore_index=True)
    merged.to_csv(target_path, index=False)
    print(f"Merged {target_path}: {merged.shape}")
    print(merged["stage_label"].value_counts())


if __name__ == "__main__":
    main()
