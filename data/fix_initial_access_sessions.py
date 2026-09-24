"""
Add pure, attack-only re-chunked sessions of CIC-IDS2017's real Web
Attack rows, alongside (not replacing) the mixed IP-pair sessions they
already live in.

Why: root-cause analysis (see docs/model_card.md section 5) found that
Initial Access's poor score was concentrated almost entirely in the
original CIC-IDS2017 web-attack rows (test recall 0.476, precision
0.300), while the CIC-IDS2018 rows added earlier this project (built as
pure attack-only sessions by data/augment_initial_access.py) score
recall 0.969, precision 1.000 on the identical test split. The cause:
the shipped CIC-IDS2017 CSVs have no IP or timestamp columns, so
preprocess_cicids.py groups consecutive CSV rows into fixed-size chunks
as sessions; web-attack rows land inside chunks that are mostly benign.
Live sessions (backend/app/ingestion.py::derive_session_key: IP pair +
5-minute bucket) can also mix attack and benign traffic. Every one of the 433 CIC-IDS2017-origin sessions
containing an Initial Access row also contains Benign rows -- confirmed
directly, not assumed.

Because production sessionization is mixed the same way, this script
ADDS pure attack-only re-chunked sessions rather than replacing the
mixed ones. Replacing would train the model only on an easier task
(continue an unbroken run of attack flows) and lose the harder, more
valuable, and more realistic forecasting signal the mixed sessions
provide (predict an upcoming attack flow from mostly-benign preceding
context, which is the actual point of a forecasting system and what
production sessions will actually look like). Adding pure sessions on
top gives the model many more unambiguous positive examples to sharpen
its decision boundary without discarding the harder mixed-session
signal or mismatching the training distribution from what it'll see in
production.

The extraction technique mirrors data/augment_initial_access.py, which
already worked for CIC-IDS2018: filter to ONLY the Web-Attack-labeled
rows before chunking, then group into consecutive session_len=8 windows
by timestamp order, guaranteeing every resulting session is 100% attack
traffic.

This does not fabricate new data -- it reuses the same 2,180 real
CIC-IDS2017 rows already in real_flows.csv under a second, additional
session-grouping scheme, the same way augment_initial_access.py already
contributes a second real data source for this stage.

Run as:
    python data/fix_initial_access_sessions.py
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

RAW_FILE = "data/raw_cicids/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]

FEATURE_CANDIDATES = {
    "flow_duration": ["Flow Duration"],
    "tot_fwd_pkts": ["Total Fwd Packets", "Total Fwd Packet"],
    "tot_bwd_pkts": ["Total Backward Packets", "Total Bwd Packets", "Total Bwd Packet"],
    "fwd_pkt_len_mean": ["Fwd Packet Length Mean"],
    "bwd_pkt_len_mean": ["Bwd Packet Length Mean"],
    "flow_bytes_s": ["Flow Bytes/s", "Flow Byts/s"],
    "flow_pkts_s": ["Flow Packets/s", "Flow Pkts/s"],
    "flow_iat_mean": ["Flow IAT Mean"],
    "flow_iat_std": ["Flow IAT Std"],
    "fwd_iat_mean": ["Fwd IAT Mean"],
    "bwd_iat_mean": ["Bwd IAT Mean"],
    "syn_flag_cnt": ["SYN Flag Count"],
    "ack_flag_cnt": ["ACK Flag Count"],
    "fin_flag_cnt": ["FIN Flag Count"],
    "rst_flag_cnt": ["RST Flag Count"],
    "psh_flag_cnt": ["PSH Flag Count"],
    "urg_flag_cnt": ["URG Flag Count"],
    "down_up_ratio": ["Down/Up Ratio"],
    "pkt_size_avg": ["Average Packet Size", "Avg Packet Size", "Packet Length Mean"],
}


def map_label(raw_label: str):
    if not isinstance(raw_label, str):
        return None
    s = raw_label.strip().lower()
    return "Initial Access" if ("brute force" in s or "xss" in s or "sql injection" in s) else None


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    result = pd.DataFrame(index=df.index)
    for target_feat, candidates in FEATURE_CANDIDATES.items():
        found = False
        for c in candidates:
            if c in df.columns:
                result[target_feat] = pd.to_numeric(df[c], errors="coerce")
                found = True
                break
        if not found:
            result[target_feat] = 0.0

    if "Fwd Header Length" in df.columns and "Bwd Header Length" in df.columns:
        fwd_h = pd.to_numeric(df["Fwd Header Length"], errors="coerce").fillna(0)
        bwd_h = pd.to_numeric(df["Bwd Header Length"], errors="coerce").fillna(0)
        result["ttl_variance"] = np.abs(fwd_h - bwd_h)
    else:
        result["ttl_variance"] = 0.0

    if "Init_Win_bytes_forward" in df.columns:
        result["tcp_win_size"] = pd.to_numeric(df["Init_Win_bytes_forward"], errors="coerce").fillna(0)
    elif "Init Win bytes forward" in df.columns:
        result["tcp_win_size"] = pd.to_numeric(df["Init Win bytes forward"], errors="coerce").fillna(0)
    else:
        result["tcp_win_size"] = 0.0

    if "Subflow Fwd Packets" in df.columns:
        sub = pd.to_numeric(df["Subflow Fwd Packets"], errors="coerce").fillna(0)
        tot = result["tot_fwd_pkts"].fillna(0)
        result["retransmit_cnt"] = np.maximum(0, tot - sub)
    else:
        result["retransmit_cnt"] = 0.0

    result = result.replace([np.inf, -np.inf], np.nan).fillna(0)
    return result


def build_pure_sessions(feats: pd.DataFrame, session_len: int, start_session_id: int) -> pd.DataFrame:
    out_rows = []
    n_sessions = 0
    base_time = pd.Timestamp("2026-02-15 00:00:00")
    for chunk_start in range(0, len(feats), session_len):
        chunk = feats.iloc[chunk_start:chunk_start + session_len]
        if len(chunk) < 3:
            continue
        sid = start_session_id + n_sessions
        n_sessions += 1
        for t, (_, row) in enumerate(chunk.iterrows()):
            out_row = {feat: float(row[feat]) for feat in FLOW_FEATURES}
            out_row["session_id"] = sid
            out_row["timestamp"] = base_time + pd.Timedelta(seconds=(chunk_start + t) * 2)
            out_row["stage_label"] = "Initial Access"
            out_row["is_malicious"] = 1
            out_rows.append(out_row)
    new_df = pd.DataFrame(out_rows)
    new_df = new_df[FLOW_FEATURES + ["session_id", "timestamp", "stage_label", "is_malicious"]]
    print(f"  Built {len(new_df)} rows across {new_df['session_id'].nunique()} pure attack-only sessions")
    return new_df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-file", default=RAW_FILE)
    ap.add_argument("--target", default="real_flows.csv")
    ap.add_argument("--session-len", type=int, default=8)
    ap.add_argument("--start-session-id", type=int, default=4000)
    args = ap.parse_args()

    print(f"Reading raw file: {args.raw_file}")
    raw = pd.read_csv(args.raw_file, low_memory=False)
    raw.columns = [str(c).strip() for c in raw.columns]
    raw["stage_label"] = raw["Label"].astype(str).apply(map_label)
    attack_rows = raw[raw["stage_label"] == "Initial Access"].copy()
    print(f"  Found {len(attack_rows)} real Web Attack rows in raw file")

    print("Extracting 22-feature vectors...")
    feats = extract_features(attack_rows)

    print(f"Chunking into pure attack-only sessions (session_len={args.session_len})...")
    new_df = build_pure_sessions(feats, args.session_len, args.start_session_id)

    target_path = Path(args.target)
    existing = pd.read_csv(target_path, parse_dates=["timestamp"])
    print(f"Existing {target_path}: {existing.shape}")

    backup_path = target_path.with_suffix(target_path.suffix + ".pre_ia_resession_backup")
    if not backup_path.exists():
        existing.to_csv(backup_path, index=False)
        print(f"Backed up original to {backup_path}")

    assert new_df["session_id"].min() > existing["session_id"].max(), "session_id collision!"
    merged = pd.concat([existing, new_df], ignore_index=True)
    merged.to_csv(target_path, index=False)
    print(f"Merged {target_path}: {merged.shape}")
    print(merged["stage_label"].value_counts())


if __name__ == "__main__":
    main()
