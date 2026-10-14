"""
Merge lab campaign flows into the existing real_flows.csv training data.

Lab flows have IPs, timestamps, and scenario labels. This script:
  1. Reads all lab run flows.csv files
  2. Maps lab labels to the pipeline's 6-stage taxonomy
  3. Creates session_ids from (src_ip, dst_ip, scenario_id, run)
  4. Merges with existing real_flows.csv (if it exists)
  5. Writes combined_flows.csv

Usage: python lab/merge_lab_flows.py --dataset dataset --base real_flows.csv --output combined_flows.csv
"""
import argparse
import sys
from pathlib import Path

import pandas as pd
import numpy as np

# Lab label -> pipeline stage mapping
LABEL_MAP = {
    "Benign":             "Benign",
    "Reconnaissance":     "Reconnaissance",
    "CredentialAccess":   "Reconnaissance",       # brute force -> Recon stage (matches CIC mapping)
    "InitialAccess":      "Initial Access",
    "Discovery":          "Reconnaissance",       # discovery -> Recon stage
    "LateralMovement":    "Lateral Movement",
    "CommandAndControl":  "C2",
    "Collection":         "C2",                   # collection phase -> C2 (closest match)
    "Exfiltration":       "Exfiltration",
    "Impact":             "C2",                   # DDoS/DoS -> C2 stage (matches CIC mapping)
}

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--base", default="real_flows.csv", help="Existing CIC-IDS training CSV")
    ap.add_argument("--output", default="combined_flows.csv")
    ap.add_argument("--session-len", type=int, default=12,
                    help="Flows per session for lab data (keep same scenario)")
    args = ap.parse_args()

    # ── Load lab flows ──
    lab_frames = []
    dataset_dir = Path(args.dataset)
    for run_dir in sorted(dataset_dir.glob("run_*")):
        flows_csv = run_dir / "flows.csv"
        if not flows_csv.exists():
            continue
        df = pd.read_csv(flows_csv)
        df["_run"] = run_dir.name
        lab_frames.append(df)
        print(f"  loaded {run_dir.name}: {len(df)} flows")

    if not lab_frames:
        print("ERROR: no lab flows found. Run flow extraction first.", file=sys.stderr)
        sys.exit(1)

    lab = pd.concat(lab_frames, ignore_index=True)
    print(f"\nTotal lab flows: {len(lab)}")
    print(f"Lab label distribution:\n{lab['label'].value_counts().to_string()}\n")

    # Map labels
    lab["stage_label"] = lab["label"].map(LABEL_MAP)
    unmapped = lab[lab["stage_label"].isna()]
    if len(unmapped) > 0:
        print(f"WARNING: {len(unmapped)} flows have unmapped labels: {unmapped['label'].unique()}")
        lab["stage_label"] = lab["stage_label"].fillna("Benign")

    lab["is_malicious"] = (lab["stage_label"] != "Benign").astype(int)

    # Create session IDs: group consecutive flows of the same scenario within a run
    lab = lab.sort_values(["_run", "timestamp"]).reset_index(drop=True)
    sessions = []
    for (run_id, scenario_id), group in lab.groupby(["_run", "scenario_id"]):
        n = len(group)
        n_sessions = max(1, n // args.session_len)
        session_ids = [f"lab_{run_id}_{scenario_id}_{i}" for i in range(n_sessions)
                       for _ in range(args.session_len)]
        session_ids = session_ids[:n]  # trim to exact flow count
        if len(session_ids) < n:
            session_ids += [session_ids[-1]] * (n - len(session_ids))
        sessions.extend(session_ids)
    lab["session_id"] = sessions

    # Build the pipeline-format dataframe
    lab_pipeline = lab[["session_id", "timestamp", "stage_label", "is_malicious"] + FLOW_FEATURES].copy()

    # Replace inf/nan
    lab_pipeline = lab_pipeline.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    print(f"Lab data prepared: {len(lab_pipeline)} flows, {lab_pipeline['session_id'].nunique()} sessions")
    print(f"Stage distribution:\n{lab_pipeline['stage_label'].value_counts().to_string()}\n")

    # ── Load base CIC-IDS data ──
    base_path = Path(args.base)
    if base_path.exists():
        print(f"Loading base data: {base_path}")
        base = pd.read_csv(base_path)
        print(f"  Base: {len(base)} flows, {base['session_id'].nunique()} sessions")

        # Ensure matching columns
        for col in lab_pipeline.columns:
            if col not in base.columns:
                base[col] = 0

        combined = pd.concat([base, lab_pipeline], ignore_index=True)
        print(f"\nCombined: {len(combined)} flows, {combined['session_id'].nunique()} sessions")
    else:
        print(f"No base data at {base_path} — using lab data only.")
        combined = lab_pipeline

    combined = combined.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    # ── Write output ──
    combined.to_csv(args.output, index=False)
    print(f"\nWrote {len(combined)} flows to {args.output}")
    print(f"Stage distribution in combined data:")
    print(combined["stage_label"].value_counts().to_string())


if __name__ == "__main__":
    main()
