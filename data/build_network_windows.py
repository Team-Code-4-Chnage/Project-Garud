"""
Build 1-minute NETWORK-STATE windows from the CIC-IDS2017 labelled flows
(files from data/fetch_cic2017_labelled.py). Needs pandas + pyarrow.

Each window aggregates ALL flows whose start time falls in one minute of one
capture day, network-wide. Timestamps in these files are minute resolution
(seconds are 0 except Monday), so one minute is the finest honest window; no
sub-minute rates are invented.

Feature groups (column prefix):
  f_  flow statistics aggregated over the window (available in the old 22-feature set)
  n_  network context: counts, diversity, protocol mix, direction, rates. These
      need the IP/port/protocol/timestamp fields this dataset carries.

Raw IP identities are never emitted as features (attacker is a single IP,
172.16.0.1, so identity would be a shortcut). Only counts, entropies and ratios.

Direction: "internal" = 192.168.0.0/16 (the testbed LAN). inbound = external
source -> internal destination, outbound = the reverse, internal = both LAN.
Not available in this dataset (no such columns): TTL, retransmissions.

Labels (never features): n_mal = malicious flows in the window, behaviour =
majority attack behaviour among them (else Benign).

Run: python data/build_network_windows.py --labels-dir data/cic2017_labelled
Output: data/netwin_1min.csv.gz
"""
import argparse
import glob
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from worldmodel_v3.state import full_grid, minute_states  # noqa: E402

BEHAVIOUR = {
    "BENIGN": "Benign",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "Web Attack - Brute Force": "WebAttack", "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Bot", "Infiltration": "Infiltration", "Heartbleed": "Heartbleed",
}
COLS = ["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Timestamp",
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
        "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
        "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count",
        "URG Flag Count", "Down/Up Ratio", "Average Packet Size", "Init_Win_bytes_forward", "Label"]


def build_day(path):
    d = pd.read_parquet(path, columns=COLS)
    d.columns = ["src", "dst", "sport", "dport", "proto", "ts", "dur", "fp", "bp", "fb", "bb", "bps", "pps",
                 "iat", "iat_std", "syn", "ack", "fin", "rst", "psh", "urg", "du", "pkt", "win", "label"]
    d["label"] = d["label"].astype(object).where(d["label"].notna(), "").astype(str)
    d["label"] = d["label"].str.replace(r"[^ -~]", "-", regex=True).str.strip()
    blank = d["label"] == ""
    if blank.any():
        print(f"  dropping {int(blank.sum())} rows with a missing label in {os.path.basename(path)}")
        d = d[~blank].copy()
    d["beh"] = d["label"].map(lambda s: "WebAttack" if s.startswith("Web Attack") else BEHAVIOUR.get(s))
    assert d["beh"].notna().all(), d.loc[d["beh"].isna(), "label"].unique()
    out = minute_states(d.drop(columns=["label", "beh"]).copy())  # labels never reach the features
    m = d["ts"].dt.floor("min")
    mal = (d["beh"] != "Benign").astype(int)
    out["y_n_mal"] = mal.groupby(m).sum()
    beh = d[mal == 1].groupby(m[mal == 1])["beh"].agg(lambda s: s.value_counts().idxmax())
    out["y_behaviour"] = beh.reindex(out.index).fillna("Benign")
    out = full_grid(out)
    out["y_behaviour"] = out["y_behaviour"].replace(0, "Benign")
    out["day"] = os.path.basename(path)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels-dir", default="data/cic2017_labelled")
    ap.add_argument("--out", default="data/netwin_1min.csv.gz")
    args = ap.parse_args()
    parts = []
    for p in sorted(glob.glob(os.path.join(args.labels_dir, "*.parquet"))):
        print("building", os.path.basename(p), flush=True)
        parts.append(build_day(p))
    allw = pd.concat(parts)
    # merge the two files of the same capture day (Thu/Fri have a morning and afternoon file)
    allw["date"] = allw.index.strftime("%Y-%m-%d")
    allw = allw.drop(columns="day").reset_index().sort_values("minute")
    allw = allw.groupby("minute", as_index=False).first() if allw["minute"].duplicated().any() else allw
    allw.to_csv(args.out, index=False, compression="gzip")
    print(allw.shape, allw["date"].value_counts().sort_index().to_dict())
    print(allw["y_behaviour"].value_counts().to_dict())


if __name__ == "__main__":
    main()
