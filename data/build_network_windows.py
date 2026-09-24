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

import numpy as np
import pandas as pd

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


def entropy(df, key):
    g = df.groupby(["m", key]).size()
    p = g / g.groupby(level=0).transform("sum")
    return -(p * np.log2(p)).groupby(level=0).sum()


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
    d = d.replace([np.inf, -np.inf], np.nan).fillna(0)
    d["m"] = d["ts"].dt.floor("min")
    d["pk"] = d["fp"] + d["bp"]
    d["by"] = d["fb"] + d["bb"]
    d["mal"] = (d["beh"] != "Benign").astype(int)
    si = d["src"].str.startswith("192.168.")
    di = d["dst"].str.startswith("192.168.")
    d["inb"], d["outb"], d["intl"] = (~si & di), (si & ~di), (si & di)
    d["tcp"], d["udp"], d["icmp"] = d["proto"] == 6, d["proto"] == 17, d["proto"] == 1
    d["synf"], d["rstf"], d["small"] = d["syn"] > 0, d["rst"] > 0, d["pk"] <= 2
    d["si_col"], d["di_col"] = d["src"].where(si), d["dst"].where(di)
    g = d.groupby("m")
    out = pd.DataFrame(index=g.size().index)
    n = g.size()
    out["n_flows"] = n
    tp = g["pk"].sum().clip(lower=1)
    out["f_total_packets"], out["f_total_bytes"] = g["pk"].sum(), g["by"].sum()
    out["f_dur_mean"], out["f_dur_std"], out["f_dur_max"] = g["dur"].mean(), g["dur"].std(), g["dur"].max()
    out["f_iat_mean"], out["f_iat_max"], out["f_iat_mean_std"] = g["iat"].mean(), g["iat"].max(), g["iat"].std()
    out["f_iat_std_mean"] = g["iat_std"].mean()
    out["f_pps_mean"], out["f_bps_mean"] = g["pps"].mean(), g["bps"].mean()
    out["f_pkt_size_mean"], out["f_pkt_size_std"] = g["pkt"].mean(), g["pkt"].std()
    out["f_down_up_mean"] = g["du"].mean()
    out["f_tcp_win_mean"], out["f_tcp_win_std"] = g["win"].mean(), g["win"].std()
    for f in ("syn", "ack", "fin", "rst", "psh", "urg"):
        out[f"f_{f}_ratio"] = g[f].sum() / tp
    for f in ("synf", "rstf", "small"):
        out[f"f_{f}_flow_frac"] = g[f].mean()
    # ---- network context ----
    out["n_uniq_src_ip"], out["n_uniq_dst_ip"] = g["src"].nunique(), g["dst"].nunique()
    out["n_uniq_src_port"], out["n_uniq_dst_port"] = g["sport"].nunique(), g["dport"].nunique()
    out["n_uniq_pairs"] = d.groupby(["m", "src", "dst"]).ngroups and d.groupby(["m", "src", "dst"]).size() \
        .groupby(level=0).size()
    out["n_uniq_internal_src"], out["n_uniq_internal_dst"] = g["si_col"].nunique(), g["di_col"].nunique()
    for f in ("tcp", "udp", "icmp"):
        out[f"n_{f}_ratio"] = g[f].mean()
    out["n_other_proto_ratio"] = 1 - out[["n_tcp_ratio", "n_udp_ratio", "n_icmp_ratio"]].sum(axis=1)
    for f in ("inb", "outb", "intl"):
        out[f"n_{f}_flow_ratio"] = g[f].mean()
    ib = d["by"].where(d["inb"], 0).groupby(d["m"]).sum()
    ob = d["by"].where(d["outb"], 0).groupby(d["m"]).sum()
    out["n_inbound_bytes"], out["n_outbound_bytes"] = ib, ob
    out["n_in_out_byte_ratio"] = ib / (ob + 1.0)
    out["n_conn_rate"] = n / 60.0
    out["n_new_conn_rate"] = g["synf"].sum() / 60.0
    out["n_ent_dst_port"], out["n_ent_src_ip"], out["n_ent_dst_ip"] = (
        entropy(d, "dport"), entropy(d, "src"), entropy(d, "dst"))
    out["n_top_src_share"] = d.groupby(["m", "src"]).size().groupby(level=0).max() / n
    out["n_dst_port_diversity"] = out["n_uniq_dst_port"] / n
    per_src_ports = d.groupby(["m", "src"])["dport"].nunique().groupby(level=0)
    out["n_dport_per_src_mean"], out["n_dport_per_src_max"] = per_src_ports.mean(), per_src_ports.max()
    per_src_hosts = d.groupby(["m", "src"])["dst"].nunique().groupby(level=0)
    out["n_dst_per_src_mean"], out["n_dst_per_src_max"] = per_src_hosts.mean(), per_src_hosts.max()
    # ---- labels (never features) ----
    out["y_n_mal"] = g["mal"].sum()
    mal = d[d["mal"] == 1]
    beh = mal.groupby("m")["beh"].agg(lambda s: s.value_counts().idxmax())
    out["y_behaviour"] = beh.reindex(out.index).fillna("Benign")
    out = out.fillna(0)
    # reindex to the full minute grid; empty minutes become an all-zero "no traffic" state
    grid = pd.date_range(out.index.min(), out.index.max(), freq="min")
    out = out.reindex(grid)
    out["y_behaviour"] = out["y_behaviour"].fillna("Benign")
    out = out.fillna(0)
    out["day"] = os.path.basename(path)
    out.index.name = "minute"
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
