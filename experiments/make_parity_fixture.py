"""
Cut a small real-traffic regression fixture for backend/tests/test_pcap_parity_real.py.

Selects complete TCP flows (SYN and FIN/RST inside the capture, not crossing a capture boundary) from a
CIC-IDS2017 capture slice, writes only their packets to a pcap and the matching official label rows to a
CSV. TCP only: CICFlowMeter's UDP header bytes depend on the preceding TCP packet in the full capture,
which a subset cannot preserve.

Run: python experiments/make_parity_fixture.py --pcap thu_web.pcapng
         --labels Thursday-WorkingHours-Morning-WebAttacks.parquet --attack 12 --benign 12
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
from capture.flow_table import flows_from_pcap  # noqa: E402
from pcap_parity import match  # noqa: E402

KEEP_COLS = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp",
             "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Fwd Packet Length Mean",
             "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
             "Fwd IAT Mean", "Bwd IAT Mean", "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count",
             "PSH Flag Count", "URG Flag Count", "Down/Up Ratio", "Average Packet Size", "Fwd Header Length",
             "Bwd Header Length", "Init_Win_bytes_forward", "Subflow Fwd Packets", "Label"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--attack", type=int, default=12)
    ap.add_argument("--benign", type=int, default=12)
    ap.add_argument("--out-dir", default=str(ROOT / "backend" / "tests" / "fixtures"))
    args = ap.parse_args()

    import scapy.layers.inet  # noqa: F401  load layer bindings before dissecting
    import scapy.layers.l2  # noqa: F401
    from scapy.utils import PcapReader, wrpcap
    with PcapReader(args.pcap) as r:
        pkts = list(r)
    t0, t1 = float(min(p.time for p in pkts)), float(max(p.time for p in pkts))
    labels = pd.read_parquet(args.labels).dropna(subset=["Timestamp"])
    lo = pd.Timestamp(t0, unit="s").floor("min") - pd.Timedelta(minutes=3)
    labels = labels[(labels["Timestamp"] >= lo) & (labels["Timestamp"] <= pd.Timestamp(t1, unit="s").ceil("min"))]

    flows = [fl for fl in flows_from_pcap(args.pcap) if fl.protocol == 6]
    by_id = {id(fl): fl for fl in flows}
    rows, *_ = match(flows, labels, t0, t1, lambda fl: dict(fl.to_features(), _id=id(fl)))
    exact = [(m, t, lab) for m, t, _, lab in rows
             if m["tot_fwd_pkts"] == t["tot_fwd_pkts"] and m["tot_bwd_pkts"] == t["tot_bwd_pkts"]]
    attack = [r for r in exact if r[2] != "BENIGN"][:args.attack]
    benign = [r for r in exact if r[2] == "BENIGN"][:args.benign]
    chosen = [by_id[m["_id"]] for m, _, _ in attack + benign]
    keys = {(fl.src_ip, fl.src_port, fl.dst_ip, fl.dst_port) for fl in chosen}
    spans = {k: (fl.start_time, fl.last_time) for fl in chosen for k in [(fl.src_ip, fl.src_port, fl.dst_ip, fl.dst_port)]}

    from scapy.layers.inet import IP, TCP
    keep = []
    for p in pkts:
        if not (p.haslayer(IP) and p.haslayer(TCP)):
            continue
        ip, tcp = p[IP], p[TCP]
        for k in ((ip.src, int(tcp.sport), ip.dst, int(tcp.dport)), (ip.dst, int(tcp.dport), ip.src, int(tcp.sport))):
            if k in keys and spans[k][0] - 1e-6 <= float(p.time) <= spans[k][1] + 1e-6:
                keep.append(p)
                break
    out = Path(args.out_dir)
    wrpcap(str(out / "cic2017_parity.pcap"), keep)

    lab = labels.copy()
    sel = []
    for fl in chosen:
        g = lab[(lab["Source IP"] == fl.src_ip) & (lab["Source Port"] == fl.src_port) &
                (lab["Destination IP"] == fl.dst_ip) & (lab["Destination Port"] == fl.dst_port) &
                (lab["Total Fwd Packets"] == fl.fwd_packets) & (lab["Total Backward Packets"] == fl.bwd_packets)]
        sel.append(g.iloc[[0]])
    rows_df = pd.concat(sel)[KEEP_COLS]
    rows_df["Label"] = rows_df["Label"].str.replace(r"[^\x20-\x7e]", "-", regex=True)
    rows_df.to_csv(out / "cic2017_parity_labels.csv", index=False)
    print(f"wrote {len(keep)} packets, {len(rows_df)} flows ({len(attack)} attack, {len(benign)} benign) to {out}")


if __name__ == "__main__":
    main()
