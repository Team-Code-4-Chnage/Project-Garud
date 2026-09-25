"""
Turn each lab run's raw pcap into a labelled flows.csv, using the same flow extractor as PCAP upload and
live capture (capture/flow_table.py, verified against CICFlowMeter in docs/pcap_parity.md).

Each flow gets the 22 model features plus src/dst IP, ports, protocol and start time, and the scenario
label whose [start, end] window contains the flow's start time (from timeline.json). Flows outside every
scenario window are labelled "Benign". The raw pcap is never modified.

Run (needs scapy; can run on the lab host or the training machine):
    python lab/extract_flows.py --dataset dataset
    python lab/extract_flows.py --run dataset/run_001
"""
import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    from capture.flow_table import flows_from_pcap
except Exception as e:  # pragma: no cover
    raise SystemExit(f"cannot import the flow extractor (need scapy): {e}")

FEATURES = ["flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean", "bwd_pkt_len_mean",
            "flow_bytes_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean",
            "syn_flag_cnt", "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "urg_flag_cnt",
            "down_up_ratio", "pkt_size_avg", "ttl_variance", "tcp_win_size", "retransmit_cnt"]
PROTO = {6: "TCP", 17: "UDP", 1: "ICMP"}


def parse_iso(s):
    # timeline times are UTC; treat a naive string as UTC too, so labelling never silently shifts by the
    # local offset. Flow start times are compared as UTC epoch seconds.
    from datetime import timezone
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def label_for(ts, windows):
    for w in windows:
        if w["start"] <= ts <= w["end"]:
            return w["label"], w["scenario_id"]
    return "Benign", ""


def extract_run(run_dir):
    pcap = run_dir / "traffic.pcap"
    timeline = run_dir / "timeline.json"
    if not pcap.exists() or not timeline.exists():
        print(f"  skip {run_dir.name}: missing pcap or timeline")
        return 0
    tl = json.loads(timeline.read_text())
    windows = [dict(start=parse_iso(s["start"]), end=parse_iso(s["end"]), label=s["label"],
                    scenario_id=s["scenario_id"]) for s in tl["scenarios"]]
    flows = flows_from_pcap(str(pcap))
    out = run_dir / "flows.csv"
    counts = {}
    with open(out, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "timestamp",
                         *FEATURES, "label", "scenario_id"])
        for fl in sorted(flows, key=lambda f: f.start_time):
            label, sid = label_for(fl.start_time, windows)
            counts[label] = counts.get(label, 0) + 1
            feats = fl.to_features()
            writer.writerow([fl.src_ip, fl.src_port, fl.dst_ip, fl.dst_port, PROTO.get(fl.protocol, fl.protocol),
                             datetime.utcfromtimestamp(fl.start_time).isoformat(),
                             *[feats[f] for f in FEATURES], label, sid])
    print(f"  {run_dir.name}: {len(flows)} flows -> {out.name}  {counts}")
    return len(flows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--run", default=None, help="a single run directory instead of the whole dataset")
    args = ap.parse_args()
    if args.run:
        extract_run(Path(args.run))
        return
    runs = sorted(Path(args.dataset).glob("run_*"))
    if not runs:
        raise SystemExit(f"no run_* directories under {args.dataset}")
    total = sum(extract_run(r) for r in runs)
    print(f"done: {total} flows across {len(runs)} runs")


if __name__ == "__main__":
    main()
