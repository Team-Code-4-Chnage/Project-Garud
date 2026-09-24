"""
PCAP feature parity: do features computed by our extractor from a raw CIC-IDS2017 capture match the
features the model was trained on (CICFlowMeter output, as transformed by data/preprocess_cicids.py)?

Ground truth is the official labelled flow file for the same day (Flow ID, IPs, ports, protocol,
minute timestamp, CICFlowMeter columns). Each extracted flow is matched to a labelled flow with the
same 5-tuple (either direction) starting in the same UTC minute; among several candidates the one
with the closest packet count, then duration, is used. Only flows that start at least 2 s after the
first packet and end at least 2 s before the last packet of the capture are compared, so flows cut
by the capture boundaries are not counted against the extractor: flows whose labelled duration runs past
the end of the capture, and flows whose 5-tuple already had a labelled flow open when the capture began
(CICFlowMeter would have appended the packets to it), are skipped and counted. TCP flows must also open with a SYN (without ACK) and
close with a FIN or RST inside the capture (otherwise part of the real flow lies outside the slice).

Modes:
  current : production extractor (capture/flow_table.py + capture/flow_state.py)
  legacy  : the extractor as it was at commit 6409c0b (sorted direction, no flow termination,
            IP length, 10 ms duration floor), reproduced here only to report a before/after

Needs pandas, pyarrow and scapy.
Run: python experiments/pcap_parity.py --pcap tue.pcapng --labels Tuesday-WorkingHours.parquet
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_bytes_s",
    "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "urg_flag_cnt", "down_up_ratio",
    "pkt_size_avg", "ttl_variance", "tcp_win_size", "retransmit_cnt",
]
CIC = {
    "flow_duration": "Flow Duration", "tot_fwd_pkts": "Total Fwd Packets", "tot_bwd_pkts": "Total Backward Packets",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean", "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "flow_bytes_s": "Flow Bytes/s", "flow_pkts_s": "Flow Packets/s", "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std", "fwd_iat_mean": "Fwd IAT Mean", "bwd_iat_mean": "Bwd IAT Mean",
    "syn_flag_cnt": "SYN Flag Count", "ack_flag_cnt": "ACK Flag Count", "fin_flag_cnt": "FIN Flag Count",
    "rst_flag_cnt": "RST Flag Count", "psh_flag_cnt": "PSH Flag Count", "urg_flag_cnt": "URG Flag Count",
    "down_up_ratio": "Down/Up Ratio", "pkt_size_avg": "Average Packet Size",
}


def training_features(row):
    """The 22 model features exactly as data/preprocess_cicids.py derives them from CICFlowMeter columns."""
    out = {k: float(row[c]) for k, c in CIC.items()}
    out["ttl_variance"] = abs(float(row["Fwd Header Length"]) - float(row["Bwd Header Length"]))
    out["tcp_win_size"] = float(row["Init_Win_bytes_forward"])
    out["retransmit_cnt"] = max(0.0, float(row["Total Fwd Packets"]) - float(row["Subflow Fwd Packets"]))
    return {k: (0.0 if not np.isfinite(v) else v) for k, v in out.items()}


def legacy_flows(path):
    """Commit 6409c0b behaviour of backend/app/routes/pcap.py, for the before/after comparison only."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.utils import PcapReader

    from capture.flow_state import FlowState
    flows = {}
    with PcapReader(path) as r:
        for pkt in r:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            sp = dp = flags = win = seq = 0
            if pkt.haslayer(TCP):
                t = pkt[TCP]
                sp, dp, flags, win, seq = int(t.sport), int(t.dport), int(t.flags), int(t.window), int(t.seq)
            elif pkt.haslayer(UDP):
                sp, dp = int(pkt[UDP].sport), int(pkt[UDP].dport)
            fwd = (ip.src, sp) <= (ip.dst, dp)
            key = (ip.src, sp, ip.dst, dp, ip.proto) if fwd else (ip.dst, dp, ip.src, sp, ip.proto)
            if key not in flows:
                flows[key] = FlowState(src_ip=key[0], src_port=key[1], dst_ip=key[2], dst_port=key[3],
                                       protocol=int(ip.proto))
            flows[key].add_packet(pkt_len=int(ip.len) if ip.len else len(pkt), is_forward=fwd,
                                  timestamp=float(pkt.time), tcp_flags=flags, ttl=int(ip.ttl), tcp_win=win, seq=seq)
    out = list(flows.values())
    for fl in out:  # same eligibility rule as the current extractor: saw a FIN or RST
        fl.terminated = bool(fl.fin_count or fl.rst_count)
    return out


def legacy_features(fl):
    """Old FlowState.to_features semantics (10 ms floor, IP length, mean window, real TTL variance)."""
    dur = (fl.last_time - fl.start_time) * 1e6
    sec, dur_us = max(dur / 1e6, 0.01), max(dur, 10000.0)
    lens = fl.fwd_pkt_lengths + fl.bwd_pkt_lengths
    tot = fl.fwd_packets + fl.bwd_packets
    m = lambda x: float(np.mean(x)) if len(x) else 0.0  # noqa: E731
    return {
        "flow_duration": dur_us, "tot_fwd_pkts": float(fl.fwd_packets), "tot_bwd_pkts": float(fl.bwd_packets),
        "fwd_pkt_len_mean": m(fl.fwd_pkt_lengths), "bwd_pkt_len_mean": m(fl.bwd_pkt_lengths),
        "flow_bytes_s": sum(lens) / sec, "flow_pkts_s": tot / sec, "flow_iat_mean": m(fl.flow_iats),
        "flow_iat_std": float(np.std(fl.flow_iats)) if len(fl.flow_iats) > 1 else 0.0,
        "fwd_iat_mean": m(fl.fwd_iats), "bwd_iat_mean": m(fl.bwd_iats),
        "syn_flag_cnt": float(fl.syn_count), "ack_flag_cnt": float(fl.ack_count), "fin_flag_cnt": float(fl.fin_count),
        "rst_flag_cnt": float(fl.rst_count), "psh_flag_cnt": float(fl.psh_count), "urg_flag_cnt": float(fl.urg_count),
        "down_up_ratio": fl.bwd_packets / max(fl.fwd_packets, 1), "pkt_size_avg": sum(lens) / max(tot, 1),
        "ttl_variance": float(np.var(fl.ttl_values)) if len(fl.ttl_values) > 1 else 0.0,
        "tcp_win_size": m(fl.tcp_win_sizes), "retransmit_cnt": float(fl.retransmit_count),
    }


def match(flows, labels, t0, t1, featurize):
    lab = labels.copy()
    lab["minute"] = lab["Timestamp"].dt.floor("min")
    lab["k"] = [tuple(sorted([(a, int(b)), (c, int(d))])) + (int(p),) for a, b, c, d, p in
                zip(lab["Source IP"], lab["Source Port"], lab["Destination IP"], lab["Destination Port"], lab["Protocol"])]
    by = {k: g for k, g in lab.groupby("k")}
    start_min = pd.Timestamp(t0, unit="s").floor("min")
    # a labelled flow on the same 5-tuple that began before the capture and may still have been open at its start
    open_before = {k for k, g in by.items()
                   if ((g["minute"] < start_min) &
                       (g["minute"] + pd.to_timedelta(g["Flow Duration"], unit="us") + pd.Timedelta(minutes=1)
                        >= pd.Timestamp(t0, unit="s"))).any()}
    rows, unmatched, direction_ok, boundary = [], 0, 0, 0
    for fl in flows:
        if int(fl.protocol) != 6 and (fl.start_time < t0 + 2 or fl.last_time > t1 - 2):
            continue  # non-TCP flows have no open/close markers; keep them away from the capture edges
        if int(fl.protocol) == 6 and not ((getattr(fl, "first_flags", 0x02) & 0x12) == 0x02 and getattr(fl, "terminated", True)):
            continue  # TCP flow not both opened (SYN) and closed (FIN/RST) inside the capture
        k = tuple(sorted([(fl.src_ip, fl.src_port), (fl.dst_ip, fl.dst_port)])) + (int(fl.protocol),)
        if k in open_before:
            boundary += 1
            continue  # CICFlowMeter may have appended these packets to a flow that began before the capture
        g = by.get(k)
        minute = pd.Timestamp(fl.start_time, unit="s").floor("min")
        if g is not None:
            g = g[g["minute"] == minute]
        if g is None or len(g) == 0:
            unmatched += 1
            continue
        mine = featurize(fl)
        npk = mine["tot_fwd_pkts"] + mine["tot_bwd_pkts"]
        g = g.assign(_d1=(g["Total Fwd Packets"] + g["Total Backward Packets"] - npk).abs(),
                     _d2=(g["Flow Duration"] - mine["flow_duration"]).abs()).sort_values(["_d1", "_d2"])
        row = g.iloc[0]
        if fl.start_time + float(row["Flow Duration"]) / 1e6 > t1 - 1:
            boundary += 1
            continue  # the labelled flow runs past the end of the capture, so it cannot be complete here
        direction_ok += int(row["Source IP"] == fl.src_ip and int(row["Source Port"]) == fl.src_port)
        rows.append((mine, training_features(row), int(fl.protocol), str(row["Label"]),
                     dict(src=fl.src_ip, dst=fl.dst_ip, start=fl.start_time)))
    return rows, unmatched, direction_ok, boundary


def agreement(rows, rtol=0.01):
    out = {}
    for f in FEATURES:
        a = np.array([r[0][f] for r in rows])
        b = np.array([r[1][f] for r in rows])
        ok = np.isclose(a, b, rtol=rtol, atol=1e-6)
        rel = np.abs(a - b) / np.maximum(np.abs(b), 1e-9)
        out[f] = dict(agree=float(ok.mean()), median_rel_err=float(np.median(rel)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--labels", required=True, help="labelled flow parquet for the same capture day")
    ap.add_argument("--mode", choices=["current", "legacy", "both"], default="both")
    ap.add_argument("--out", default=None)
    ap.add_argument("--dump", default=None, help="CSV of matched flows (pcap and csv features) for model-level parity")
    ap.add_argument("--no-padding", action="store_true",
                    help="do not count Ethernet padding as payload (CIC-IDS2017 Tuesday was processed this way)")
    ap.add_argument("--debug", default="", help="comma list of features: print mismatches on exact-count flows")
    ap.add_argument("--debug-label", default="", help="restrict --debug output to labels containing this text")
    args = ap.parse_args()

    import scapy.layers.inet  # noqa: F401  load layer bindings before dissecting
    import scapy.layers.l2  # noqa: F401
    from scapy.utils import PcapReader
    with PcapReader(args.pcap) as r:
        ts = [float(p.time) for p in r]
    t0, t1 = min(ts), max(ts)
    labels = pd.read_parquet(args.labels)
    labels = labels.dropna(subset=["Timestamp"])
    lo, hi = pd.Timestamp(t0, unit="s").floor("min") - pd.Timedelta(minutes=3), pd.Timestamp(t1, unit="s").ceil("min")
    labels = labels[(labels["Timestamp"] >= lo) & (labels["Timestamp"] <= hi)]
    print(f"capture {pd.Timestamp(t0, unit='s')} .. {pd.Timestamp(t1, unit='s')} UTC ({t1 - t0:.1f} s, {len(ts)} packets); "
          f"labelled flows in range: {len(labels)}")

    result = {}
    modes = ["legacy", "current"] if args.mode == "both" else [args.mode]
    for mode in modes:
        if mode == "legacy":
            flows, feat = legacy_flows(args.pcap), legacy_features
        else:
            from capture.flow_table import flows_from_pcap
            flows, feat = flows_from_pcap(args.pcap, count_padding=not args.no_padding), (lambda fl: fl.to_features())
        rows, unmatched, dir_ok, boundary = match(flows, labels, t0, t1, feat)
        ag = agreement(rows)
        exact_pk = np.mean([m["tot_fwd_pkts"] == t["tot_fwd_pkts"] and m["tot_bwd_pkts"] == t["tot_bwd_pkts"]
                            for m, t, *_ in rows]) if rows else 0.0
        if args.dump and mode == "current":
            recs = []
            for m, t, _, lab_, meta in rows:
                recs.append({**meta, "label": lab_, **{f"pcap_{k}": v for k, v in m.items()},
                             **{f"csv_{k}": v for k, v in t.items()}})
            pd.DataFrame(recs).to_csv(args.dump, index=False)
        if args.debug:
            for m, t, pr, lab_, _meta in rows:
                if args.debug_label and args.debug_label not in lab_:
                    continue
                if m["tot_fwd_pkts"] != t["tot_fwd_pkts"] or m["tot_bwd_pkts"] != t["tot_bwd_pkts"]:
                    print("   count mismatch", lab_, "ours", m["tot_fwd_pkts"], m["tot_bwd_pkts"], "label",
                          t["tot_fwd_pkts"], t["tot_bwd_pkts"])
                    continue
                bad = {f: (round(m[f], 3), round(t[f], 3)) for f in args.debug.split(",")
                       if not np.isclose(m[f], t[f], rtol=0.01, atol=1e-6)}
                if bad:
                    print("   proto", pr, "fwd/bwd", m["tot_fwd_pkts"], m["tot_bwd_pkts"], "ours/label", bad)
        result[mode] = dict(flows=len(flows), compared=len(rows), unmatched=unmatched, boundary_skipped=boundary,
                            direction_agrees=dir_ok / max(len(rows), 1), packet_counts_exact=float(exact_pk),
                            features=ag, mean_agreement=float(np.mean([v["agree"] for v in ag.values()])))
        print(f"\n== {mode}: {len(flows)} flows, {len(rows)} compared, {unmatched} unmatched, "
              f"{boundary} skipped (flow crosses a capture boundary), direction agrees {dir_ok / max(len(rows), 1):.1%}, exact packet counts {exact_pk:.1%}")
        for f, v in ag.items():
            print(f"  {f:<18} agree(1%) {v['agree']:6.1%}   median rel err {v['median_rel_err']:.3g}")
        print(f"  mean agreement across 22 features: {result[mode]['mean_agreement']:.1%}")
        for name, sel in (("benign", lambda l: l == "BENIGN"), ("attack", lambda l: l != "BENIGN")):
            sub = [r for r in rows if sel(r[3])]
            if sub:
                a = agreement(sub)
                result[mode][f"mean_agreement_{name}"] = float(np.mean([v["agree"] for v in a.values()]))
                labels_seen = sorted({r[3] for r in sub})
                print(f"  {name}: {len(sub)} flows {labels_seen if name == 'attack' else ''} "
                      f"mean agreement {result[mode][f'mean_agreement_{name}']:.1%}")
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
