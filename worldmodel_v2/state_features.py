"""
Network-state construction for the V2 world model.

S[t] = aggregate of G consecutive flows of one session (a "state window"),
instead of a single flow. Built only from the 22 flow features that exist in
both the training data and the live pipeline. Nothing here reads labels.

Features that were requested but CANNOT be built honestly from this dataset
(CIC-IDS2017/2018 CSVs used here carry no IP, port, protocol or direction
columns, and timestamps are synthetic) are listed in UNAVAILABLE together
with the reason. They are not approximated with invented values.
"""
import numpy as np

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]
FI = {f: i for i, f in enumerate(FLOW_FEATURES)}

# retransmit_cnt is identically 0 in the training data, so its mean is dropped.
MEAN_FEATURES = [f for f in FLOW_FEATURES if f != "retransmit_cnt"]

AGG_FEATURES = [
    "total_packets", "total_bytes",
    "flow_duration_std", "flow_duration_max", "iat_mean_std", "iat_max",
    "pkt_size_std", "tcp_win_std", "ttl_var_std",
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio", "psh_ratio", "urg_ratio",
    "syn_flow_frac", "rst_flow_frac", "fin_flow_frac", "psh_flow_frac",
    "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio",
    "small_flow_ratio", "flow_shape_diversity",
]
STATE_FEATURES = ["mean_" + f for f in MEAN_FEATURES] + AGG_FEATURES
STATE_DIM = len(STATE_FEATURES)

# name: (definition/formula, inputs, train, serve)
FEATURE_DOC = {
    "mean_<flow feature>": ("Mean over the G flows of the window of each of 21 flow features "
                            "(retransmit_cnt excluded, constant 0)", "22 flow features", "yes", "yes"),
    "total_packets": ("sum(tot_fwd_pkts + tot_bwd_pkts)", "tot_fwd_pkts, tot_bwd_pkts", "yes", "yes"),
    "total_bytes": ("sum(fwd_pkt_len_mean*tot_fwd_pkts + bwd_pkt_len_mean*tot_bwd_pkts)",
                    "packet counts, mean lengths", "yes", "yes"),
    "flow_duration_std / _max": ("std / max of flow_duration across the window", "flow_duration", "yes", "yes"),
    "iat_mean_std / iat_max": ("std / max of flow_iat_mean across the window", "flow_iat_mean", "yes", "yes"),
    "pkt_size_std": ("std of pkt_size_avg across the window", "pkt_size_avg", "yes", "yes"),
    "tcp_win_std / ttl_var_std": ("std across the window", "tcp_win_size, ttl_variance", "yes",
                                  "yes (definitions differ live vs training)"),
    "<flag>_ratio": ("sum(flag count) / total_packets, for syn, ack, fin, rst, psh, urg",
                     "*_flag_cnt", "yes", "yes"),
    "<flag>_flow_frac": ("fraction of the window's flows with flag count > 0 (syn, rst, fin, psh)",
                         "*_flag_cnt", "yes", "yes"),
    "fwd_bwd_pkt_ratio / _byte_ratio": ("sum(fwd)/(sum(bwd)+1) for packets and bytes. Direction is the "
                                        "flow's forward/backward, not inbound/outbound", "packet counts, bytes",
                                        "yes", "yes"),
    "small_flow_ratio": ("fraction of flows with <= 2 packets (scan/probe signature)", "packet counts",
                         "yes", "yes"),
    "flow_shape_diversity": ("distinct (fwd pkts, bwd pkts, rounded fwd/bwd mean length) tuples / G. Proxy "
                             "for how uniform the traffic is; NOT a port count", "packet counts, lengths",
                             "yes", "yes"),
}

UNAVAILABLE = {
    "unique_source_ips / unique_destination_ips / *_internal_*":
        "training CSVs have no IP columns (one placeholder pair)",
    "unique_source_ports / unique_destination_ports / port_diversity / unique_dst_ports_per_source":
        "no port columns in the training data",
    "tcp/udp/icmp counts and ratios": "no protocol column in the training data",
    "inbound/outbound packets, bytes and their ratio": "no direction relative to the local network",
    "connection_rate / new_connection_rate":
        "timestamps are synthetic (fixed 2 s spacing), so a rate would be invented",
    "ttl_mean / ttl_std (real TTL)": "no TTL in the training data; ttl_variance there is a header-length difference",
    "retransmission_rate": "retransmit_cnt is 0 in 100% of training rows",
    "destination_diversity / source_diversity": "no IPs; flow_shape_diversity is the closest proxy",
}


def state_from_groups(g):
    """g: (n, G, 22) raw flow features -> (n, STATE_DIM) log1p-compressed states."""
    g = np.asarray(g, dtype=np.float64)
    n, G, _ = g.shape
    fwd, bwd = g[..., FI["tot_fwd_pkts"]], g[..., FI["tot_bwd_pkts"]]
    pk = fwd + bwd
    byt = g[..., FI["fwd_pkt_len_mean"]] * fwd + g[..., FI["bwd_pkt_len_mean"]] * bwd
    total_pk = pk.sum(1)
    safe = np.maximum(total_pk, 1.0)

    cols = [g[..., FI[f]].mean(1) for f in MEAN_FEATURES]
    dur, iat = g[..., FI["flow_duration"]], g[..., FI["flow_iat_mean"]]
    cols += [
        total_pk, byt.sum(1),
        dur.std(1), dur.max(1), iat.std(1), iat.max(1),
        g[..., FI["pkt_size_avg"]].std(1), g[..., FI["tcp_win_size"]].std(1),
        g[..., FI["ttl_variance"]].std(1),
    ]
    for f in ("syn", "ack", "fin", "rst", "psh", "urg"):
        cols.append(g[..., FI[f + "_flag_cnt"]].sum(1) / safe)
    for f in ("syn", "rst", "fin", "psh"):
        cols.append((g[..., FI[f + "_flag_cnt"]] > 0).mean(1))
    cols += [
        fwd.sum(1) / (bwd.sum(1) + 1.0),
        (g[..., FI["fwd_pkt_len_mean"]] * fwd).sum(1) / ((g[..., FI["bwd_pkt_len_mean"]] * bwd).sum(1) + 1.0),
        (pk <= 2).mean(1),
    ]
    shape = np.stack([fwd, bwd, np.round(g[..., FI["fwd_pkt_len_mean"]]),
                      np.round(g[..., FI["bwd_pkt_len_mean"]])], axis=-1)
    div = np.array([len({tuple(r) for r in s}) for s in shape]) / G
    cols.append(div)
    out = np.stack(cols, axis=1)
    out = np.nan_to_num(out, nan=0.0, posinf=0.0, neginf=0.0)
    return np.log1p(np.maximum(out, 0.0)).astype(np.float32)


def session_states(flows, labels_mal, labels_stage, G):
    """One session (rows already time-ordered).

    flows (n,22) raw; labels_mal (n,) 0/1; labels_stage (n,) int stage ids.
    Returns states (m,D), y_risk (m,) [any malicious flow in the window],
    y_stage (m,) [majority stage among malicious flows, else 0=Benign],
    first_flow_idx (m,) index of each window's first flow. Trailing flows
    that do not fill a window are dropped.
    """
    m = len(flows) // G
    if m == 0:
        return (np.zeros((0, STATE_DIM), np.float32), np.zeros(0, np.int64),
                np.zeros(0, np.int64), np.zeros(0, np.int64))
    g = np.asarray(flows[:m * G]).reshape(m, G, -1)
    mal = np.asarray(labels_mal[:m * G]).reshape(m, G)
    st = np.asarray(labels_stage[:m * G]).reshape(m, G)
    y_risk = (mal.sum(1) > 0).astype(np.int64)
    y_stage = np.zeros(m, dtype=np.int64)
    for i in np.where(y_risk == 1)[0]:
        vals, cnt = np.unique(st[i][mal[i] == 1], return_counts=True)
        y_stage[i] = vals[np.argmax(cnt)]
    return state_from_groups(g), y_risk, y_stage, np.arange(m) * G
