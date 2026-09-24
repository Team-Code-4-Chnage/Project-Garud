"""
Network-state construction: all flows that start in one minute -> one state vector S[t].

Shared by the training-data builder (data/build_network_windows.py, from CIC-IDS2017 labelled flow
files) and the backend (backend/app/network_state.py, from flows produced by capture/flow_table.py),
so training and serving compute the state with the same code.

Input columns (one row per flow; CICFlowMeter definitions, which capture/flow_state.py reproduces):
  src, dst, sport, dport, proto, ts (flow start, datetime), dur (us), fp, bp (packets fwd/bwd),
  fb, bb (payload bytes fwd/bwd), bps, pps, iat, iat_std, syn, ack, fin, rst, psh, urg, du, pkt, win

Direction features need to know which addresses are internal. Training used the CIC testbed LAN
(192.168.0.0/16). Features that depend on that choice are listed in DIRECTION_FEATURES.
"""
import numpy as np
import pandas as pd

TRAINING_INTERNAL_PREFIXES = ("192.168.",)
RFC1918_PREFIXES = ("10.", "192.168.") + tuple(f"172.{i}." for i in range(16, 32))

DIRECTION_FEATURES = [
    "n_uniq_internal_src", "n_uniq_internal_dst", "n_inb_flow_ratio", "n_outb_flow_ratio", "n_intl_flow_ratio",
    "n_inbound_bytes", "n_outbound_bytes", "n_in_out_byte_ratio",
]
# busiest single source's share of flows: in CIC-IDS2017 every attack comes from one address (172.16.0.1)
HOST_CONCENTRATION_FEATURES = ["n_top_src_share"]


def _entropy(d, key):
    g = d.groupby(["m", key]).size()
    p = g / g.groupby(level=0).transform("sum")
    return -(p * np.log2(p)).groupby(level=0).sum()


def minute_states(d, internal_prefixes=TRAINING_INTERNAL_PREFIXES):
    """Per-minute network state (not reindexed; minutes without flows are absent). Column order is fixed."""
    d = d.replace([np.inf, -np.inf], np.nan)
    num = d.columns.difference(["src", "dst", "ts"])
    d[num] = d[num].fillna(0)
    d = d.assign(m=d["ts"].dt.floor("min"))
    d["pk"] = d["fp"] + d["bp"]
    d["by"] = d["fb"] + d["bb"]
    si = d["src"].str.startswith(internal_prefixes)
    di = d["dst"].str.startswith(internal_prefixes)
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
    # f_iat_max is the largest per-flow MEAN inter-arrival time in the minute, not CIC's Flow IAT Max
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
    out["n_uniq_src_ip"], out["n_uniq_dst_ip"] = g["src"].nunique(), g["dst"].nunique()
    out["n_uniq_src_port"], out["n_uniq_dst_port"] = g["sport"].nunique(), g["dport"].nunique()
    out["n_uniq_pairs"] = d.groupby(["m", "src", "dst"]).size().groupby(level=0).size()
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
        _entropy(d, "dport"), _entropy(d, "src"), _entropy(d, "dst"))
    out["n_top_src_share"] = d.groupby(["m", "src"]).size().groupby(level=0).max() / n
    out["n_dst_port_diversity"] = out["n_uniq_dst_port"] / n
    per_src_ports = d.groupby(["m", "src"])["dport"].nunique().groupby(level=0)
    out["n_dport_per_src_mean"], out["n_dport_per_src_max"] = per_src_ports.mean(), per_src_ports.max()
    per_src_hosts = d.groupby(["m", "src"])["dst"].nunique().groupby(level=0)
    out["n_dst_per_src_mean"], out["n_dst_per_src_max"] = per_src_hosts.mean(), per_src_hosts.max()
    out.index.name = "minute"
    return out.fillna(0)


def full_grid(states, start=None, end=None):
    """Reindex to every minute between start and end; minutes without traffic become all-zero states."""
    if len(states) == 0 and (start is None or end is None):
        return states
    start = states.index.min() if start is None else start
    end = states.index.max() if end is None else end
    return states.reindex(pd.date_range(start, end, freq="min")).fillna(0).rename_axis("minute")


def flows_from_features(rows):
    """Model-feature flow records (backend FlowRecord-like dicts: the 22 features plus src_ip, dst_ip,
    src_port, dst_port, protocol, timestamp) -> the input frame minute_states expects."""
    d = pd.DataFrame(rows)
    proto = d["protocol"].map(lambda p: {"TCP": 6, "UDP": 17, "ICMP": 1}.get(str(p).upper(), p))
    return pd.DataFrame({
        "src": d["src_ip"].astype(str), "dst": d["dst_ip"].astype(str),
        "sport": pd.to_numeric(d["src_port"], errors="coerce").fillna(0).astype(int),
        "dport": pd.to_numeric(d["dst_port"], errors="coerce").fillna(0).astype(int),
        "proto": pd.to_numeric(proto, errors="coerce").fillna(0).astype(int),
        "ts": pd.to_datetime(d["timestamp"], utc=True).dt.tz_localize(None),
        "dur": d["flow_duration"], "fp": d["tot_fwd_pkts"], "bp": d["tot_bwd_pkts"],
        "fb": d["fwd_pkt_len_mean"] * d["tot_fwd_pkts"], "bb": d["bwd_pkt_len_mean"] * d["tot_bwd_pkts"],
        "bps": d["flow_bytes_s"], "pps": d["flow_pkts_s"], "iat": d["flow_iat_mean"], "iat_std": d["flow_iat_std"],
        "syn": d["syn_flag_cnt"], "ack": d["ack_flag_cnt"], "fin": d["fin_flag_cnt"], "rst": d["rst_flag_cnt"],
        "psh": d["psh_flag_cnt"], "urg": d["urg_flag_cnt"], "du": d["down_up_ratio"], "pkt": d["pkt_size_avg"],
        "win": d["tcp_win_size"],
    })
