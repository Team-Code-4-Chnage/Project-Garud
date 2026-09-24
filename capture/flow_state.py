"""
Shared FlowState: bidirectional flow reconstruction and the 22 model features.

Used identically by capture/live_capture.py and backend/app/routes/pcap.py (both through
capture/flow_table.py).

`to_features()` reproduces the features the model was TRAINED on, i.e. CICFlowMeter's output as
transformed by data/preprocess_cicids.py. Parity against the official CIC-IDS2017 flow files is
measured by experiments/pcap_parity.py. Consequences of matching training exactly:
  * packet lengths are transport payload bytes, not IP lengths
  * `ttl_variance` is |forward header bytes - backward header bytes|. That is what the training
    column contains (the CIC files have no TTL). The name is historical; it is not TTL.
  * `tcp_win_size` is the TCP window of the first forward packet (CIC Init_Win_bytes_forward), -1 if not TCP
  * `pkt_size_avg` counts the first packet's payload twice, as CICFlowMeter does
  * timestamps are truncated to whole microseconds (capture/flow_table.py)
  * `retransmit_cnt` is 0: training derived it as Total Fwd Packets - Subflow Fwd Packets, which is
    0 in every training row

Real packet-level measurements (TTL statistics, retransmissions, payload size distribution) are
kept separately in `packet_features()`. They are not model inputs until a model is trained on them.
"""
from dataclasses import dataclass, field

import numpy as np

try:
    from .signatures import detect_heartbleed
except ImportError:
    from signatures import detect_heartbleed


def _us(seconds):
    """Interval in whole microseconds (CICFlowMeter uses integer microsecond timestamps; float seconds near
    the epoch lose about 0.24 us of precision, so intervals are rounded back)."""
    return float(round(seconds * 1e6))


def _mean(x):
    return float(np.mean(x)) if len(x) else 0.0


def _std(x):
    # CICFlowMeter uses Apache Commons SummaryStatistics: sample standard deviation (n - 1)
    return float(np.std(x, ddof=1)) if len(x) > 1 else 0.0


@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6

    start_time: float = 0.0
    last_time: float = 0.0

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    fwd_pkt_lengths: list = field(default_factory=list)
    bwd_pkt_lengths: list = field(default_factory=list)

    fwd_iats: list = field(default_factory=list)
    bwd_iats: list = field(default_factory=list)
    flow_iats: list = field(default_factory=list)

    last_fwd_time: float = 0.0
    last_bwd_time: float = 0.0
    last_pkt_time: float = 0.0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    fwd_hdr_bytes: int = 0
    bwd_hdr_bytes: int = 0
    init_win_fwd: int = 0

    ttl_values: list = field(default_factory=list)
    tcp_win_sizes: list = field(default_factory=list)

    _seen_seqs: set = field(default_factory=set)
    retransmit_count: int = 0
    packet_count: int = 0

    heartbleed_detected: bool = False
    first_flags: int = 0
    first_payload_len: int = 0
    terminated: bool = False

    def add_packet(
        self,
        pkt_len: int,
        is_forward: bool,
        timestamp: float,
        tcp_flags: int = 0,
        ttl: int = 64,
        tcp_win: int = 0,
        seq: int = 0,
        payload: bytes = b"",
        hdr_len: int = 0,
    ):
        """pkt_len is the transport payload length in bytes; hdr_len the header bytes counted by CICFlowMeter."""
        if self.packet_count == 0:
            self.first_flags = tcp_flags
            self.first_payload_len = pkt_len
            self.start_time = timestamp
            self.last_pkt_time = timestamp
            self.last_fwd_time = timestamp
            self.last_bwd_time = timestamp

        self.last_time = timestamp
        self.packet_count += 1

        if self.packet_count > 1:
            self.flow_iats.append(max(0.0, _us(timestamp - self.last_pkt_time)))
        self.last_pkt_time = timestamp

        if is_forward:
            if self.fwd_packets == 0:
                self.init_win_fwd = tcp_win
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            self.fwd_hdr_bytes += hdr_len
            self.fwd_pkt_lengths.append(pkt_len)
            if self.fwd_packets > 1:
                self.fwd_iats.append(max(0.0, _us(timestamp - self.last_fwd_time)))
            self.last_fwd_time = timestamp
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            self.bwd_hdr_bytes += hdr_len
            self.bwd_pkt_lengths.append(pkt_len)
            if self.bwd_packets > 1:
                self.bwd_iats.append(max(0.0, _us(timestamp - self.last_bwd_time)))
            self.last_bwd_time = timestamp

        if tcp_flags:
            if tcp_flags & 0x02:
                self.syn_count += 1
            if tcp_flags & 0x10:
                self.ack_count += 1
            if tcp_flags & 0x01:
                self.fin_count += 1
            if tcp_flags & 0x04:
                self.rst_count += 1
            if tcp_flags & 0x08:
                self.psh_count += 1
            if tcp_flags & 0x20:
                self.urg_count += 1

        self.ttl_values.append(ttl)
        if tcp_win > 0:
            self.tcp_win_sizes.append(tcp_win)
        if seq > 0 and pkt_len > 0:
            if (is_forward, seq) in self._seen_seqs:
                self.retransmit_count += 1
            else:
                self._seen_seqs.add((is_forward, seq))

        if payload and not self.heartbleed_detected:
            self.heartbleed_detected = detect_heartbleed(payload)

    def to_features(self) -> dict:
        """The 22 model features, defined as in the training data (see module docstring)."""
        duration_us = max(0.0, _us(self.last_time - self.start_time))
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts = self.fwd_packets + self.bwd_packets
        sec = duration_us / 1e6
        # CICFlowMeter divides by zero for single-timestamp flows (Infinity/NaN); training replaced those with 0
        return {
            "flow_duration": duration_us,
            "tot_fwd_pkts": float(self.fwd_packets),
            "tot_bwd_pkts": float(self.bwd_packets),
            "fwd_pkt_len_mean": _mean(self.fwd_pkt_lengths),
            "bwd_pkt_len_mean": _mean(self.bwd_pkt_lengths),
            "flow_bytes_s": float(total_bytes / sec) if sec > 0 else 0.0,
            "flow_pkts_s": float(total_pkts / sec) if sec > 0 else 0.0,
            "flow_iat_mean": _mean(self.flow_iats),
            "flow_iat_std": _std(self.flow_iats),
            "fwd_iat_mean": _mean(self.fwd_iats),
            "bwd_iat_mean": _mean(self.bwd_iats),
            # CICFlowMeter's "<X> Flag Count" columns are 0/1 values taken from the flow's FIRST packet, with
            # SYN and PSH swapped (measured against the official CIC-IDS2017 files, experiments/pcap_parity.py):
            # ACK column = first packet ACK bit (100% agreement), PSH column = first packet SYN bit (100%),
            # SYN column = first packet PSH bit (97%). URG never matched a packet bit; 0 agrees 90% of the time.
            # FIN and RST use the first packet's own bit; not yet confirmed (no non-zero case observed so far).
            # Real per-packet flag counts are in self.<flag>_count and are not model inputs.
            "syn_flag_cnt": float(bool(self.first_flags & 0x08)),
            "ack_flag_cnt": float(bool(self.first_flags & 0x10)),
            "fin_flag_cnt": float(bool(self.first_flags & 0x01)),
            "rst_flag_cnt": float(bool(self.first_flags & 0x04)),
            "psh_flag_cnt": float(bool(self.first_flags & 0x02)),
            "urg_flag_cnt": 0.0,
            "down_up_ratio": float(self.bwd_packets // self.fwd_packets) if self.fwd_packets else 0.0,
            # CICFlowMeter adds the first packet's payload to its length statistics twice
            "pkt_size_avg": float((total_bytes + self.first_payload_len) / total_pkts) if total_pkts else 0.0,
            "ttl_variance": float(abs(self.fwd_hdr_bytes - self.bwd_hdr_bytes)),
            "tcp_win_size": float(self.init_win_fwd) if self.protocol == 6 else -1.0,  # CIC writes -1 without TCP
            "retransmit_cnt": 0.0,
        }

    def packet_features(self) -> dict:
        """Genuine packet-level measurements. Not model inputs (the training data has none of them)."""
        lens = self.fwd_pkt_lengths + self.bwd_pkt_lengths
        return {
            "ttl_mean": _mean(self.ttl_values),
            "ttl_variance_real": float(np.var(self.ttl_values)) if len(self.ttl_values) > 1 else 0.0,
            "retransmissions": float(self.retransmit_count),
            "payload_len_std": float(np.std(lens)) if len(lens) > 1 else 0.0,
            "payload_len_max": float(max(lens)) if lens else 0.0,
            "zero_payload_frac": float(np.mean([x == 0 for x in lens])) if lens else 0.0,
        }
