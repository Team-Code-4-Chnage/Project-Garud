"""
Packet parsing and flow assembly shared by PCAP upload and live capture.

One code path turns packets into FlowState objects so that PCAP upload, live capture
and the parity test (experiments/pcap_parity.py) cannot drift apart.

Flow rules follow CICFlowMeter, the tool that produced the training data:
  * forward direction = direction of the first packet seen for the 5-tuple
  * a flow ends after FLOW_TIMEOUT seconds from its first packet, or when a FIN or RST
    is seen (the next packet on the same 5-tuple starts a new flow)
  * flows with fewer than MIN_PACKETS packets are discarded (the CIC-IDS2017 files contain no
    single-packet flows: 0 of 445,909 on Tuesday)
"""
try:
    from .flow_state import FlowState
except ImportError:  # run as a script from inside capture/
    from flow_state import FlowState

FLOW_TIMEOUT = 120.0
MIN_PACKETS = 2


def packet_fields(pkt, count_padding=True):
    """Extract the fields FlowState needs from a Scapy packet. Returns None for non-IP packets.

    count_padding: CICFlowMeter counted Ethernet padding of short frames as payload on the CIC-IDS2017
    Wednesday, Thursday and Friday captures (every clean case checked) but not on Tuesday. The default
    follows the majority; the difference is at most 6 bytes per minimum-size frame."""
    from scapy.layers.inet import IP, TCP, UDP

    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    ip_hdr = int(ip.ihl or 5) * 4
    ip_len = int(ip.len) if ip.len else len(bytes(ip))
    # CICFlowMeter works on whole-microsecond timestamps
    f = dict(ts=int(pkt.time * 1_000_000) / 1e6, src=ip.src, dst=ip.dst, proto=int(ip.proto), ttl=int(ip.ttl),
             ip_len=ip_len, sport=0, dport=0, flags=0, win=0, seq=0, l4_hdr=0, payload=b"")
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        f.update(sport=int(tcp.sport), dport=int(tcp.dport), flags=int(tcp.flags), win=int(tcp.window),
                 seq=int(tcp.seq), l4_hdr=int(tcp.dataofs or 5) * 4)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        f.update(sport=int(udp.sport), dport=int(udp.dport), l4_hdr=8)
    # CICFlowMeter counts Ethernet padding of short frames as payload (a 60-byte frame carrying a bare ACK
    # reports 6 payload bytes), so payload = captured IP-layer bytes (padding included) minus headers.
    ip_bytes = len(bytes(ip)) if count_padding else ip_len
    f["payload_len"] = max(0, ip_bytes - ip_hdr - f["l4_hdr"])
    if f["payload_len"] and pkt.haslayer(TCP):
        f["payload"] = bytes(pkt[TCP].payload)[:f["payload_len"]]
    return f


class FlowTable:
    """Assemble packets into flows. `add` returns flows completed by this packet (FIN/RST or timeout);
    `expire(now, idle)` returns flows idle for longer than `idle` seconds; `flush` returns the rest."""

    def __init__(self, flow_timeout=FLOW_TIMEOUT, fin_terminates=True, min_packets=MIN_PACKETS):
        self.flow_timeout = flow_timeout
        self.fin_terminates = fin_terminates
        self.min_packets = min_packets
        self.active = {}
        # CICFlowMeter reports, for every non-TCP packet, the header length of the last TCP packet it parsed
        # (stale parser state). Reproduced so UDP "Fwd/Bwd Header Length" match the training data:
        # 196 of 196 UDP flows agreed in the parity test. It carries no information about the UDP packet.
        self.last_tcp_hdr = 0

    def _keep(self, flows):
        return [fl for fl in flows if fl.packet_count >= self.min_packets]

    @staticmethod
    def _key(f):
        a, b = (f["src"], f["sport"]), (f["dst"], f["dport"])
        return (a, b, f["proto"]) if a <= b else (b, a, f["proto"])

    def add(self, f):
        done = []
        key = self._key(f)
        flow = self.active.get(key)
        if flow is not None and self.flow_timeout and f["ts"] - flow.start_time > self.flow_timeout:
            done.append(self.active.pop(key))
            flow = None
        if flow is None:
            flow = FlowState(src_ip=f["src"], dst_ip=f["dst"], src_port=f["sport"], dst_port=f["dport"],
                                   protocol=f["proto"])
            self.active[key] = flow
        is_fwd = (f["src"], f["sport"]) == (flow.src_ip, flow.src_port)
        if f["proto"] == 6:
            self.last_tcp_hdr = f["l4_hdr"]
        flow.add_packet(pkt_len=f["payload_len"], is_forward=is_fwd, timestamp=f["ts"], tcp_flags=f["flags"],
                        ttl=f["ttl"], tcp_win=f["win"], seq=f["seq"], payload=f["payload"],
                        hdr_len=self.last_tcp_hdr)  # CICFlowMeter header length (TCP header bytes; see above)
        if self.fin_terminates and f["flags"] & 0x05:  # FIN or RST
            flow.terminated = True
            done.append(self.active.pop(key))
        return self._keep(done)

    def expire(self, now, idle):
        keys = [k for k, fl in self.active.items() if now - fl.last_time > idle]
        return self._keep([self.active.pop(k) for k in keys])

    def flush(self):
        out = list(self.active.values())
        self.active.clear()
        return self._keep(out)


def flows_from_pcap(path, count_padding=True, **table_kwargs):
    """All flows of a capture file (pcap or pcapng), in completion order."""
    import scapy.layers.inet  # noqa: F401  layer bindings must be loaded before packets are dissected
    import scapy.layers.l2  # noqa: F401
    from scapy.utils import PcapReader

    table = FlowTable(**table_kwargs)
    out = []
    with PcapReader(path) as reader:
        for pkt in reader:
            f = packet_fields(pkt, count_padding)
            if f is not None:
                out.extend(table.add(f))
    out.extend(table.flush())
    return out
