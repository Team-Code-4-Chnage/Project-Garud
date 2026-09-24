"""
Flow assembly and feature rules that reproduce CICFlowMeter, the tool that produced the training data.
Each rule was measured against the official CIC-IDS2017 flow files (experiments/pcap_parity.py).
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from capture.flow_table import FlowTable  # noqa: E402


def pkt(ts, src, sport, dst, dport, flags=0x10, payload=0, proto=6, win=1000, l4=20):
    return dict(ts=ts, src=src, dst=dst, sport=sport, dport=dport, proto=proto, ttl=64, ip_len=20 + l4 + payload,
                flags=flags, win=win, seq=1, l4_hdr=l4, payload_len=payload, payload=b"")


C, S = ("10.0.0.1", 40000), ("10.0.0.2", 80)


def tcp(ts, frm, flags=0x10, payload=0, win=1000, l4=20):
    a, b = (C, S) if frm == "c" else (S, C)
    return pkt(ts, a[0], a[1], b[0], b[1], flags=flags, payload=payload, win=win, l4=l4)


def run(packets, **kw):
    t = FlowTable(**kw)
    out = []
    for p in packets:
        out += t.add(p)
    return out + t.flush()


def test_forward_is_first_packet_direction():
    (fl,) = run([tcp(1.0, "s", 0x12), tcp(1.1, "c", 0x10)])
    assert (fl.src_ip, fl.src_port) == S


def test_fin_closes_flow_and_teardown_starts_new_flow():
    flows = run([tcp(1.0, "c", 0x02), tcp(1.1, "s", 0x12), tcp(1.2, "c", 0x10), tcp(1.3, "s", 0x11),
                 tcp(1.4, "c", 0x10), tcp(1.5, "c", 0x11), tcp(1.6, "s", 0x10)])
    # first FIN closes the flow; the teardown forms a second flow; the lone final ACK is dropped
    assert [(f.fwd_packets, f.bwd_packets) for f in flows] == [(2, 2), (2, 0)]


def test_flow_timeout_splits_long_flows():
    flows = run([tcp(0.0, "c"), tcp(1.0, "s"), tcp(121.0, "c"), tcp(122.0, "s")])
    assert len(flows) == 2


def test_payload_lengths_and_first_payload_counted_twice():
    (fl,) = run([tcp(1.0, "c", 0x18, payload=100), tcp(1.5, "s", 0x18, payload=300)])
    f = fl.to_features()
    assert f["fwd_pkt_len_mean"] == 100 and f["bwd_pkt_len_mean"] == 300
    assert f["pkt_size_avg"] == (100 * 2 + 300) / 2


def test_flag_columns_follow_first_packet_with_syn_psh_swap():
    (fl,) = run([tcp(1.0, "c", 0x02), tcp(1.1, "s", 0x12), tcp(1.2, "c", 0x18)])
    f = fl.to_features()
    assert f["psh_flag_cnt"] == 1.0 and f["syn_flag_cnt"] == 0.0 and f["ack_flag_cnt"] == 0.0
    (fl,) = run([tcp(1.0, "c", 0x18), tcp(1.1, "s", 0x10)])
    f = fl.to_features()
    assert f["syn_flag_cnt"] == 1.0 and f["ack_flag_cnt"] == 1.0 and f["psh_flag_cnt"] == 0.0
    assert f["urg_flag_cnt"] == 0.0


def test_init_window_and_header_bytes():
    (fl,) = run([tcp(1.0, "c", 0x02, win=29200, l4=40), tcp(1.1, "s", 0x12, win=5000, l4=40),
                 tcp(1.2, "c", 0x10, win=229, l4=32)])
    f = fl.to_features()
    assert f["tcp_win_size"] == 29200
    assert f["ttl_variance"] == abs((40 + 32) - 40)  # training column is |fwd header bytes - bwd header bytes|


def test_udp_uses_last_tcp_header_and_window_minus_one():
    t = FlowTable()
    t.add(tcp(1.0, "c", 0x10, l4=32))
    t.add(pkt(1.1, "10.0.0.9", 5353, "10.0.0.8", 53, flags=0, proto=17, payload=40, l4=8))
    t.add(pkt(1.2, "10.0.0.8", 53, "10.0.0.9", 5353, flags=0, proto=17, payload=90, l4=8))
    udp = [fl for fl in t.flush() if fl.protocol == 17][0]
    assert udp.fwd_hdr_bytes == 32 and udp.bwd_hdr_bytes == 32
    assert udp.to_features()["tcp_win_size"] == -1.0


def test_no_duration_floor_and_integer_microseconds():
    (fl,) = run([tcp(1499343857.087492, "c"), tcp(1499343857.087495, "s")])
    f = fl.to_features()
    assert f["flow_duration"] == 3.0 and f["flow_iat_mean"] == 3.0
    (fl,) = run([tcp(5.0, "c"), tcp(5.0, "s")])
    assert fl.to_features()["flow_bytes_s"] == 0.0  # CIC divides by zero here; training replaced it with 0


def test_packet_features_are_real_but_not_model_inputs():
    (fl,) = run([tcp(1.0, "c", payload=10), tcp(1.1, "s", payload=20)])
    extra = fl.packet_features()
    assert {"ttl_variance_real", "retransmissions", "payload_len_std"} <= set(extra)
    assert "ttl_variance_real" not in fl.to_features()
