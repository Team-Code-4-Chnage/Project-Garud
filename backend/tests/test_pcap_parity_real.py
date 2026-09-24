"""
Real-traffic regression: features extracted from a CIC-IDS2017 capture excerpt must equal the
official CICFlowMeter features (as data/preprocess_cicids.py turns them into model inputs).

Fixture: 24 complete TCP flows (12 Web Attack - Brute Force, 12 benign) cut from Thursday
2017-07-06 12:24-12:26 UTC by experiments/make_parity_fixture.py.
"""
import csv
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
FIX = Path(__file__).parent / "fixtures"

from app.config import FLOW_FEATURES  # noqa: E402
from capture.flow_table import flows_from_pcap  # noqa: E402

CIC = {
    "flow_duration": "Flow Duration", "tot_fwd_pkts": "Total Fwd Packets", "tot_bwd_pkts": "Total Backward Packets",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean", "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "flow_bytes_s": "Flow Bytes/s", "flow_pkts_s": "Flow Packets/s", "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std", "fwd_iat_mean": "Fwd IAT Mean", "bwd_iat_mean": "Bwd IAT Mean",
    "syn_flag_cnt": "SYN Flag Count", "ack_flag_cnt": "ACK Flag Count", "fin_flag_cnt": "FIN Flag Count",
    "rst_flag_cnt": "RST Flag Count", "psh_flag_cnt": "PSH Flag Count", "urg_flag_cnt": "URG Flag Count",
    "down_up_ratio": "Down/Up Ratio", "pkt_size_avg": "Average Packet Size",
}


def training_features(r):
    """Same derivation as data/preprocess_cicids.py."""
    out = {k: float(r[c]) for k, c in CIC.items()}
    out["ttl_variance"] = abs(float(r["Fwd Header Length"]) - float(r["Bwd Header Length"]))
    out["tcp_win_size"] = float(r["Init_Win_bytes_forward"])
    out["retransmit_cnt"] = max(0.0, float(r["Total Fwd Packets"]) - float(r["Subflow Fwd Packets"]))
    return {k: (0.0 if not math.isfinite(v) else v) for k, v in out.items()}


@pytest.fixture(scope="module")
def pairs():
    pytest.importorskip("scapy")
    flows = flows_from_pcap(str(FIX / "cic2017_parity.pcap"))
    by_key = {(f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.fwd_packets, f.bwd_packets): f for f in flows}
    with open(FIX / "cic2017_parity_labels.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    out = []
    for r in rows:
        key = (r["Source IP"], int(float(r["Source Port"])), r["Destination IP"], int(float(r["Destination Port"])),
               int(float(r["Total Fwd Packets"])), int(float(r["Total Backward Packets"])))
        out.append((r["Label"], by_key.get(key), training_features(r)))
    return out


def test_every_labelled_flow_is_reconstructed(pairs):
    missing = [lab for lab, fl, _ in pairs if fl is None]
    assert len(pairs) == 24 and not missing


def test_all_22_features_match_training_definitions(pairs):
    bad = []
    for lab, fl, truth in pairs:
        mine = fl.to_features()
        for f in FLOW_FEATURES:
            if not math.isclose(mine[f], truth[f], rel_tol=0.01, abs_tol=1e-6):
                bad.append((lab, f, mine[f], truth[f]))
    assert not bad, bad[:10]


def test_fixture_contains_attack_traffic(pairs):
    assert sum(lab.startswith("Web Attack") for lab, _, _ in pairs) == 12


def test_pcap_upload_end_to_end_flags_real_attack_flows():
    """Upload the real CIC-IDS2017 excerpt through the production /ingest/pcap route."""
    pytest.importorskip("scapy")
    from fastapi.testclient import TestClient

    from app.main import app
    from app.model_loader import artifacts

    if not artifacts.is_loaded:
        artifacts.load()
    with TestClient(app) as client:
        with open(FIX / "cic2017_parity.pcap", "rb") as fh:
            res = client.post("/ingest/pcap", files={"file": ("cic2017_parity.pcap", fh, "application/octet-stream")})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["flows_accepted"] == 24 and body["flows_rejected"] == 0
    assert body["alerts_generated"] >= 1  # the 12 web brute-force flows share one attacker/victim session
