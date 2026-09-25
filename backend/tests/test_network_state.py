"""Network-state world model service: state building, forecast payload, sustained alert and API."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.config import FLOW_FEATURES  # noqa: E402
from app.network_state import NetworkStateTracker  # noqa: E402
from app.schemas import FlowRecord  # noqa: E402

T0 = datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)


def flow(minute, i, dport=80, src="10.0.0.5"):
    f = {k: 1.0 for k in FLOW_FEATURES}
    f.update(flow_duration=1000.0 + i, tot_fwd_pkts=3, tot_bwd_pkts=2, fwd_pkt_len_mean=100, bwd_pkt_len_mean=400)
    return FlowRecord(**f, src_ip=src, dst_ip="10.0.0.9", src_port=40000 + i, dst_port=dport, protocol="TCP",
                      timestamp=T0 + timedelta(minutes=minute, seconds=i % 50), source="csv_upload")


@pytest.fixture
def tracker():
    t = NetworkStateTracker()
    if t.model is None:
        pytest.skip("backend/artifacts_v3 not present")
    return t


def test_states_are_per_minute_and_fill_quiet_minutes(tracker):
    for m in (0, 1, 3):  # minute 2 has no traffic
        for i in range(5):
            tracker.add(flow(m, i), "csv_upload")
    st = tracker.states("csv_upload")
    assert len(st) == 4 and list(st["n_flows"]) == [5, 5, 0, 5]


def test_warming_up_before_six_minutes(tracker):
    for m in range(3):
        tracker.add(flow(m, 0), "csv_upload")
        tracker.add(flow(m, 1), "csv_upload")
    r = tracker.analyze("csv_upload")
    assert r["status"] == "warming_up" and r["minutes_needed"] == 6


def test_forecast_payload(tracker):
    for m in range(12):
        n = 4 if m < 9 else 40  # a burst of new connections to many ports in the last minutes
        for i in range(n):
            tracker.add(flow(m, i, dport=80 if m < 9 else 1000 + i), "csv_upload")
    r = tracker.analyze("csv_upload")
    assert r["status"] == "ok"
    assert len(r["minutes"]) == 12 and len(r["risk_score"]) == 12 and len(r["alert"]) == 12
    assert r["risk_score"][:5] == [None] * 5 and all(0 <= v <= 1 for v in r["risk_score"][5:])
    assert [s["step"] for s in r["forecast"]] == [1, 2, 3, 4]
    for s in r["forecast"]:
        assert 0 <= s["risk"] <= 1
        assert abs(sum(b["probability"] for b in s["behaviours"])) <= 1.0 + 1e-6
        assert "n_uniq_dst_port" in s["state"]
    assert len(r["explanation"]) == 8
    assert r["model"]["feature_set"] == "net_nodir" and r["model"]["caveats"]


def test_sustained_rule_matches_config(tracker):
    m = tracker.model
    for mi in range(10):
        for i in range(3):
            tracker.add(flow(mi, i), "csv_upload")
    r = tracker.analyze("csv_upload")
    scores = np.array([np.nan if v is None else v for v in r["risk_score"]])
    run, expected = 0, []
    for v in scores:
        run = run + 1 if (not np.isnan(v) and v >= m.thr) else 0
        expected.append(run >= m.N)
    assert r["alert"] == expected


def test_sources_are_kept_apart(tracker):
    tracker.add(flow(0, 0), "csv_upload")
    tracker.add(flow(0, 1), "pcap_upload")
    assert {s["source"] for s in tracker.sources()} == {"csv_upload", "pcap_upload"}
    tracker.reset("csv_upload")
    assert {s["source"] for s in tracker.sources()} == {"pcap_upload"}


def test_api_endpoints_after_pcap_upload():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.network_state import tracker as shared

    shared.reset()
    fix = Path(__file__).parent / "fixtures" / "cic2017_parity.pcap"
    with TestClient(app) as client:
        with open(fix, "rb") as fh:
            assert client.post("/ingest/pcap", files={"file": ("f.pcap", fh, "application/octet-stream")}).status_code == 200
        srcs = client.get("/network/sources").json()
        assert srcs[0]["source"] == "pcap_upload" and srcs[0]["flows"] == 24
        r = client.get("/network/forecast", params={"source": "pcap_upload"}).json()
        assert r["status"] in ("warming_up", "ok")  # the fixture spans about 2 minutes
        assert client.post("/network/reset").json() == {"reset": "all"}
