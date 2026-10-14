"""
Integration tests for Project Garud FastAPI endpoints.
Tests the complete flow from ingestion -> prediction -> alert generation -> query.
Uses FastAPI's official TestClient for robust end-to-end API verification.
"""
import io
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import FLOW_FEATURES, N_FEATURES, STAGES, WINDOW_SIZE
from app.main import app
from app.model_loader import artifacts


@pytest.fixture(scope="module")
def client():
    """Module-scoped TestClient with startup/lifespan triggered."""
    if not artifacts.is_loaded:
        artifacts.load()
    with TestClient(app) as tc:
        yield tc


def make_dummy_flow(src_ip="192.168.1.100", dst_ip="10.0.0.5", multiplier=1.0):
    """Generate a valid 22-feature FlowRecord dictionary."""
    flow = {f: float(i * multiplier + 1.0) for i, f in enumerate(FLOW_FEATURES)}
    flow.update({
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 4444,
        "dst_port": 80,
        "protocol": "TCP",
        "flow_duration": 100000.0,
        "flow_pkts_s": 500.0,
        "flow_bytes_s": 25000.0,
        "source": "api_test",
    })
    return flow


def test_health_endpoint(client: TestClient):
    """Verify system health, model readiness, and feature taxonomy."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True
    assert data["features_count"] == N_FEATURES
    assert len(data["stages"]) == len(STAGES)
    assert data.get("model_hash") is not None
    assert data.get("scaler_hash") is not None


def test_direct_predict_endpoint(client: TestClient):
    """Verify POST /predict with a 6x22 window."""
    window = [[0.5] * N_FEATURES for _ in range(WINDOW_SIZE)]
    payload = {"window": window, "needs_scaling": True}
    res = client.post("/predict", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "infiltration_probability" in data
    assert 0.0 <= data["infiltration_probability"] <= 1.0
    assert data["predicted_stage"] in STAGES
    assert "is_alert" in data


def test_direct_forecast_endpoint(client: TestClient):
    """Verify POST /forecast returns exactly k-step rollout."""
    window = [[0.1] * N_FEATURES for _ in range(WINDOW_SIZE)]
    payload = {"window": window, "k_steps": 6, "n_mc_samples": 5, "needs_scaling": True}
    res = client.post("/forecast", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "steps" in data
    assert len(data["steps"]) == 6
    for step in data["steps"]:
        assert 0.0 <= step["infiltration_prob_mean"] <= 1.0
        assert step["predicted_stage"] in STAGES


def test_ingest_flow_updates_session(client: TestClient):
    """Verify POST /ingest saves flow record and establishes session."""
    flow = make_dummy_flow(src_ip="192.168.1.110", dst_ip="10.0.0.20")
    res = client.post("/ingest", json=flow)
    assert res.status_code == 200
    data = res.json()
    assert "session_key" in data
    assert "192.168.1.110->10.0.0.20" in data["session_key"]
    assert data["buffer_size"] >= 1

    sess_res = client.get("/sessions")
    assert sess_res.status_code == 200
    sessions = sess_res.json()
    matching = [s for s in sessions if "192.168.1.110->10.0.0.20" in s["session_key"]]
    assert len(matching) > 0

    fresh_res = client.get("/sessions?active_within_seconds=300")
    assert fresh_res.status_code == 200
    fresh = [s for s in fresh_res.json() if "192.168.1.110->10.0.0.20" in s["session_key"]]
    assert len(fresh) > 0

    stale_res = client.get("/sessions?active_within_seconds=1")
    assert stale_res.status_code == 200
    import time
    time.sleep(1.1)
    stale_res2 = client.get("/sessions?active_within_seconds=1")
    stale_matching = [s for s in stale_res2.json() if "192.168.1.110->10.0.0.20" in s["session_key"]]
    assert len(stale_matching) == 0


def test_ingest_window_and_predict_flow(client: TestClient):
    """Ingest a window of 6 flows to trigger model prediction automatically."""
    src = "172.16.0.50"
    dst = "10.0.0.80"

    prediction_result = None
    for i in range(WINDOW_SIZE):
        flow = make_dummy_flow(src_ip=src, dst_ip=dst, multiplier=float(i + 1))
        res = client.post("/ingest", json=flow)
        assert res.status_code == 200
        data = res.json()
        if i == WINDOW_SIZE - 1:
            prediction_result = data.get("prediction")

    assert prediction_result is not None
    assert "infiltration_probability" in prediction_result
    assert 0.0 <= prediction_result["infiltration_probability"] <= 1.0
    assert prediction_result["predicted_stage"] in STAGES


def test_full_chain_ingest_alert_and_query(client: TestClient):
    """Verify complete ingest -> prediction -> alert generation -> alerts query chain."""
    src = "192.168.10.99"
    dst = "10.10.10.99"

    for _ in range(WINDOW_SIZE):
        flow = make_dummy_flow(src_ip=src, dst_ip=dst, multiplier=100.0)
        flow["retransmit_cnt"] = 50.0
        flow["syn_flag_cnt"] = 100.0
        res = client.post("/ingest", json=flow)
        assert res.status_code == 200

    alerts_res = client.get("/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert isinstance(alerts, list)


def test_heartbleed_signature_triggers_immediate_alert(client: TestClient):
    """
    A flow flagged with heartbleed_signature=True must produce a critical
    'Exfiltration' alert on the very first flow — it must not wait for the
    6-flow ML window to fill, since a single malformed heartbeat is already
    a complete exploit attempt.
    """
    flow = make_dummy_flow(src_ip="192.168.20.5", dst_ip="10.20.20.5")
    flow["heartbleed_signature"] = True
    res = client.post("/ingest", json=flow)
    assert res.status_code == 200
    data = res.json()

    assert data["buffer_size"] == 1
    assert data["prediction"] is None
    assert data["heartbleed_alert"] is not None
    assert data["heartbleed_alert"]["severity"] == "critical"
    assert data["heartbleed_alert"]["predicted_stage"] == "Exfiltration"
    assert data["heartbleed_alert"]["infiltration_prob"] == 1.0

    alerts_res = client.get("/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert any(
        a.get("predicted_stage") == "Exfiltration" and a.get("severity") == "critical"
        for a in alerts
    )


def test_normal_flow_does_not_trigger_heartbleed_alert(client: TestClient):
    """Sanity check: a normal flow (heartbleed_signature defaults to False) never
    produces a heartbleed_alert."""
    flow = make_dummy_flow(src_ip="192.168.20.6", dst_ip="10.20.20.6")
    res = client.post("/ingest", json=flow)
    assert res.status_code == 200
    assert res.json()["heartbleed_alert"] is None


def test_ingest_csv_batch_upload(client: TestClient):
    """Verify batch flow upload via CSV."""
    header = ",".join(FLOW_FEATURES + ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"])
    row1_vals = [str(1.0 + i) for i in range(len(FLOW_FEATURES))] + ["192.168.5.1", "10.0.5.2", "5000", "80", "TCP"]
    row2_vals = [str(2.0 + i) for i in range(len(FLOW_FEATURES))] + ["192.168.5.1", "10.0.5.2", "5001", "80", "TCP"]
    csv_content = f"{header}\n{','.join(row1_vals)}\n{','.join(row2_vals)}\n".encode("utf-8")

    files = {"file": ("batch_flows.csv", io.BytesIO(csv_content), "text/csv")}
    res = client.post("/ingest/csv", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["flows_accepted"] >= 2
    assert data["flows_rejected"] == 0


def test_ip_address_validation(client: TestClient):
    """Verify that invalid IP addresses are rejected with 422 while valid IPs and placeholders succeed."""
    valid_flow = make_dummy_flow(src_ip="192.168.1.50", dst_ip="10.0.0.1")
    assert client.post("/ingest", json=valid_flow).status_code == 200

    v6_flow = make_dummy_flow(src_ip="::1", dst_ip="fe80::1")
    assert client.post("/ingest", json=v6_flow).status_code == 200

    bracket_flow = make_dummy_flow(src_ip="[2001:db8::1]:8080", dst_ip="192.168.1.1:443")
    assert client.post("/ingest", json=bracket_flow).status_code == 200

    placeholder_flow = make_dummy_flow(src_ip="unknown", dst_ip="localhost")
    assert client.post("/ingest", json=placeholder_flow).status_code == 200

    invalid_flow = make_dummy_flow(src_ip="not_an_ip_address", dst_ip="10.0.0.1")
    res_invalid = client.post("/ingest", json=invalid_flow)
    assert res_invalid.status_code == 422
    assert "Invalid IP address format" in res_invalid.text
