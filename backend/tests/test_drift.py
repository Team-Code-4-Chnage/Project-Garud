"""
Unit tests for Concept and Data Drift Detector (SIH 2026 PS:26153).
"""
import numpy as np
import pytest
from app.config import FLOW_FEATURES, N_FEATURES
from app.drift import DriftMonitor, drift_monitor


def test_drift_monitor_initial_state():
    monitor = DriftMonitor()
    report = monitor.get_drift_report()
    assert report["drift_detected"] is False
    assert report["overall_status"] == "nominal"
    assert report["features_monitored"] == N_FEATURES
    assert len(report["all_features"]) == N_FEATURES


def test_drift_monitor_records_nominal_flows():
    monitor = DriftMonitor(alpha=0.1)
    # Feed nominal features close to baseline
    dummy = {f: 10.0 for f in FLOW_FEATURES}
    for _ in range(5):
        monitor.record_flow(dummy)
    assert monitor.sample_count == 5
    report = monitor.get_drift_report()
    assert "overall_drift_score" in report
    assert report["sample_count"] == 5


def test_drift_monitor_detects_severe_covariate_shift():
    monitor = DriftMonitor(alpha=0.5, drift_z_threshold=2.0)
    # Feed extreme abnormal values across all features to trigger significant shift
    extreme_vector = np.full((1, N_FEATURES), 1e9, dtype=np.float32)
    for _ in range(15):
        monitor.record_flow(extreme_vector)

    report = monitor.get_drift_report()
    assert report["drifting_feature_count"] > 0
    assert report["overall_drift_score"] > 0.0


def test_drift_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as client:
        response = client.get("/system/drift")
        assert response.status_code == 200
        data = response.json()
        assert "drift_detected" in data
        assert "overall_status" in data
        assert "overall_drift_score" in data
        assert "features_monitored" in data
        assert data["features_monitored"] == 22
