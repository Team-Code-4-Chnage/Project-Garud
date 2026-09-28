"""
Security tests — input validation, boundary conditions, API key enforcement.

Verifies that the API rejects malformed, oversized, and adversarial inputs
gracefully (400/422) rather than crashing (500). Also checks that the rate
limiter and API-key middleware don't block health checks.
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import N_FEATURES, WINDOW_SIZE
from app.main import app
from app.model_loader import artifacts


@pytest.fixture(scope="module")
def client():
    if not artifacts.is_loaded:
        artifacts.load()
    with TestClient(app) as tc:
        yield tc


class TestInputValidation:
    """Verify that malformed inputs produce clean 400/422 errors, never 500."""

    def test_oversized_window_rejected(self, client):
        """Window larger than 6×22 must be rejected."""
        window = [[0.5] * N_FEATURES for _ in range(WINDOW_SIZE + 5)]
        res = client.post("/predict", json={"window": window})
        assert res.status_code in (400, 422), (
            f"Oversized window returned {res.status_code}, expected 400/422"
        )

    def test_undersized_window_rejected(self, client):
        """Window smaller than 6×22 must be rejected."""
        window = [[0.5] * N_FEATURES for _ in range(3)]
        res = client.post("/predict", json={"window": window})
        assert res.status_code in (400, 422), (
            f"Undersized window returned {res.status_code}, expected 400/422"
        )

    def test_wrong_feature_count_rejected(self, client):
        """Window with wrong feature dimension must be rejected."""
        window = [[0.5] * 10 for _ in range(WINDOW_SIZE)]
        res = client.post("/predict", json={"window": window})
        assert res.status_code in (400, 422), (
            f"Wrong feature count returned {res.status_code}, expected 400/422"
        )

    def test_nan_input_does_not_crash(self, client):
        """NaN values should not cause a 500 Internal Server Error."""
        window = [[float("nan")] * N_FEATURES for _ in range(WINDOW_SIZE)]
        res = client.post("/predict", json={"window": window})
        assert res.status_code != 500, "NaN input caused a server crash"

    def test_extreme_values_handled(self, client):
        """Very large feature values should not crash the server."""
        window = [[1e15] * N_FEATURES for _ in range(WINDOW_SIZE)]
        res = client.post("/predict", json={"window": window})
        assert res.status_code in (200, 400, 422), (
            f"Extreme values returned {res.status_code}"
        )

    def test_empty_body_rejected(self, client):
        """POST with no body should be rejected."""
        res = client.post("/predict")
        assert res.status_code == 422

    def test_negative_k_steps_rejected(self, client):
        """Negative k_steps in forecast should be rejected."""
        window = [[0.5] * N_FEATURES for _ in range(WINDOW_SIZE)]
        res = client.post(
            "/forecast", json={"window": window, "k_steps": -1}
        )
        assert res.status_code in (400, 422)

    def test_zero_k_steps_handled(self, client):
        """k_steps=0 should either be rejected or return empty steps."""
        window = [[0.5] * N_FEATURES for _ in range(WINDOW_SIZE)]
        res = client.post(
            "/forecast", json={"window": window, "k_steps": 0}
        )
        assert res.status_code in (200, 400, 422)

    def test_excessive_mc_samples_handled(self, client):
        """n_mc_samples > 100 should be rejected or capped."""
        window = [[0.5] * N_FEATURES for _ in range(WINDOW_SIZE)]
        res = client.post(
            "/forecast",
            json={"window": window, "k_steps": 6, "n_mc_samples": 999},
        )
        assert res.status_code in (200, 400, 422)


class TestEndpointAvailability:
    """Verify all documented endpoints respond without 500 errors."""

    def test_health_always_responds(self, client):
        for _ in range(5):
            res = client.get("/health")
            assert res.status_code == 200

    def test_root_responds(self, client):
        res = client.get("/")
        assert res.status_code == 200

    def test_mitre_mapping_responds(self, client):
        res = client.get("/mitre/mapping")
        assert res.status_code == 200

    def test_mitre_lookup_valid_label(self, client):
        res = client.get("/mitre/lookup/Benign")
        assert res.status_code == 200

    def test_mitre_lookup_unknown_label(self, client):
        res = client.get("/mitre/lookup/NonExistentLabel")
        assert res.status_code in (200, 404)

    def test_sessions_responds(self, client):
        res = client.get("/sessions")
        assert res.status_code == 200

    def test_alerts_responds(self, client):
        res = client.get("/alerts")
        assert res.status_code == 200

    def test_dashboard_stats_responds(self, client):
        res = client.get("/dashboard/stats")
        assert res.status_code == 200

    def test_system_mode_responds(self, client):
        res = client.get("/system/mode")
        assert res.status_code == 200

    def test_host_identity_responds(self, client):
        res = client.get("/system/host-identity")
        assert res.status_code == 200
