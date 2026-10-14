"""
Unit and integration tests for the "Why?" Interpretable Decision Support & Attribution subsystem.
Verifies all 4 attribution engines:
1. SHAP (Game-Theoretic Shapley values)
2. GRADIENT (Gradient x Input Saliency)
3. ATTENTION (Temporal Recurrence sequence attention across t-5..t)
4. STATE DELTA (Dynamic state feature drift sensitivity)
"""
import os
import sys

import numpy as np
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


def test_explain_all_four_methods(client):
    """Ensure all 4 explainability engines return valid attributions."""
    window = [[0.1 * (i + j) for j in range(N_FEATURES)] for i in range(WINDOW_SIZE)]

    for method in ["shap", "gradient", "attention", "state_delta"]:
        res = client.post(
            "/explain",
            json={
                "window": window,
                "top_k": 5,
                "needs_scaling": False,
                "method": method,
            },
        )
        assert res.status_code == 200, f"Method {method} failed with {res.status_code}: {res.text}"
        data = res.json()
        assert "attributions" in data
        assert len(data["attributions"]) <= 5
        assert "infiltration_probability" in data
        assert "predicted_stage" in data
        assert data["method_used"] in (method, "shap", "gradient", "attention", "state_delta")

        if method == "attention":
            assert "temporal_weights" in data
            if data["temporal_weights"] is not None:
                assert len(data["temporal_weights"]) == WINDOW_SIZE
                assert abs(sum(data["temporal_weights"]) - 1.0) < 0.05


def test_explain_system_endpoint(client):
    """Ensure GET /explain/system returns whole-system posture and attribution."""
    res = client.get("/explain/system?method=gradient")
    assert res.status_code == 200, f"GET /explain/system failed: {res.text}"
    data = res.json()
    assert data.get("scope") == "whole_system"
    assert "system_posture" in data
    assert "risk_score" in data["system_posture"]
    assert "predicted_stage" in data["system_posture"]
    assert "attributions" in data
    assert "contributing_endpoints" in data
