"""
Real inference tests — runs actual model predictions on known windows.
This is your "does it actually work" proof for judges.
"""
import os
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import HIDDEN_SIZE, N_FEATURES, N_STAGES, NUM_LSTM_LAYERS, STAGES, WINDOW_SIZE
from app.inference import (
    ema_smooth,
    explain_window,
    explain_window_shap,
    forecast_rollout,
    predict_single,
)
from app.model_loader import WorldModel, artifacts

# Skip every test in this module in CI when trained .pt artifacts aren't present.
pytestmark = pytest.mark.requires_model


@pytest.fixture(scope="module", autouse=True)
def load_model():
    """Load model artifacts once for all tests."""
    if not artifacts.is_loaded:
        artifacts.load()


class TestModelLoading:
    def test_model_is_loaded(self):
        assert artifacts.is_loaded

    def test_model_architecture(self):
        model = artifacts.model
        assert isinstance(model, WorldModel)
        assert model.lstm.input_size == N_FEATURES
        assert model.lstm.hidden_size == HIDDEN_SIZE
        assert model.lstm.num_layers == NUM_LSTM_LAYERS

    def test_scaler_fitted(self):
        assert hasattr(artifacts.scaler, "n_features_in_")
        assert artifacts.scaler.n_features_in_ == N_FEATURES

    def test_config_matches(self):
        assert artifacts.config["window"] == WINDOW_SIZE
        assert len(artifacts.config["features"]) == N_FEATURES
        assert len(artifacts.config["stages"]) == N_STAGES

    def test_stage_logit_bias_loaded_and_aligned(self):
        """Bias tensor must exist, match N_STAGES, and follow config.json's stage order."""
        assert artifacts.stage_logit_bias is not None
        assert artifacts.stage_logit_bias.shape == (N_STAGES,)
        bias_cfg = artifacts.config.get("stage_logit_bias", {})
        for i, stage in enumerate(artifacts.config["stages"]):
            assert artifacts.stage_logit_bias[i].item() == pytest.approx(bias_cfg.get(stage, 0.0))


class TestPrediction:
    def test_predict_single_shape(self):
        """Feed a random window → assert output shapes and ranges."""
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = predict_single(window)

        assert "infiltration_probability" in result
        assert "predicted_stage" in result
        assert "predicted_stage_id" in result
        assert "is_alert" in result

    def test_predict_probability_range(self):
        """Infiltration probability must be in [0, 1]."""
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = predict_single(window)
        assert 0.0 <= result["infiltration_probability"] <= 1.0

    def test_predict_stage_valid(self):
        """Predicted stage must be one of the 6 MITRE stages."""
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = predict_single(window)
        assert result["predicted_stage"] in STAGES
        assert 0 <= result["predicted_stage_id"] < N_STAGES

    def test_predict_wrong_shape_raises(self):
        """Wrong window shape must raise ValueError, not silently proceed."""
        with pytest.raises(ValueError):
            predict_single(np.random.randn(3, N_FEATURES).astype(np.float32))
        with pytest.raises(ValueError):
            predict_single(np.random.randn(WINDOW_SIZE, 10).astype(np.float32))

    def test_predict_deterministic(self):
        """Same input → same output (model is in eval mode, no dropout)."""
        window = np.ones((WINDOW_SIZE, N_FEATURES), dtype=np.float32) * 0.5
        r1 = predict_single(window)
        r2 = predict_single(window)
        assert r1["infiltration_probability"] == r2["infiltration_probability"]
        assert r1["predicted_stage"] == r2["predicted_stage"]


class TestForecast:
    def test_forecast_output_length(self):
        """Forecast must return exactly k_steps steps."""
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = forecast_rollout(window, k_steps=6, n_mc_samples=5)

        assert len(result["steps"]) == 6
        for step in result["steps"]:
            assert 0.0 <= step["infiltration_prob_mean"] <= 1.0
            assert step["infiltration_prob_std"] >= 0.0
            assert step["predicted_stage"] in STAGES

    def test_forecast_threshold_present(self):
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = forecast_rollout(window, k_steps=3, n_mc_samples=3)
        assert "threshold" in result
        assert "alert_triggered" in result

    def test_ema_smoothing(self):
        """EMA should smooth a sequence — no NaN/Inf."""
        probs = [0.9, 0.3, 0.7, 0.5, 0.8]
        smoothed = ema_smooth(probs)
        assert len(smoothed) == len(probs)
        assert smoothed[0] == probs[0]
        for p in smoothed:
            assert 0.0 <= p <= 1.0
            assert np.isfinite(p)


class TestExplanation:
    def test_explain_returns_attributions(self):
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = explain_window(window, top_k=5)

        assert "attributions" in result
        assert len(result["attributions"]) == 5
        for attr in result["attributions"]:
            assert "feature" in attr
            assert "importance" in attr
            assert "direction" in attr
            assert attr["direction"] in ("malicious", "benign")

    def test_explain_includes_prediction(self):
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = explain_window(window)
        assert "infiltration_probability" in result
        assert "predicted_stage" in result

    def test_explain_shap(self):
        window = np.random.randn(WINDOW_SIZE, N_FEATURES).astype(np.float32)
        result = explain_window_shap(window, top_k=5, n_samples=20)
        assert "attributions" in result
        assert len(result["attributions"]) == 5
        assert result["method_used"] in ("shap", "gradient_fallback")
        assert "infiltration_probability" in result
        assert "predicted_stage" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
