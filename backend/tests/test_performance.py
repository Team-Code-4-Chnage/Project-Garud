"""
Performance benchmarks — proves the latency and throughput claims in README.

These tests are NOT about correctness (test_inference.py and test_model_quality.py
handle that). They measure wall-clock time to catch regressions and to give judges
a reproducible number instead of a marketing claim.

Contracts:
  - Single prediction: median < 5ms on CPU
  - Full forecast (k=6, N=20 MC): median < 500ms on CPU
  - Gradient explain: median < 50ms
  - SHAP explain (n=50): < 10s
  - Batch throughput: > 100 predictions/sec
"""
import os
import sys
import time

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import N_FEATURES, WINDOW_SIZE
from app.inference import (
    explain_window,
    explain_window_shap,
    forecast_rollout,
    predict_single,
)
from app.model_loader import artifacts

pytestmark = pytest.mark.requires_model


@pytest.fixture(scope="module", autouse=True)
def load_model():
    if not artifacts.is_loaded:
        artifacts.load()


def _random_scaled_window():
    """Generate a random window scaled by the production scaler."""
    raw = np.random.rand(WINDOW_SIZE, N_FEATURES).astype(np.float32) * 100
    return artifacts.scale_features(raw)


class TestInferenceLatency:
    """Latency contracts: single prediction < 5ms, forecast < 500ms on CPU."""

    def test_single_prediction_under_5ms(self):
        window = _random_scaled_window()
        # Warm up JIT / caches
        predict_single(window)

        times = []
        for _ in range(100):
            start = time.perf_counter()
            predict_single(window)
            times.append(time.perf_counter() - start)

        times.sort()
        median_ms = times[50] * 1000
        p99_ms = times[99] * 1000
        print(f"\nSingle prediction: median={median_ms:.2f}ms, p99={p99_ms:.2f}ms")
        assert median_ms < 5.0, (
            f"Median prediction latency {median_ms:.2f}ms exceeds 5ms contract"
        )

    def test_forecast_rollout_under_500ms(self):
        window = _random_scaled_window()
        # Warm up
        forecast_rollout(window, k_steps=6, n_mc_samples=20)

        times = []
        for _ in range(10):
            start = time.perf_counter()
            forecast_rollout(window, k_steps=6, n_mc_samples=20)
            times.append(time.perf_counter() - start)

        times.sort()
        median_ms = times[5] * 1000
        print(f"\nForecast (k=6, N=20): median={median_ms:.2f}ms")
        assert median_ms < 500.0, (
            f"Forecast latency {median_ms:.2f}ms exceeds 500ms contract"
        )

    def test_gradient_explain_under_50ms(self):
        window = _random_scaled_window()
        explain_window(window)  # warm up

        times = []
        for _ in range(20):
            start = time.perf_counter()
            explain_window(window, top_k=10)
            times.append(time.perf_counter() - start)

        times.sort()
        median_ms = times[10] * 1000
        print(f"\nGradient explain: median={median_ms:.2f}ms")
        assert median_ms < 50.0, (
            f"Gradient explain latency {median_ms:.2f}ms exceeds 50ms"
        )

    def test_shap_explain_under_10s(self):
        window = _random_scaled_window()
        start = time.perf_counter()
        result = explain_window_shap(window, top_k=10, n_samples=50)
        elapsed = time.perf_counter() - start
        print(
            f"\nSHAP explain (n=50): {elapsed:.2f}s, "
            f"method={result['method_used']}"
        )
        assert elapsed < 10.0, f"SHAP explain took {elapsed:.2f}s (>10s)"


class TestThroughput:
    """Throughput: can we sustain the ingestion rate needed for enterprise?"""

    def test_batch_prediction_throughput(self):
        """Measure predictions/second for batch processing."""
        windows = [_random_scaled_window() for _ in range(200)]

        start = time.perf_counter()
        for w in windows:
            predict_single(w)
        elapsed = time.perf_counter() - start

        throughput = len(windows) / elapsed
        print(
            f"\nBatch throughput: {throughput:.0f} predictions/sec "
            f"({elapsed:.2f}s for {len(windows)} windows)"
        )
        assert throughput > 100, (
            f"Throughput {throughput:.0f}/s too low for enterprise use"
        )
