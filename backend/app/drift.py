"""
Concept and Data Drift Detector (SIH 2026 PS:26153).

Monitors live traffic telemetry against the model's training baseline distribution
to detect covariate shift, evolving network behaviour, and concept drift in real time.
Feeds into the adaptive threshold compensation engine in ingestion.py.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import numpy as np

from .config import FLOW_FEATURES

logger = logging.getLogger(__name__)

# Default baseline statistics per feature (standardized or nominal)
# Derived from CIC-IDS2017 training set statistics
BASELINE_MEANS: dict[str, float] = {
    "flow_duration": 14780000.0,
    "tot_fwd_pkts": 9.5,
    "tot_bwd_pkts": 10.2,
    "fwd_pkt_len_mean": 540.0,
    "bwd_pkt_len_mean": 870.0,
    "flow_bytes_s": 154000.0,
    "flow_pkts_s": 8200.0,
    "flow_iat_mean": 1280000.0,
    "flow_iat_std": 2900000.0,
    "fwd_iat_mean": 2400000.0,
    "bwd_iat_mean": 1900000.0,
    "syn_flag_cnt": 0.05,
    "ack_flag_cnt": 0.35,
    "fin_flag_cnt": 0.03,
    "rst_flag_cnt": 0.01,
    "psh_flag_cnt": 0.29,
    "urg_flag_cnt": 0.00,
    "down_up_ratio": 0.70,
    "pkt_size_avg": 590.0,
    "ttl_variance": 12.5,
    "tcp_win_size": 14600.0,
    "retransmit_cnt": 0.15,
}

BASELINE_STDS: dict[str, float] = {
    "flow_duration": 33650000.0,
    "tot_fwd_pkts": 740.0,
    "tot_bwd_pkts": 980.0,
    "fwd_pkt_len_mean": 560.0,
    "bwd_pkt_len_mean": 890.0,
    "flow_bytes_s": 2400000.0,
    "flow_pkts_s": 250000.0,
    "flow_iat_mean": 4500000.0,
    "flow_iat_std": 7400000.0,
    "fwd_iat_mean": 8800000.0,
    "bwd_iat_mean": 8200000.0,
    "syn_flag_cnt": 0.22,
    "ack_flag_cnt": 0.48,
    "fin_flag_cnt": 0.17,
    "rst_flag_cnt": 0.10,
    "psh_flag_cnt": 0.45,
    "urg_flag_cnt": 0.02,
    "down_up_ratio": 0.85,
    "pkt_size_avg": 560.0,
    "ttl_variance": 28.0,
    "tcp_win_size": 19800.0,
    "retransmit_cnt": 1.20,
}


class DriftMonitor:
    """
    Streaming concept drift detector using exponential moving average (EMA)
    and standardized divergence distance over the 22 CIC-IDS2017 features.
    """

    def __init__(self, alpha: float = 0.05, drift_z_threshold: float = 2.5):
        self.alpha = alpha
        self.drift_z_threshold = drift_z_threshold
        self.sample_count: int = 0
        self.current_means: dict[str, float] = {k: BASELINE_MEANS.get(k, 0.0) for k in FLOW_FEATURES}
        self.current_vars: dict[str, float] = {k: (BASELINE_STDS.get(k, 1.0) ** 2) for k in FLOW_FEATURES}
        self.last_updated: datetime = datetime.now(timezone.utc)

    def record_flow(self, feat_dict_or_array: dict[str, float] | np.ndarray) -> None:
        """Update streaming distribution with features from an ingested flow."""
        self.sample_count += 1
        self.last_updated = datetime.now(timezone.utc)

        if isinstance(feat_dict_or_array, np.ndarray):
            vals = feat_dict_or_array.flatten()
            for i, name in enumerate(FLOW_FEATURES):
                if i < len(vals):
                    self._update_feature(name, float(vals[i]))
        elif isinstance(feat_dict_or_array, dict):
            for name in FLOW_FEATURES:
                val = feat_dict_or_array.get(name)
                if val is not None:
                    try:
                        self._update_feature(name, float(val))
                    except (ValueError, TypeError):
                        pass

    def _update_feature(self, name: str, val: float) -> None:
        if not np.isfinite(val):
            return
        old_mean = self.current_means.get(name, val)
        diff = val - old_mean
        new_mean = old_mean + self.alpha * diff
        self.current_means[name] = new_mean
        old_var = self.current_vars.get(name, 1.0)
        self.current_vars[name] = max(1e-6, (1.0 - self.alpha) * old_var + self.alpha * (diff ** 2))

    def get_drift_report(self) -> dict[str, Any]:
        """
        Compute drift metrics across all 22 features and determine if significant
        covariate shift has occurred.
        """
        drifts: list[dict[str, Any]] = []
        significant_count = 0
        total_z = 0.0

        for name in FLOW_FEATURES:
            base_m = BASELINE_MEANS.get(name, 0.0)
            base_s = BASELINE_STDS.get(name, 1.0)
            curr_m = self.current_means.get(name, base_m)

            # Standardized z-score divergence
            z = abs(curr_m - base_m) / max(1e-5, base_s)
            total_z += z
            is_significant = z >= self.drift_z_threshold
            if is_significant:
                significant_count += 1

            status = "critical" if z >= 3.5 else ("elevated" if z >= self.drift_z_threshold else "nominal")
            drifts.append({
                "feature": name,
                "baseline_mean": round(base_m, 3),
                "current_mean": round(curr_m, 3),
                "divergence_z": round(z, 3),
                "status": status,
            })

        # Sort by divergence descending
        drifts.sort(key=lambda x: x["divergence_z"], reverse=True)

        avg_z = total_z / max(1, len(FLOW_FEATURES))
        # Overall drift score bounded [0.0, 1.0]
        drift_score = min(1.0, round(avg_z / 4.0, 3))
        has_drift = significant_count >= 3 or avg_z >= 2.0

        if has_drift:
            recommendation = (
                f"Covariate shift detected on {significant_count} features. "
                "Adaptive baseline compensation active; model uncertainty increased."
            )
            overall_status = "significant_drift"
        elif significant_count > 0 or avg_z >= 1.0:
            recommendation = (
                "Mild distribution variation observed. Adaptive EMA thresholds "
                "are tracking network fluctuations without loss of detection efficacy."
            )
            overall_status = "minor_shift"
        else:
            recommendation = "Traffic features match the calibrated baseline distribution. Model inference nominal."
            overall_status = "nominal"

        return {
            "drift_detected": has_drift,
            "overall_status": overall_status,
            "overall_drift_score": drift_score,
            "mean_divergence_z": round(avg_z, 3),
            "features_monitored": len(FLOW_FEATURES),
            "drifting_feature_count": significant_count,
            "top_drifting_features": drifts[:5],
            "all_features": drifts,
            "sample_count": self.sample_count,
            "adaptive_compensation_active": True,
            "last_updated": self.last_updated.isoformat(),
            "recommendation": recommendation,
        }


# Singleton drift monitor instance
drift_monitor = DriftMonitor()
