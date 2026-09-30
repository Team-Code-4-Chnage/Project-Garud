"""
Single-flow behaviour classifier trained on real CIC-IDS2017 flows (see flowclf/train.py).

Scores each flow from its 22 features alone, so it works on any table the converter can read, whether or
not the file has addresses, timestamps or sessions. Returns the probability that the flow is an attack
(1 - P(Benign)) and the most likely behaviour.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import numpy as np
import pandas as pd

from .config import BASE_DIR, FLOW_FEATURES

ARTIFACTS_FLOW = Path(BASE_DIR / "artifacts_flow")


class FlowClassifier:
    def __init__(self, directory: Path = ARTIFACTS_FLOW):
        import joblib

        self.config = json.load(open(directory / "config.json"))
        if self.config["features"] != FLOW_FEATURES:
            raise ValueError("flow classifier was trained on a different feature order")
        self.model = joblib.load(directory / "flow_classifier.joblib")
        self.behaviours: list[str] = self.config["behaviours"]
        self.threshold: float = float(self.config["attack_threshold"])
        self._benign_col = list(self.model.classes_).index(0)

    def predict(self, feats: pd.DataFrame, batch: int = 250_000) -> dict:
        """attack_prob (n,), behaviour (n,) names, confidence (n,) = probability of the named behaviour."""
        x = feats[FLOW_FEATURES].to_numpy(dtype=np.float64)
        n = len(x)
        attack = np.empty(n, dtype=np.float32)
        beh = np.empty(n, dtype=object)
        conf = np.empty(n, dtype=np.float32)
        classes = np.asarray(self.model.classes_)
        names = np.asarray(self.behaviours, dtype=object)
        for i in range(0, n, batch):
            p = self.model.predict_proba(x[i:i + batch])
            ap = 1.0 - p[:, self._benign_col]
            attack[i:i + batch] = ap
            attack_cols = np.delete(np.arange(p.shape[1]), self._benign_col)
            best_attack = attack_cols[np.argmax(p[:, attack_cols], axis=1)]
            flagged = ap >= self.threshold
            chosen = np.where(flagged, best_attack, self._benign_col)
            beh[i:i + batch] = names[classes[chosen]]
            conf[i:i + batch] = p[np.arange(len(p)), chosen] if len(p) else 0.0
        return dict(attack_prob=attack, behaviour=beh, confidence=conf)


_lock = threading.Lock()
_instance: FlowClassifier | None = None
_error: str | None = None


def get_classifier() -> FlowClassifier:
    global _instance, _error
    with _lock:
        if _instance is None and _error is None:
            try:
                _instance = FlowClassifier()
            except Exception as exc:  # missing artifact must give a clear error, not a crash at import
                _error = str(exc)
        if _instance is None:
            raise RuntimeError(f"Flow classifier unavailable: {_error}. Train it with `python -m flowclf.train`.")
        return _instance
