"""
Model loader — loads world_model.pt, scaler.pkl, config.json at startup.
Fails loudly if anything is wrong. No silent fallbacks.
"""
import hashlib
import json
import logging
import pickle

import numpy as np
import torch
import torch.nn as nn

from .config import (
    CONFIG_PATH,
    FLOW_FEATURES,
    HIDDEN_SIZE,
    LSTM_DROPOUT,
    MODEL_PATH,
    N_FEATURES,
    N_STAGES,
    NUM_LSTM_LAYERS,
    SCALER_PATH,
    WINDOW_SIZE,
)

logger = logging.getLogger(__name__)


class WorldModel(nn.Module):
    def __init__(self, n_features: int = N_FEATURES, hidden: int = HIDDEN_SIZE,
                 n_stages: int = N_STAGES, num_layers: int = NUM_LSTM_LAYERS,
                 dropout: float = LSTM_DROPOUT):
        super().__init__()
        self.lstm = nn.LSTM(
            n_features, hidden, num_layers=num_layers,
            batch_first=True, dropout=dropout if num_layers > 1 else 0.0,
        )
        self.next_state_head = nn.Linear(hidden, n_features)
        self.infiltration_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 32), nn.ReLU(),
            nn.Linear(32, 1),
        )
        self.stage_head = nn.Sequential(
            nn.Linear(hidden, 64), nn.ReLU(),
            nn.Linear(64, n_stages),
        )

    def forward(self, x: torch.Tensor):
        out, (h_n, _) = self.lstm(x)
        h = h_n[-1]
        next_state = self.next_state_head(h)
        infiltration_logit = self.infiltration_head(h).squeeze(-1)
        stage_logits = self.stage_head(h)
        return next_state, infiltration_logit, stage_logits


class StandardScaler:
    """Self-contained standard scaler that does not depend on C-extensions."""
    def __init__(self, mean=None, scale=None):
        self.mean_ = np.asarray(mean, dtype=np.float32) if mean is not None else None
        self.scale_ = np.asarray(scale, dtype=np.float32) if scale is not None else None
        self.n_features_in_ = len(self.mean_) if self.mean_ is not None else N_FEATURES

    def fit(self, X):
        X = np.asarray(X, dtype=np.float32)
        self.mean_ = np.mean(X, axis=0)
        self.scale_ = np.std(X, axis=0)
        self.scale_[self.scale_ == 0.0] = 1.0
        self.n_features_in_ = X.shape[1]
        return self

    def transform(self, X):
        X = np.asarray(X, dtype=np.float32)
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X):
        return self.fit(X).transform(X)


class ModelArtifacts:
    """Container for all loaded artifacts. Validates shapes on load."""

    def __init__(self):
        self.model: WorldModel | None = None
        self.scaler = None
        self.config: dict | None = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._loaded = False
        self.model_version: str = "1.0.0"
        self.model_hash: str | None = None
        self.scaler_hash: str | None = None
        self._scaler_mean: np.ndarray | None = None
        self.stage_logit_bias: torch.Tensor | None = None

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def load(self) -> None:
        """Load all artifacts. Raises on any failure — never returns a half-loaded state."""
        logger.info("Loading model artifacts...")

        if not CONFIG_PATH.exists():
            raise FileNotFoundError(f"config.json not found at {CONFIG_PATH}")
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)

        cfg_features = self.config.get("features", [])
        cfg_stages = self.config.get("stages", [])
        cfg_window = self.config.get("window")

        if len(cfg_features) != N_FEATURES:
            raise ValueError(
                f"config.json has {len(cfg_features)} features, expected {N_FEATURES}. "
                f"Missing: {set(FLOW_FEATURES) - set(cfg_features)}"
            )
        if cfg_features != FLOW_FEATURES:
            raise ValueError(
                f"config.json feature order doesn't match expected order. "
                f"Got: {cfg_features[:5]}... Expected: {FLOW_FEATURES[:5]}..."
            )
        if len(cfg_stages) != N_STAGES:
            raise ValueError(f"config.json has {len(cfg_stages)} stages, expected {N_STAGES}")
        if cfg_window != WINDOW_SIZE:
            raise ValueError(f"config.json window={cfg_window}, expected {WINDOW_SIZE}")

        logger.info("  config.json: OK (%d features, %d stages, window=%d)",
                     len(cfg_features), len(cfg_stages), cfg_window)

        if not SCALER_PATH.exists():
            raise FileNotFoundError(f"scaler.pkl not found at {SCALER_PATH}")
        with open(SCALER_PATH, "rb") as f:
            raw_scaler = pickle.load(f)

        if isinstance(raw_scaler, dict):
            self.scaler = StandardScaler(mean=raw_scaler["mean"], scale=raw_scaler["scale"])
        else:
            self.scaler = raw_scaler

        if hasattr(self.scaler, "n_features_in_"):
            if self.scaler.n_features_in_ != N_FEATURES:
                raise ValueError(
                    f"scaler.pkl fitted on {self.scaler.n_features_in_} features, "
                    f"expected {N_FEATURES}"
                )
        self._scaler_mean = np.zeros((1, N_FEATURES), dtype=np.float32)
        logger.info("  scaler.pkl: OK (n_features=%d)", N_FEATURES)

        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"world_model.pt not found at {MODEL_PATH}")

        hidden_size = self.config.get("hidden_size", HIDDEN_SIZE)
        num_layers = self.config.get("num_layers", NUM_LSTM_LAYERS)
        dropout = self.config.get("lstm_dropout", LSTM_DROPOUT)
        self.model = WorldModel(
            n_features=N_FEATURES, hidden=hidden_size, n_stages=N_STAGES,
            num_layers=num_layers, dropout=dropout,
        )
        state_dict = torch.load(MODEL_PATH, map_location=self.device, weights_only=True)
        self.model.load_state_dict(state_dict)
        self.model.to(self.device)
        self.model.eval()

        dummy = torch.randn(1, WINDOW_SIZE, N_FEATURES, device=self.device)
        with torch.no_grad():
            next_state, inf_logit, stage_logits = self.model(dummy)

        assert next_state.shape == (1, N_FEATURES), \
            f"next_state head shape {next_state.shape}, expected (1, {N_FEATURES})"
        assert inf_logit.shape == (1,), \
            f"infiltration head shape {inf_logit.shape}, expected (1,)"
        assert stage_logits.shape == (1, N_STAGES), \
            f"stage head shape {stage_logits.shape}, expected (1, {N_STAGES})"

        def _hash_file(p):
            h = hashlib.sha256()
            with open(p, "rb") as fp:
                while chunk := fp.read(65536):
                    h.update(chunk)
            return h.hexdigest()[:16]

        self.model_hash = _hash_file(MODEL_PATH)
        self.scaler_hash = _hash_file(SCALER_PATH)
        self.model_version = self.config.get("version", "1.0.0")

        bias_cfg = self.config.get("stage_logit_bias")
        if bias_cfg:
            bias_vec = [bias_cfg.get(stage, 0.0) for stage in cfg_stages]
            self.stage_logit_bias = torch.tensor(bias_vec, dtype=torch.float32, device=self.device)
        else:
            self.stage_logit_bias = torch.zeros(N_STAGES, dtype=torch.float32, device=self.device)

        logger.info("  world_model.pt: OK (hidden=%d, layers=%d, dropout=%.2f, sha256=%s)",
                     HIDDEN_SIZE, NUM_LSTM_LAYERS, LSTM_DROPOUT, self.model_hash)
        self._loaded = True
        logger.info("All artifacts loaded successfully on device=%s", self.device)

    def scale_features(self, raw_features: np.ndarray) -> np.ndarray:
        """Scale raw features using the loaded scaler. Input: (n_samples, 22)."""
        if not self._loaded:
            raise RuntimeError("Artifacts not loaded — call load() first")
        return self.scaler.transform(raw_features)

    def get_shap_background(self) -> np.ndarray:
        """Return background data for SHAP KernelExplainer (scaler mean in scaled space = zeros)."""
        if self._scaler_mean is None:
            return np.zeros((1, N_FEATURES), dtype=np.float32)
        return self._scaler_mean


artifacts = ModelArtifacts()
