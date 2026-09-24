import logging

import numpy as np
import torch

from .config import (
    DEFAULT_K_STEPS,
    DEFAULT_MC_NOISE_STD,
    DEFAULT_MC_SAMPLES,
    DEFAULT_THRESHOLD,
    EMA_ALPHA,
    N_FEATURES,
    STAGES,
    WINDOW_SIZE,
)
from .model_loader import artifacts

logger = logging.getLogger(__name__)


def _ensure_loaded():
    if not artifacts.is_loaded:
        raise RuntimeError(
            "Model artifacts not loaded. The server failed to initialize properly. "
            "Check startup logs."
        )


def predict_single(window: np.ndarray) -> dict:
    _ensure_loaded()

    if window.shape != (WINDOW_SIZE, N_FEATURES):
        raise ValueError(f"Window shape {window.shape}, expected ({WINDOW_SIZE}, {N_FEATURES})")

    model = artifacts.model
    device = artifacts.device

    x = torch.tensor(window, dtype=torch.float32).unsqueeze(0).to(device)
    with torch.no_grad():
        next_state, inf_logit, stage_logits = model(x)
        stage_logits = stage_logits + artifacts.stage_logit_bias

    prob = torch.sigmoid(inf_logit).item()
    stage_id = torch.argmax(stage_logits, dim=1).item()
    stage = STAGES[stage_id]

    return {
        "infiltration_probability": round(prob, 6),
        "predicted_stage": stage,
        "predicted_stage_id": stage_id,
        "is_alert": prob > DEFAULT_THRESHOLD,
        "threshold": DEFAULT_THRESHOLD,
    }


def forward_simulate(
    initial_window: np.ndarray,
    k_steps: int = DEFAULT_K_STEPS,
    noise_std: float = 0.0,
) -> list[dict]:
    _ensure_loaded()
    model = artifacts.model
    device = artifacts.device

    window = torch.tensor(initial_window, dtype=torch.float32).unsqueeze(0).to(device)
    if noise_std > 0:
        window = window + torch.randn_like(window) * noise_std

    timeline = []
    with torch.no_grad():
        for step in range(k_steps):
            next_state, inf_logit, stage_logits = model(window)
            stage_logits = stage_logits + artifacts.stage_logit_bias
            prob = torch.sigmoid(inf_logit).item()
            stage = STAGES[torch.argmax(stage_logits, dim=1).item()]
            timeline.append({
                "step": step + 1,
                "infiltration_prob": prob,
                "predicted_stage": stage,
            })
            window = torch.cat(
                [window[:, 1:, :], next_state.unsqueeze(1)], dim=1
            )

    return timeline


def ema_smooth(probs: list[float], alpha: float = EMA_ALPHA) -> list[float]:
    smoothed = [probs[0]]
    for p in probs[1:]:
        smoothed.append(alpha * p + (1 - alpha) * smoothed[-1])
    return smoothed


def forecast_rollout(
    window: np.ndarray,
    k_steps: int = DEFAULT_K_STEPS,
    n_mc_samples: int = DEFAULT_MC_SAMPLES,
    noise_std: float = DEFAULT_MC_NOISE_STD,
) -> dict:
    _ensure_loaded()

    all_probs = np.zeros((n_mc_samples, k_steps))
    all_stages: list[list[str]] = [[None] * k_steps for _ in range(n_mc_samples)]

    for i in range(n_mc_samples):
        run = forward_simulate(window, k_steps=k_steps, noise_std=noise_std)
        for step_data in run:
            idx = step_data["step"] - 1
            all_probs[i, idx] = step_data["infiltration_prob"]
            all_stages[i][idx] = step_data["predicted_stage"]

    mean_probs = all_probs.mean(axis=0)
    std_probs = all_probs.std(axis=0)
    ema_probs = ema_smooth(mean_probs.tolist())

    mode_stages = []
    for col in zip(*all_stages):
        counts = {s: col.count(s) for s in set(col)}
        best = sorted(counts.items(), key=lambda kv: (-kv[1], STAGES.index(kv[0])))[0][0]
        mode_stages.append(best)

    steps = []
    alert_triggered = False
    alert_at_step = None
    for i in range(k_steps):
        steps.append({
            "step": i + 1,
            "infiltration_prob_mean": round(float(mean_probs[i]), 6),
            "infiltration_prob_std": round(float(std_probs[i]), 6),
            "infiltration_prob_ema": round(float(ema_probs[i]), 6),
            "predicted_stage": mode_stages[i],
        })
        if mean_probs[i] > DEFAULT_THRESHOLD and not alert_triggered:
            alert_triggered = True
            alert_at_step = i + 1

    return {
        "steps": steps,
        "threshold": DEFAULT_THRESHOLD,
        "alert_triggered": alert_triggered,
        "alert_at_step": alert_at_step,
    }


def explain_window(window: np.ndarray, top_k: int = 10) -> dict:
    _ensure_loaded()
    model = artifacts.model
    device = artifacts.device

    x = torch.tensor(window, dtype=torch.float32).unsqueeze(0).to(device)
    x.requires_grad_(True)

    next_state, inf_logit, stage_logits = model(x)
    inf_logit.backward()
    grads = x.grad.detach().cpu().numpy()[0]
    input_vals = x.detach().cpu().numpy()[0]

    attributions = (grads * input_vals).mean(axis=0)

    indices = np.argsort(np.abs(attributions))[::-1][:top_k]
    from .config import FLOW_FEATURES

    result = []
    for idx in indices:
        result.append({
            "feature": FLOW_FEATURES[idx],
            "importance": round(float(attributions[idx]), 6),
            "direction": "malicious" if attributions[idx] > 0 else "benign",
        })

    pred = predict_single(window)

    return {
        "attributions": result,
        "infiltration_probability": pred["infiltration_probability"],
        "predicted_stage": pred["predicted_stage"],
        "method_used": "gradient",
    }


def explain_window_shap(
    window: np.ndarray,
    top_k: int = 10,
    n_samples: int = 50,
) -> dict:
    """
    Compute SHAP (Shapley Additive exPlanations) values for the input window.
    Uses KernelExplainer with a baseline background to attribute infiltration
    probability to individual features.
    Falls back gracefully to gradient attribution if SHAP encounters an issue.
    """
    _ensure_loaded()
    model = artifacts.model
    device = artifacts.device

    try:
        import shap

        def predict_fn(flat_windows: np.ndarray) -> np.ndarray:
            x_tensor = torch.tensor(
                flat_windows.reshape(-1, WINDOW_SIZE, N_FEATURES),
                dtype=torch.float32,
            ).to(device)
            with torch.no_grad():
                _, inf_logit, _ = model(x_tensor)
                probs = torch.sigmoid(inf_logit).cpu().numpy()
            return probs

        background = np.zeros((1, WINDOW_SIZE * N_FEATURES), dtype=np.float32)
        explainer = shap.KernelExplainer(predict_fn, background)

        flat_input = window.reshape(1, WINDOW_SIZE * N_FEATURES)
        shap_vals = explainer.shap_values(
            flat_input, nsamples=n_samples, l1_reg="num_features(10)", silent=True
        )

        if isinstance(shap_vals, list):
            vals = shap_vals[0]
        else:
            vals = shap_vals

        val_grid = np.array(vals).reshape(WINDOW_SIZE, N_FEATURES)
        attributions = val_grid.mean(axis=0)
        method_used = "shap"
    except Exception as e:
        logger.warning("SHAP explanation failed (%s), falling back to gradient attribution", e)
        res = explain_window(window, top_k=top_k)
        res["method_used"] = "gradient_fallback"
        return res

    indices = np.argsort(np.abs(attributions))[::-1][:top_k]
    from .config import FLOW_FEATURES

    result = []
    for idx in indices:
        val = float(attributions[idx])
        result.append({
            "feature": FLOW_FEATURES[idx],
            "importance": round(val, 6),
            "direction": "malicious" if val > 0 else "benign",
        })

    pred = predict_single(window)

    return {
        "attributions": result,
        "infiltration_probability": pred["infiltration_probability"],
        "predicted_stage": pred["predicted_stage"],
        "method_used": method_used,
    }
