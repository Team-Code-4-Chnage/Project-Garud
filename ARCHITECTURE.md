# Project Garud / NetForecast — Architecture

**SIH 2026, Problem Statement 26153 (NTRO).** A defensive network world model: it learns the evolving state of
a network from flow telemetry, forecasts near-future state and attack risk, maps predicted behaviour to MITRE
ATT&CK, and explains each prediction. Two models are served side by side. Detailed numbers and methods are in
`docs/model_card.md`, `docs/world_model_v3_report.md`, and `docs/pcap_parity.md`; this is the 2-page overview.

## Pipeline

```
CSV flows ─┐
PCAP ──────┼─> flow extractor ─> 22 features ─> per-flow model (V1)   ─┐
Live NIC ──┘   (capture/flow_table.py,          + per-minute network   ├─> REST + WebSocket ─> React dashboard
               flow_state.py; CICFlowMeter        state ─> network       │   (alerts, forecast, explanation,
               semantics)                          world model (V3)     ─┘    MITRE, reports) + SQLite store
```

One extractor serves PCAP upload and live capture, reproducing the CICFlowMeter definitions the model was
trained on (padding, first-packet flag encoding, header-length, integer-microsecond timing). Verified against
the official CIC-IDS2017 flow files at 95–100% per-feature agreement, and the served model gives the same
alert on 99–100% of windows whether features come from a PCAP or the official CSV (`docs/pcap_parity.md`).

## Model 1 — per-flow world model (V1, `backend/artifacts/`)

Input: a window of 6 consecutive flows, each a 22-feature vector. A 2-layer LSTM (hidden 256, dropout 0.25)
feeds three heads: next-state regression (22-dim), an infiltration-risk logit, and a 6-way stage head. Loss is
MSE(next state) + pos-weighted BCE(risk) + class-weighted focal cross-entropy(stage). At inference it rolls
forward up to K steps (Monte-Carlo input noise for an uncertainty band); the stage head classifies the last
flow's stage. **Stage labels are dataset-derived proxies, not a verified kill chain** (e.g. the "C2" label was
trained on DoS traffic). Held-out (de-duplicated): infiltration ROC-AUC 0.948, F1 0.838, FPR 3.5%; it beats a
Logistic Regression baseline on the same split (F1 0.838 vs ~0.52). It does not demonstrate early warning.

The 22 features are the CICFlowMeter columns as `data/preprocess_cicids.py` derives them, so several carry that
tool's quirks: the flag columns are 0/1 bits of the flow's first packet (with SYN/PSH swapped), `ttl_variance`
is a header-length difference (not TTL), and `retransmit_cnt` is always 0. Real TTL, retransmission and
payload-size statistics are extracted separately (`FlowState.packet_features()`) and are **not** model inputs,
because no training data contains them. Full table and formulas: `docs/model_card.md`.

## Model 2 — network-state world model (V3, `backend/artifacts_v3/`, served)

State S(t) is the whole network aggregated over **one minute**: 45 features covering flow statistics plus
network context — unique source/destination hosts and ports, unique pairs, protocol mix, port and host
entropy, connection and new-connection rate, per-source destination-port/host spread, and scan/flag ratios
(`worldmodel_v3/state.py`, shared by the training-data builder and the backend). It excludes direction and
single-host-share features, which an ablation showed mostly encode the CIC testbed layout rather than attack
behaviour (`docs/world_model_v3_report.md` §14).

An LSTM is trained with genuine multi-step targets: from the last 6 minutes it predicts states, infiltration
risk, and behaviour class for t+1…t+4, using recursive rollout with scheduled teacher forcing so training
matches inference. A sustained-alert rule (risk ≥ threshold for N consecutive minutes) is frozen on validation
under a false-alarm budget; the shipped weights are the ones evaluated on the held-out test segment. Served via
`GET /network/forecast` and the NETWORK_FORECAST dashboard view, which also shows the model's measured
reliability and caveats.

Honest evaluation (chronological within-day split; families seen in training, later in the day): detection
ROC-AUC 0.83; state prediction beats a persistence baseline at t+2…t+4 but not at t+1; false alarms ~0.4 per
quiet hour after operating-point tuning. On attack families **never seen in training** (leave-one-day-out,
5 seeds): detection near chance (ROC-AUC ~0.56) and ~34% of episodes warned within 20 minutes. Behaviour
forecasting did not beat persistence. In an end-to-end replay of a real DDoS it detected the attack shortly
after onset, not before it. Net reading: strong at detection, weak at genuine forecasting — the limiting
factor is that open flow datasets contain no multi-stage campaign, which the `lab/` collection addresses.

## Explainability

Both models are explained from the actual prediction, no hard-coded values. V1: SHAP KernelExplainer (50
samples, training-mean baseline) with a gradient×input fast path, attributing the infiltration risk over the
22 features. V3: gradient×input of the forecast risk over the 45 network-state features, surfaced in the
dashboard as the drivers of each forecast.

## MITRE ATT&CK mapping

An analyst-written backend lookup (`backend/app/mitre.py`, `GET /mitre/mapping`), not a model output. It maps a
behaviour or stage label to techniques and tactics with a rationale and confidence, corrects the dataset
mislabels (DoS/DDoS → Impact, brute force → Credential Access, scanning → Reconnaissance/Discovery), and flags
ambiguous mappings. Verify IDs against the current ATT&CK release before external use.

## Deployment and safety

FastAPI backend, async SQLite store with cycle archiving, React/Vite dashboard; runs fully offline (one
optional Google-Fonts import). SlowAPI rate limiting (120/min per IP), optional `X-API-Key` (constant-time
compare; `/health`, `/docs`, `/ws` exempt), CORS restricted to `FRONTEND_URL`, Pydantic input validation,
`torch.no_grad()`/`eval()` inference. Live capture runs as its own elevated process posting to `/ingest`. A
mode gate rejects simulated traffic while in live mode. Docker Compose builds from the repo root so the backend
image includes the shared `capture/` and `worldmodel_*` code. The `lab/` harness generates multi-stage attack
data on an isolated VM network, refusing in code any target outside the configured lab subnet (`LAB_SETUP.md`).

## Reproducibility

Fixed seeds, committed weights and configs, and a committed 1-minute network-state dataset. Retrain: V1 via
`pipeline_fixed.py`; V3 via `worldmodel_v3/train_production.py`. Evaluate: `experiments/evaluate_model.py`,
`worldmodel_v3/run_lodo.py`, `experiments/pcap_parity.py`. ~100 automated tests cover inference, the flow
extractor's CICFlowMeter parity (incl. a real-traffic fixture), the network-state service, MITRE rules, and the
lab harness allow-list.
