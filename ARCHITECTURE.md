# Architecture

This document describes what the code does today. Measured results are in [docs/model_card.md](docs/model_card.md).

## Overview

```text
 live capture (Scapy)     PCAP / PCAPNG via /ingest/pcap     CSV via /ingest/csv     POST /ingest
        |                        |                     |               |
        +------------------------+----------+----------+---------------+
                                            |
                          capture/flow_table.py + flow_state.py
                          (CICFlowMeter-style flow reconstruction, 22 features)
                                            |
                                  backend/app/ingestion.py
             validation, session resolution, SQLite persistence, WebSocket broadcast
                     |                                              |
        per-flow path (per session)                    network-state path (all flows)
        6-flow window -> LSTM model                    1-minute state vector -> LSTM model
        backend/app/inference.py                       backend/app/network_state.py
                     |                                              |
        plausibility rules, adaptive                   rule-based indicators blended with
        threshold, alert + ledger                      model output, sustained-alert rule
                     |                                              |
                     +---------------------+------------------------+
                                           |
                        REST + WebSocket API (FastAPI)  ->  React dashboard
```

The diagram is the live system. Uploads from the Offline Analysis page take a separate path that never reaches it (see "Offline analysis path" below).

## Components

### Flow extraction (`capture/`)

- `flow_table.py` and `flow_state.py` reconstruct bidirectional flows from packets and compute the 22 features the per-flow model expects. The same code serves live capture and PCAP upload. Feature parity with CICFlowMeter labelled data is checked by `backend/tests/test_cic_semantics.py`, `test_flow_parity.py` and `test_pcap_parity_real.py`; limits are in [docs/pcap_parity.md](docs/pcap_parity.md).
- `signatures.py` detects Heartbleed by parsing TLS heartbeat records in raw payloads. This is a deterministic signature, not a model output.
- `live_capture.py` runs as a separate process started by the system routes.

### Backend (`backend/app/`)

| Module | Responsibility |
| --- | --- |
| `main.py` | Application setup, CORS, optional API key, security headers, optional rate limiting, router registration |
| `table_reader.py` | Recognises the container and layout of an uploaded table by content (gzip, zip, Parquet, JSON, JSON lines, Zeek, delimited text in any encoding) and yields text chunks |
| `flow_schema.py` | Converts CICFlowMeter, Zeek, Suricata, nfdump, NetFlow, UNSW-NB15 and Garud tables to the 22 features: column recognition, derived features, unit and date checks, and a report of every assumption |
| `labels.py` | Maps attack labels of public datasets (and 0/1, normal/attack) to the behaviour classes |
| `flow_classifier.py` | Loads the real-data flow classifier (`backend/artifacts_flow/`) and scores flows in batches |
| `offline_analysis.py`, `routes/offline.py` | Isolated analysis of uploaded files (see below); no database, live tracker or WebSocket access |
| `upload_ingest.py` | Streaming and bulk ingestion for `/ingest/csv` and `/ingest/pcap` (live system) |
| `ingestion.py` | Validates flows, resolves sessions, keeps per-session windows, calls the models, creates alerts, broadcasts events |
| `model_loader.py`, `inference.py` | Loads the per-flow model; single prediction, rollout with Monte Carlo input noise, SHAP and gradient attribution |
| `network_state.py` | Per-minute network state, network-state model, forecast payload, sustained-alert rule |
| `database.py` | Async SQLite models: flows, sessions, alerts, cycle archives |
| `drift.py` | Compares live feature distributions with baseline statistics |
| `geoip.py`, `graph_state.py`, `routes/graph.py` | GeoIP lookup (in-memory cache only) and topology graph |
| `mitre.py` | Analyst-written mapping from behaviour classes to ATT&CK techniques, with reasoning and an ambiguity flag |
| `routes/` | HTTP and WebSocket endpoints; the list is in the README |

SQLite file: `backend/data/forecaster.db`. Operating cycles are archived as JSON in `backend/data/archives/`.

### Per-flow model (`backend/artifacts/`)

Two-layer LSTM (hidden 256, dropout 0.25) over a window of 6 flows x 22 features, standardised with `scaler.pkl`. Three heads: next-flow feature regression, a malicious-probability head, and a 6-class stage head (Benign, Reconnaissance, Initial Access, Lateral Movement, C2, Exfiltration). A per-class logit bias from `config.json` is applied to the stage logits. Forecasting rolls the next-state head forward and re-scores each predicted state.

The shipped weights were trained on synthetic sessions (see the model card). Stage names are labels of that synthetic generator.

### Rule layer around the per-flow model (`ingestion.py`)

Model output is post-processed before it becomes an alert:

- Adaptive threshold: exponential moving average plus two standard deviations of the session's recent probabilities, bounded by the configured base threshold and 0.95.
- `validate_attack_plausibility` forces the stage to Benign for trusted local processes, for live-capture traffic on ports 53, 80, 443, 8080 and 8443, for outbound "Lateral Movement", and for live-capture "Reconnaissance".
- If the malicious head fires while the stage head says Benign, the stage is set to Initial Access (web ports) or Reconnaissance (other ports).
- A Heartbleed signature match raises a critical alert regardless of the model.

These are hand-written rules. They reduce false alarms on the local host's own traffic and they also mean the reported stage is not always the model's argmax.

### Network-state model (`backend/artifacts_v3/`, `worldmodel_v3/`)

- `worldmodel_v3/state.py` builds one 45-dimensional state per minute from all flows: volume, duration and inter-arrival statistics, flag ratios, unique address and port counts, entropies, protocol shares, connection rates. IP addresses are never features.
- The model is a two-layer LSTM (hidden 128, dropout 0.3) over 6 minutes. It rolls forward 4 minutes and predicts the state, a risk value and a behaviour class (Benign, PortScan, BruteForce, DoS, DDoS, WebAttack, Bot, Infiltration, Heartbleed) for each step.
- Alert rule (in `config.json`): the maximum predicted risk over the next 4 minutes must reach 0.518 for at least 5 consecutive minutes. Threshold and length were chosen on validation segments under a false-alarm budget.
- The same state builder (`worldmodel_v3/state.py`) is used for training data and at serving time.

### Rules applied on top of the network-state model (`network_state.py`)

The forecast shown to the user is not only model output:

- `compute_empirical_threat` scores each minute with fixed thresholds on port fan-out, port entropy, SYN/RST ratios, connection rate, byte counts and similar, and assigns a stage from five rule families.
- `STAGE_CALIBRATED_RISK` maps a stage label carried by ingested flows to a constant risk (for example 0.68 for Reconnaissance, 0.94 for Exfiltration).
- The per-minute risk is the model risk capped to 0.10 to 0.16 on benign minutes, or the larger of the model risk and the rule score on attack minutes.
- The forecast for the next four minutes is the model risk, raised to a projection of the recent rule score: growing toward 0.99 while a threat is current and not falling, decaying by a factor of 0.92 per minute after it stops.
- In live mode, when the newest flow is older than 3 minutes the current risk is reported as 0.08 (idle baseline).
- When fewer than 6 minutes of data exist, the status is `warming_up` and the model runs on a zero-padded window.

These constants and thresholds are engineering choices, not trained values.

### Offline analysis path (`offline_analysis.py`)

```text
uploaded file -> table_reader (container, layout) -> flow_schema (22 features, time, labels, report)
   -> completion of missing structure (synthetic timeline only if no timestamps; blocks of 30 rows if no addresses)
   -> flow_classifier (attack probability, behaviour, confidence per flow)   [labels from the file kept as truth]
   -> per-minute network state (worldmodel_v3.state) on the file's own dates, split at silences over 60 minutes
   -> network-state model on every window of every activity period (no rules, caps or blending)
   -> forecast for the next 4 minutes, and with labels a back-test of every forecast issued in the period
```

The path has its own copy of the state builder inputs and never calls the live tracker's `add`, `analyze` or database code, so an upload cannot change live sessions, alerts, logs, the map or the live forecast. The result is returned as one JSON document; nothing is stored on the server.

Complexity is linear in the number of flows: reading and conversion in 50,000-row chunks, classification in batches of 250,000, the network model over the minutes of each period. Measured: about 15,000 flows per second, about 1.2 KB of memory per flow.

### Flow classifier (`backend/artifacts_flow/`, `flowclf/`)

A gradient-boosted classifier (scikit-learn `HistGradientBoostingClassifier`) over the 22 features of a single flow, with nine output classes (Benign plus eight behaviours). The attack probability is 1 - P(Benign); flows at or above 0.5 are flagged. It uses no session, address or time information, so it works on any table the converter can read. Training data, split and measured results are in `backend/artifacts_flow/config.json` and the model card. The split is the network-state model's: the last 25% of each capture day are held out from everything.

### Frontend (`frontend/src/`)

React 19 with Vite, Recharts for charts and Leaflet for the map. `App.jsx` handles navigation, health polling and the WebSocket connection. Views: dashboard, live logs, alerts, network forecast and map, explainability, reports, ingestion, settings. All data comes from the backend through `api.js`; the model result panel on the forecast view reads the served model's `config.json`.

### Modes

- `live`: real capture or uploaded files. Simulated flows are ignored.
- `simulated`: `demo/traffic_simulator.py` produces synthetic attack scenarios for demonstration. Data from this mode is marked with source `simulated` and can be purged.

## Training and evaluation code

| Path | Purpose |
| --- | --- |
| `setup/run_all.py` | Generates synthetic campaigns and trains the per-flow model |
| `pipeline_fixed.py` | Per-flow training pipeline for real flow data |
| `worldmodel_v3/` | Network-state model, state builder, training, leave-one-day-out and behaviour studies |
| `flowclf/` | Flow classifier training and held-out evaluation |
| `data/` | Dataset download, preprocessing, augmentation, window builder |
| `experiments/` | Evaluation, calibration, parity and replay scripts with recorded JSON outputs |
| `lab/` | Isolated-lab data collection (see [LAB_SETUP.md](LAB_SETUP.md)) |

Recorded JSON files in `experiments/` (`v3_*.json`) are outputs of the leave-one-day-out and behaviour studies in `worldmodel_v3/`.
