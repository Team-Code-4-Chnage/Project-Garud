# Project Garud

Project Garud is a network-flow security analysis platform. A FastAPI backend accepts flow telemetry, stores sessions and alerts in SQLite, scores six-flow windows with PyTorch models, and exposes REST/WebSocket APIs. A React/Vite frontend presents prediction, forecasting, explainability, alert, topology, and forensic-report views.

[Architecture](ARCHITECTURE.md) · [Model Card](docs/model_card.md) · [Setup Guide](setup/README.md)

## Current Model

### Per-flow model

The production artifact in `backend/artifacts/` is a two-layer LSTM that consumes six consecutive flows with 22 configured features. It produces next-flow state estimates, infiltration probability, and one of six dataset-derived stage labels.

`backend/app/model_loader.py` loads `world_model.pt`, `scaler.pkl`, and `config.json`. The model is used by `/predict`, `/forecast`, ingestion, alerts, and explainability routes. Stage labels are dataset proxies, not verified attacker kill-chain stages.

### Network-state model

The network-state path aggregates flows into one-minute state vectors and rolls the last six minutes forward. Its implementation is in `backend/app/network_state.py`, with training utilities in `worldmodel_v2/` and `worldmodel_v3/`. The served artifact is in `backend/artifacts_v3/`; the API is exposed through `/network/sources`, `/network/forecast`, and `/network/reset`.

## Manual Setup

### Prerequisites

- Python 3.10 or newer.
- Node.js and npm.
- A PyTorch installation supported by the host.
- Optional Scapy support when using PCAP ingestion.

### Backend

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

The API is available at `http://localhost:8000`. OpenAPI documentation is available at `/docs`; health status is available at `/health`.

### Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The dashboard runs at `http://localhost:5173`. Set `VITE_API_URL` when the backend is not running at `http://localhost:8000`.

### Environment

Copy `.env.example` to `.env` and review these settings:

| Variable | Purpose |
| --- | --- |
| `ARTIFACTS_DIR` | Per-flow model artifact directory. |
| `ARTIFACTS_V3_DIR` | Network-state artifact directory. |
| `DB_DIR` | SQLite persistence directory. |
| `ALERT_THRESHOLD` | Base alert probability threshold. |
| `ADAPTIVE_THRESHOLD` | Enables adaptive thresholding when set to `1`. |
| `API_KEY` | Optional `X-API-Key` authentication. |
| `FRONTEND_URL` | Allowed frontend origins. |
| `VITE_API_URL` | Frontend backend URL. |
| `VITE_API_KEY` | Optional frontend API key. |

## PCAP Ingestion

PCAP upload uses the shared flow reconstruction code in `capture/flow_table.py` and `capture/flow_state.py`. The extractor produces configured flow features before the backend stores and scores them.

Upload a `.pcap` or `.pcapng` file through the dashboard or directly:

```bash
curl -X POST http://localhost:8000/ingest/pcap \
  -F "file=@sample_attack.pcap"
```

PCAP parity utilities and their limitations are documented in [docs/pcap_parity.md](docs/pcap_parity.md).

## Retraining

Retraining is manual:

```text
raw CIC-IDS data
    -> preprocessing and label mapping
    -> optional Initial Access and Lateral Movement augmentation
    -> session/window construction
    -> train/validation/test split
    -> PyTorch training
    -> evaluation and calibration
    -> backend/artifacts/
```

Prepare data with:

```bash
python data/download_cicids.py
python data/preprocess_cicids.py --input-dir data/raw_cicids --output real_flows.csv
python data/augment_lateral_movement.py --target real_flows.csv
python data/augment_initial_access.py --target real_flows.csv
python data/fix_initial_access_sessions.py --target real_flows.csv
```

Train the per-flow artifact:

```bash
python pipeline_fixed.py \
  --data real_flows.csv \
  --out backend/artifacts \
  --epochs 20 \
  --batch-size 128 \
  --hidden-size 256 \
  --num-layers 2 \
  --dropout 0.25 \
  --stage-target current
```

The output contains `world_model.pt`, `scaler.pkl`, `config.json`, and the benchmark CSV. Run `python experiments/calibrate_stage_logits.py` only when recalibrating a newly trained artifact. Do not replace shipped artifacts until evaluation and backend tests pass.

The network-state model has a separate workflow under `worldmodel_v2/` and `worldmodel_v3/`; its output is written to `backend/artifacts_v3/`.

## Experimentation

The `experiments/` directory contains offline analysis, not automatic retraining:

| Area | Entry points | Purpose |
| --- | --- | --- |
| Per-flow evaluation | `evaluate_model.py` | Held-out risk, stage, rollout, and deduplication metrics. |
| Stage calibration | `calibrate_stage_logits.py` | Validation-only per-class logit-bias search. |
| Generalization | `family_holdout_eval.py` | Attack-family holdout evaluation. |
| PCAP parity | `pcap_parity.py`, `pcap_model_parity.py` | Feature and model-decision parity studies. |
| Network-state evaluation | `worldmodel_v2/evaluate.py`, `worldmodel_v3/run_lodo.py`, `run_behaviour.py` | State and behavior forecasting studies. |
| Threshold analysis | `tune_infiltration_threshold.py` | Compare thresholds without changing deployment config. |

Committed JSON and CSV files are recorded experiment results; they do not trigger retraining or change the running service.

## API Endpoints

All routes are registered in `backend/app/main.py`. When `API_KEY` is configured, protected HTTP endpoints require `X-API-Key`. `/health`, `/docs`, `/openapi.json`, and `/redoc` are public.

### Service, prediction, and explainability

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service landing response. |
| `GET` | `/health` | Service and artifact health. |
| `POST` | `/predict` | Score a six-flow feature window. |
| `POST` | `/forecast` | Run a multi-step per-flow rollout. |
| `POST` | `/explain` | Explain a supplied feature window. |
| `GET` | `/explain/system` | Explain highest-risk stored sessions. |
| `GET` | `/forecast/view/html` | Render a forecast dossier. |
| `GET` | `/forecast/export/html` | Download forecast HTML. |
| `GET` | `/forecast/export/csv` | Download forecast CSV. |
| `GET` | `/forecast/export/json` | Download forecast JSON. |
| `GET` | `/explain/view/html` | Render an explanation dossier. |
| `GET` | `/explain/export/html` | Download explanation HTML. |
| `GET` | `/explain/export/csv` | Download feature attributions CSV. |
| `GET` | `/explain/export/json` | Download feature attributions JSON. |

### Ingestion and telemetry

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/ingest` | Ingest one flow record. |
| `POST` | `/ingest/csv` | Ingest flow records from CSV. |
| `POST` | `/ingest/pcap` | Reconstruct and ingest PCAP/PCAPNG flows. |
| `GET` | `/ingest/buffer-status` | Inspect session window buffers. |
| `GET` | `/sessions` | List stored sessions. |
| `GET` | `/sessions/{session_key}/flows` | List flows for one session. |
| `GET` | `/flows/recent` | List recent flows. |
| `GET` | `/dashboard/stats` | Dashboard aggregate statistics. |
| `GET` | `/dashboard/stage-distribution` | Session counts by stage. |

### Network state and topology

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/network/sources` | Summarize network-state sources. |
| `GET` | `/network/forecast` | Return minute-level network forecast. |
| `POST` | `/network/reset` | Reset network-state tracking. |
| `GET` | `/graph/topology` | Return session topology. |
| `GET` | `/graph/topology_geo` | Return topology with geographic data. |
| `GET` | `/graph/topology/summary` | Return topology summary. |
| `GET` | `/graph/geoip/{ip}` | Resolve an IP address. |
| `POST` | `/graph/geoip/clear_cache` | Clear GeoIP cache. |

### Alerts, reports, and mappings

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/alerts` | List alerts. |
| `GET` | `/alerts/stats` | Alert statistics. |
| `POST` | `/alerts/{alert_id}/acknowledge` | Acknowledge an alert. |
| `POST` | `/alerts/acknowledge-all` | Acknowledge all alerts. |
| `POST` | `/alerts/{alert_id}/contain` | Record containment. |
| `POST` | `/alerts/{alert_id}/revoke` | Revoke containment. |
| `GET` | `/alerts/containment/rules` | List containment rules. |
| `GET` | `/alerts/ledger/verify` | Verify alert ledger. |
| `GET` | `/alerts/ledger/blocks` | Read ledger blocks. |
| `POST` | `/alerts/clear` | Clear alert records. |
| `GET` | `/alerts/block-rules/export` | Export block rules. |
| `GET` | `/reports/view/html` | Render forensic report. |
| `GET` | `/reports/export/html` | Download forensic HTML. |
| `GET` | `/reports/export/csv` | Export forensic CSV. |
| `GET` | `/reports/export/json` | Export structured JSON. |
| `GET` | `/mitre/mapping` | List MITRE interpretations. |
| `GET` | `/mitre/lookup/{label}` | Resolve a stage or behavior label. |

### System and cycles

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/system/mode` | Read operating mode. |
| `POST` | `/system/mode` | Set `live` or `simulated` mode. |
| `POST` | `/system/simulator/start` | Start simulator. |
| `GET` | `/system/simulator/status` | Read simulator status. |
| `POST` | `/system/simulator/stop` | Stop simulator. |
| `POST` | `/system/capture/start` | Start capture process. |
| `GET` | `/system/capture/status` | Read capture status. |
| `POST` | `/system/capture/stop` | Stop capture process. |
| `POST` | `/system/purge-simulated` | Remove simulated records. |
| `POST` | `/system/cycle/start` | Archive current cycle and start another. |
| `GET` | `/system/cycle/current` | Read active cycle. |
| `GET` | `/system/cycles` | List archived cycles. |
| `GET` | `/system/cycles/{cycle_id}` | Read one archived cycle. |
| `POST` | `/system/device-location` | Update device location. |
| `GET` | `/system/host-identity` | Read host identity. |
| `GET` | `/system/drift` | Read drift-monitor state. |
| `WS` | `/ws/live` | WebSocket flow and dashboard stream. |
| `WS` | `/api/packets/ws` | WebSocket compatibility alias. |

## Directory Structure

```text
Project-Garud/
├── backend/app/             FastAPI app, inference, persistence, and routes
├── backend/artifacts/       Production per-flow model artifacts
├── backend/artifacts_v3/    Network-state model artifacts
├── backend/scripts/          Operational database utilities
├── backend/tests/            Backend and model tests
├── capture/                  Flow reconstruction, PCAP parsing, capture, signatures
├── data/                     Dataset download, preprocessing, augmentation
├── demo/                     Traffic simulator used by the system simulator
├── experiments/              Evaluation, calibration, parity, and research scripts
├── frontend/src/             React application and UI components
├── lab/                      Optional lab data-collection helpers
├── setup/                    Training/setup helper and documentation
├── worldmodel_v2/            Network-state training and evaluation
├── worldmodel_v3/            Network-state production workflow
├── pipeline_fixed.py         Per-flow model training pipeline
├── pyproject.toml            Python project and test configuration
├── .env.example              Runtime configuration template
├── ARCHITECTURE.md           Architecture overview and diagram
└── README.md                 Project documentation
```

## Validation

```bash
python3 -m compileall -q backend/app capture data experiments setup pipeline_fixed.py
python3 -m pytest backend/tests
cd frontend && npm run lint && npm run build
```

The backend test command requires `backend/requirements.txt`; model-dependent tests also require the committed artifacts.
