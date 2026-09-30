# Project Garud

Network-flow monitoring and attack-forecasting platform, built for Smart India Hackathon 2026 (problem statement 26153, *AI Based Network Attack Forecasting from Network Traffic Data*).

A FastAPI backend ingests network flows (live capture, PCAP files, tables, API), scores them with PyTorch and scikit-learn models, stores sessions and alerts in SQLite, and serves a React dashboard with a live map, alert console, network-wide forecast, explainability views, exportable reports and an isolated offline analysis of uploaded files.

Documentation: [Architecture](ARCHITECTURE.md) | [Model card and measured results](docs/model_card.md) | [Lab data collection](LAB_SETUP.md)

## Read this first: what the models can and cannot do

The repository ships three models. Their evidence is very different, so the numbers must not be mixed.

| | Per-flow LSTM | Network-state model | Flow classifier |
| --- | --- | --- | --- |
| Location | `backend/artifacts/` | `backend/artifacts_v3/` | `backend/artifacts_flow/` |
| Used by | live ingestion, alerts, `/predict` | live network forecast, offline forecast | offline analysis (labels, flags) |
| Input | 6 flows of one session, 22 features | 6 one-minute network states, 45 features | one flow, 22 features |
| Output | next-flow risk, 6 stage labels | risk and behaviour for the next 4 minutes | attack probability and behaviour |
| Trained on | 200 **synthetic** sessions (`setup/run_all.py`, hand-written Gaussian profiles) | CIC-IDS2017 (5 days) | CIC-IDS2017 (8 files, 2.0 M flows before the held-out cut) |
| Held-out result | F1 0.988 on its own synthetic data; on real flows ROC-AUC 0.53 (chance) | F1 0.52, ROC-AUC 0.83 on the last 25% of each day | ROC-AUC 0.92, F1 0.73, false-positive rate 3.9% on the last 25% of each day (families unseen in training are largely missed) |

Consequences, stated plainly:

- The per-flow LSTM separates its own synthetic classes almost perfectly and does **not** transfer to real traffic. Its stage labels are labels of the synthetic generator, not verified attacker behaviour. It still drives live alerts; use the offline analysis for anything that must rest on real-data models.
- The network-state model is trained on real traffic, but CIC-IDS2017 contains no multi-stage campaign. Only attack behaviour classes exist, and the behaviour forecast shows no skill over persistence.
- The flow classifier finds behaviours it was trained on. On the held-out segments: PortScan 99.7% and BruteForce 95.9% of flows detected; DDoS, which is absent from its training rows, 61.9% detected but never named correctly; Heartbleed and Infiltration (11 and 18 flows) not detected. Other datasets and capture environments can be poorly separated (CSE-CIC-IDS2018 infiltration: ROC-AUC 0.45).
- The risk value on the dashboard's live network forecast is not raw model output. `backend/app/network_state.py` combines the model with rule-based indicators and per-stage constants (see the architecture file). The offline analysis shows the network model's own output without those rules.
- This is a research prototype. It is not validated for production defence.

Every figure above is reproducible with the commands in [docs/model_card.md](docs/model_card.md).

## Features

- Flow ingestion from live capture (Scapy), file upload and REST. Flow reconstruction follows CICFlowMeter definitions; parity checks are in [docs/pcap_parity.md](docs/pcap_parity.md).
- Offline file analysis (Offline Analysis page): upload any flow table or capture of any size; the layout is recognised, converted to the model's 22 features, labelled (the file's own labels, or predicted ones) and forecast on the dates inside the file, without adding anything to live sessions, alerts, logs, the map or the live forecast.
- Per-session scoring, multi-step rollout with Monte Carlo spread, adaptive alert threshold, SHAP and gradient attributions.
- Network-wide one-minute state and a 4-minute forecast with a sustained-alert rule.
- Heartbleed signature detection on raw TLS heartbeat records.
- Alert console with a SHA-256 hash-chained ledger, containment records and exportable firewall rules.
- Topology graph and world map. Locations come from live GeoIP lookups; addresses that cannot be located are not plotted.
- MITRE ATT&CK mapping of behaviour classes (`backend/app/mitre.py`), written by the authors and not learned by any model.
- Input drift monitor, forensic report export (HTML, CSV, JSON), operating cycles with archives.

## Requirements

- Python 3.10 or newer (CI uses 3.11), Node.js and npm
- PyTorch (a CPU build is sufficient)
- Npcap (Windows) or libpcap (Linux) and administrator rights for live capture
- Optional: `slowapi` for rate limiting; `pyarrow` for Parquet files (both in `requirements.txt`)

## Run

Backend, from the repository root:

```bash
python -m venv backend/venv
backend/venv/Scripts/activate          # Linux/macOS: source backend/venv/bin/activate
pip install -r backend/requirements.txt
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Frontend, in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The dashboard is at `http://localhost:5173`, the API at `http://localhost:8000` (`/docs` for OpenAPI, `/health` for status). On Windows, `start_all.ps1` starts both.

Docker images for the two parts are defined in `backend/Dockerfile` and `frontend/Dockerfile`. The backend image expects the repository root as build context.

## Configuration

Copy `.env.example` to `.env`.

| Variable | Purpose |
| --- | --- |
| `ARTIFACTS_DIR` | Per-flow model directory (default `backend/artifacts`) |
| `ARTIFACTS_V3_DIR` | Network-state model directory (default `backend/artifacts_v3`) |
| `DB_DIR` | Directory of the SQLite file `forecaster.db` (default `backend/data`) |
| `ALERT_THRESHOLD` | Base alert probability threshold |
| `ADAPTIVE_THRESHOLD` | `1` enables the adaptive threshold |
| `AUTO_START_CAPTURE` | `1` (default) starts the live sniffer with the service; `0` disables it |
| `API_KEY` | If set, HTTP endpoints require the `X-API-Key` header (`/health`, `/docs` and WebSockets excluded) |
| `FRONTEND_URL` | Allowed CORS origins |
| `VITE_API_URL`, `VITE_API_KEY` | Backend URL and key used by the frontend |

## API

All routes are registered in `backend/app/main.py`; the interactive reference is served at `/docs`.

| Area | Routes |
| --- | --- |
| Service | `GET /`, `GET /health` |
| Prediction | `POST /predict`, `POST /forecast`, `POST /explain`, `GET /explain/system` |
| Ingestion (live system) | `POST /ingest`, `POST /ingest/csv`, `POST /ingest/pcap`, `GET /ingest/buffer-status` |
| Offline analysis (isolated) | `POST /offline/analyze`, `POST /offline/convert` |
| Data | `GET /sessions`, `GET /sessions/{session_key}/flows`, `GET /flows/recent`, `GET /dashboard/stats`, `GET /dashboard/stage-distribution` |
| Network state | `GET /network/forecast`, `GET /network/sources`, `POST /network/reset` |
| Topology | `GET /graph/topology`, `GET /graph/topology_geo`, `GET /graph/topology/summary`, `GET /graph/geoip/{ip}`, `POST /graph/geoip/clear_cache` |
| Alerts | `GET /alerts`, `GET /alerts/stats`, `POST /alerts/{id}/acknowledge`, `POST /alerts/acknowledge-all`, `POST /alerts/{id}/contain`, `POST /alerts/{id}/revoke`, `POST /alerts/clear`, `GET /alerts/containment/rules`, `GET /alerts/block-rules/export`, `GET /alerts/ledger/verify`, `GET /alerts/ledger/blocks` |
| Reports | `/reports/view/html`, `/reports/export/{html,csv,json}`; the same view and export routes exist under `/forecast` and `/explain` |
| MITRE | `GET /mitre/mapping`, `GET /mitre/lookup/{label}` |
| System | `GET/POST /system/mode`, `/system/simulator/{start,stop,status}`, `/system/capture/{start,stop,status}`, `POST /system/purge-simulated`, `/system/cycle/*`, `GET /system/cycles`, `GET /system/drift`, `GET /system/host-identity`, `POST /system/device-location` |
| WebSocket | `/ws/live`, `/api/packets/ws` |

## Offline analysis of uploaded files

`POST /offline/analyze` (the Offline Analysis page) accepts any file and does everything automatically. The analysis runs in memory and is isolated from the live system: it writes nothing to the database, creates no alert or session, sends no WebSocket event and does not feed the live forecast (`test_offline_analysis_never_touches_the_live_system` compares the dashboard, alert, topology, flow and network-state endpoints before and after uploads). There is no size limit.

**1. Reading.** The container and layout are recognised from the content, not the name: PCAP/PCAPNG; gzip and zip; Parquet; JSON arrays, JSON lines and nested records (Suricata eve.json); Zeek logs with a `#fields` header; delimited text with comma, semicolon, tab or pipe, UTF-8 or UTF-16, BOM, comment lines, ragged rows, decimal commas, thousands separators, and headerless files that hold the 22 features in order. Excel workbooks are refused with an instruction to save as CSV.

**2. Conversion to the 22 features.** Columns are matched by normalised name across CICFlowMeter, Zeek, Suricata, nfdump, Argus, NetFlow, UNSW-NB15 and the project's own layout. Each feature is read directly, derived from other columns (for example bytes and packets give mean packet length; Zeek history letters give flag counts), or set to 0 when the source cannot provide it, as the training pipeline does. Infinite or missing values become 0. The duration unit is checked against the packet rate columns and corrected when wrong. `POST /offline/convert` returns the converted table plus predicted labels as a CSV.

**3. Time.** The forecast runs on the dates in the file: ISO strings, day-first or month-first slash dates (decided from unambiguous rows), epoch seconds to nanoseconds, Excel serial dates, separate date and time columns, time zone offsets (converted to UTC). Rows are sorted by time. Traffic silent for more than an hour splits the file into activity periods, each forecast on its own. Only when a file has no usable timestamps is a synthetic time axis used (20 or more rows per minute), and the report and charts say so.

**4. Labels.** If the file has a label column, its values are mapped to behaviours (`backend/app/labels.py`: CIC-IDS2017/2018 and UNSW names, 0/1, normal/attack) and kept as ground truth. Otherwise every flow gets a predicted behaviour, attack probability and confidence from the flow classifier, and the report claims no accuracy because there is no ground truth. Files without addresses are grouped in blocks of 30 consecutive rows.

**5. Forecast and evaluation.** For each activity period the network-state model's own output is shown for the next 4 minutes: risk, the three most likely behaviours and predicted network state, without rules, caps or blending. With labels the report adds a back-test of every forecast issued in the period (ROC-AUC per horizon, early warning and false alarms under the model's alert rule, next-minute behaviour accuracy), the model's state-prediction error against repeating the last minute, and the flow classifier's precision, recall, false-positive rate and ROC-AUC per attack family.

Every assumption made for a file is listed in its report. Measured on the development machine: about 15,000 flows per second end to end (500,000 flows in 27 to 33 seconds, 550 to 670 MB of memory).

Sample files (`python data/make_offline_sample.py` regenerates them; the 2017 file needs `python data/fetch_cic2017_labelled.py` first):

| File | Content | What it shows |
| --- | --- | --- |
| `data/samples/cic2017_tuesday_ssh_patator_heldout.csv.gz` | 49,576 real CIC-IDS2017 flows, Tuesday 2017-07-04 17:59 to 19:00, real addresses and timestamps, original columns, real labels (1,097 SSH-Patator flows, ending about 18:13) | Held out from both served models. Flow classifier: recall 0.96, false-positive rate 0.35%, ROC-AUC 0.996. Forecast back-test: ROC-AUC 0.63 to 0.64 per horizon on 13 attack minutes; state prediction beats repeating the last minute |
| `data/samples/cic2018_infiltration_sample.csv` | 5,828 real CSE-CIC-IDS2018 flows (28 Feb 2018, every 30th flow), no addresses | The conversion of a table without addresses, day-first dates and negative values. A hard, out-of-domain case: flow classifier ROC-AUC 0.45; forecast back-test ROC-AUC about 0.74 |

Speed of the live-ingestion path (`/ingest/csv`, `/ingest/pcap`): about 250 flows per second, limited by the LSTM scoring one flow at a time.

## Repository layout

```text
backend/app/            FastAPI application: routes, inference, network state, persistence, GeoIP
backend/artifacts/      Per-flow model (weights, scaler, config)
backend/artifacts_v3/   Network-state model (weights, config)
backend/artifacts_flow/ Flow classifier (model, config with measured results)
backend/tests/          Test suite
capture/                Flow reconstruction, packet parsing, live capture, signatures
data/                   Dataset download, preprocessing and window building; netwin_1min.csv.gz; samples/ (offline-analysis test files)
demo/                   Traffic simulator used by simulated mode
docs/                   Model card and research reports
experiments/            Evaluation scripts and their recorded JSON outputs
flowclf/                Flow classifier training
frontend/src/           React application
lab/                    Isolated-lab data collection helpers
setup/run_all.py        Synthetic campaign generator and per-flow model trainer
worldmodel_v3/          Network-state model, state builder, training and studies (served)
pipeline_fixed.py       Per-flow training pipeline used by the evaluation scripts
```

## Tests and lint

```bash
cd backend
python -m pytest tests -m "not requires_model"      # runs in CI
python -m pytest tests -m requires_model            # model quality, see note
ruff check app
cd ../frontend && npm run lint && npm run build
```

Note: 10 of the `requires_model` tests currently fail. They check the per-flow model against real CIC-IDS2017 sessions, and the shipped model, trained on synthetic data, does not pass them. This is expected given the results above and is kept visible on purpose.

## Retraining

Network-state model (real data, reproducible in about 20 seconds from the committed windows):

```bash
python -m worldmodel_v3.train_production --out backend/artifacts_v3
```

Flow classifier (real data; needs the labelled CIC-IDS2017 files, about 350 MB, a few minutes to train):

```bash
python data/fetch_cic2017_labelled.py
python -m flowclf.train
```

Per-flow LSTM on synthetic campaigns (how the shipped weights were made):

```bash
python setup/run_all.py --mode scratch
```

Per-flow LSTM on real CIC-IDS2017 flows (needs the raw data, about 1 GB):

```bash
python data/download_cicids.py
python data/preprocess_cicids.py --input-dir data/raw_cicids --output real_flows.csv
python pipeline_fixed.py --data real_flows.csv --out backend/artifacts --epochs 20
```

Do not replace shipped artifacts before running the evaluation in [docs/model_card.md](docs/model_card.md).

## Datasets in this repository

| File | Content |
| --- | --- |
| `data/netwin_1min.csv.gz` | One-minute network windows built from CIC-IDS2017 labelled flows; training data of the served model |
| `campaign_dataset.csv` | 5,785 synthetic flows in 200 sessions; training data of the shipped per-flow LSTM |
| `data/cic2017_labelled/` (not tracked) | CIC-IDS2017 labelled flows with addresses and timestamps, from `fetch_cic2017_labelled.py`; training data of the flow classifier |
| `data/samples/` | Two real-data files for the offline analysis |
| `real_flows.csv` (not tracked) | Merged real and augmented flows used by the earlier per-flow model and by `experiments/evaluate_model.py` |

## Limitations

- Per-flow LSTM: trained on synthetic data; no evidence of detection on real traffic.
- Flow classifier: supervised, so families it has not seen are largely missed; 22 features from a flow table cannot separate every dataset (see above).
- Network-state model: 3 attack episodes in its test segments, so early-warning skill cannot be estimated; attack families in the test segments were seen in training; the internal/external split used by the feature builder is hard-coded to the CIC-IDS2017 testbed (192.168.0.0/16).
- Behaviour and stage forecasting: no skill over persistence on the available data.
- The network-state feature builder was validated on the committed CIC windows and an API replay of one day; it has not been evaluated on live captures.
- GeoIP uses public lookup services and needs internet access.
