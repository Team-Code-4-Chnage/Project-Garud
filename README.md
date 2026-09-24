<div align="center">

# Project Garud
### Autonomous Network Attack Forecasting & Deep World Model Telemetry Engine
**SIH 2026 — Problem Statement ID 26153 (National Technical Research Organisation)**
**Team: Code 4 Change • Repository: [Team-Code-4-Chnage/Project-Garud](https://github.com/Team-Code-4-Chnage/Project-Garud)**

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.x-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)](https://pytorch.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.0-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)](https://attack.mitre.org)
[![Dataset](https://img.shields.io/badge/Dataset-CIC--IDS2017-orange?style=for-the-badge)](https://www.unb.ca/cic/datasets/ids-2017.html)

[Quickstart](#quickstart) • [Architecture](ARCHITECTURE.md) • [Simulation Playbook](SIMULATION.md) • [Presentation Deck](PRESENTATION.md) • [Benchmarks](#benchmark-performance-on-cic-ids2017--cic-ids2018) • [API Reference](#api-endpoints) • [Lab Setup](LAB_SETUP.md)

</div>

---

## Executive Summary

Traditional network intrusion detection is reactive: it flags malicious behavior after a signature or anomalous payload has already crossed the wire. In a Critical Information Infrastructure (CII) or high-assurance enterprise perimeter, that's often too late — data has already been staged, privileges escalated, persistence established.

Project Garud (built around the NetForecast recurrent telemetry engine) takes a different approach. It trains a world model on sliding windows of network flow telemetry, so it predicts the *next* flow-feature vectors before the corresponding packets arrive, rather than only classifying packets already seen. Those predicted trajectories are mapped onto the 6-stage MITRE ATT&CK kill chain, giving an early read on where a session is heading, not just where it currently sits.

A few things this system does, beyond plain classification:

- Monte Carlo rollouts (k=6 steps, N=20 samples) give confidence intervals on the forecast instead of a single point estimate.
- An adaptive EMA threshold (mean + 2 standard deviations, tuned to live background traffic) keeps the alert rate sane instead of firing on every minor fluctuation.
- Every alert carries an explanation: SHAP (Shapley values) and gradient×input attribution both point to the specific telemetry features that drove the score.
- Live sockets are resolved back to local PIDs and executable names (`chrome.exe`, `python.exe`, `nmap.exe`), with IPs classified as host/LAN/NAT.
- Monitoring state survives server hot-reloads and tab switches, with on-demand archiving of a cycle's flows and sessions.
- Incident reports export as themed HTML, CSV, or JSON for SIEM ingestion or a printable dossier.

---

## Benchmark Performance on CIC-IDS2017 + CIC-IDS2018

Evaluated on 328,868 real-world flows — CIC-IDS2017 (all 8 capture days) plus 7,940 real Lateral
Movement (Infiltration) flows and 928 real Initial Access (Web Attack) flows pulled in from
CIC-IDS2018, added because CIC-IDS2017 alone only has around 36 real Lateral Movement examples in
its entire public release (see `data/augment_lateral_movement.py`, `data/augment_initial_access.py`).
A session-level 3-way split (1,481 train / 212 validation / 424 test sessions) means checkpoint
selection during training only ever looks at the validation set — the test set (58,945 windowed
sequences) is touched exactly once, for the numbers below, and its session boundary is computed
identically to every prior split in this project's history, so these numbers are directly
comparable to earlier ones.

| Model Architecture | F1-Score | Precision | Recall (Detection Rate) | False Positive Rate (FPR) | Latency (Inference, CPU) |
|---|:---:|:---:|:---:|:---:|:---:|
| Logistic Regression *(Linear Baseline)* | 0.535 | 0.694 | 0.436 | 6.42% | < 1 ms |
| Isolation Forest *(Unsupervised Baseline)* | 0.355 | 0.338 | 0.373 | 24.41% | ~ 8 ms |
| NetForecast World Model *(Proposed, MAX Config)* | **0.862** | **0.859** | **0.865** | **4.75%** | **~ 0.7 ms** (measured, single-window forward pass) |

> [!NOTE]
> The training pipeline uses a genuine 3-way train/val/test split for checkpoint selection, so these test numbers are honest — checkpoint selection never sees the test set. See `docs/model_card.md` §5 for details.

The table above is binary malicious-vs-benign detection, and shouldn't be read as "detects all 6 stages equally well" — per-stage capability varies a lot. Focal loss on the MITRE stage head (gamma=2, generalizing the earlier class-weighted cross-entropy — see `docs/model_card.md` §5) plus a tuned class-weight clip (6x, down from an initial 50x that over-corrected) and positive-weighted BCE (`pos_weight≈2.94`) get 86.5% recall at the binary level with a 4.75% FPR, well below the Isolation Forest baseline's 24.41% FPR. Benign, Reconnaissance, C2, and Lateral Movement are all reliably classified (F1 0.80–0.96, calibrated). Lateral Movement in particular reaches precision 98.5%, recall 86.5%, F1 0.92 on 857 real held-out test flows, after real CIC-IDS2018 Infiltration data replaced an earlier synthetic-oversampling attempt that a held-out evaluation confirmed did not transfer to real traffic.

Initial Access (web attacks) has been through three rounds of tuning — real CIC-IDS2018 web-attack data, a retuned class-weight clip, and post-hoc per-class logit-bias calibration (`experiments/calibrate_stage_logits.py`) — moving precision from 6.2% to 27.0% to 35.1% (recall 53%), roughly a 5.7x improvement overall. It's still the weakest of the six stages. The ML model does not detect Exfiltration on its own (0% recall — CIC-IDS2017 has only around 11 Heartbleed flows in its entire public release, 2 in this sample, too little to learn from), but Exfiltration/Heartbleed is separately covered by a deterministic signature detector (`capture/signatures.py`) that doesn't rely on ML at all: CVE-2014-0160 has a fixed wire-format signature, verified end-to-end against a crafted malicious packet with zero false positives on legitimate traffic. Full per-stage numbers and root-cause analysis are in [`docs/model_card.md`](docs/model_card.md#6-evaluation--comparative-benchmark).

We also directly tested generalization to unseen attack tools (`experiments/family_holdout_eval.py`, results in [§9 of the model card](docs/model_card.md#9-generalization-to-unseen-attack-families)): holding an entire attack family out of training, a held-out DoS variant (slowloris) is still correctly flagged 64% of the time, while a held-out botnet family (Bot) and a payload-driven attack (XSS) show no meaningful transfer. That's an honest, uneven result rather than a cherry-picked win.

---

## MITRE ATT&CK Kill-Chain Mapping

NetForecast classifies every network flow and forecasts future progression across a 6-stage taxonomy:

```mermaid
stateDiagram-v2
    [*] --> Benign: Normal Baseline Traffic
    Benign --> Reconnaissance: PortScan, Patator, Botnet Probing
    Reconnaissance --> Initial_Access: Web Attacks (SQLi, XSS, Brute Force)
    Initial_Access --> Lateral_Movement: Internal Infiltration, SMB/RDP Spreading
    Lateral_Movement --> Command_and_Control: Beaconing, C2 Heartbeats, DoS Spikes
    Command_and_Control --> Exfiltration: High-Volume Data Egress, Heartbleed
    Exfiltration --> [*]: Attack Objective Achieved
```

| MITRE Stage | Target ATT&CK Techniques | CIC-IDS2017 Mapped Attacks | Key Telemetry Signatures |
|---|---|---|---|
| Benign | N/A (Standard Business Traffic) | Normal HTTP/S, DNS, SSH | Balanced flow rates, standard TCP flags |
| Reconnaissance | T1595 (Active Scanning), T1046 (Network Service Discovery) | PortScan, Bot, FTP-Patator, SSH-Patator | High SYN/RST flag counts, small packet sizes, rapid IAT |
| Initial Access | T1190 (Exploit Public-Facing App), T1110 (Brute Force) | Web Attack (SQL Injection, XSS, Brute Force) | Asymmetric forward packet size, PSH flags, repeated requests |
| Lateral Movement | T1021 (Remote Services), T1210 (Exploitation of Remote Services) | Infiltration, Internal SMB/RDP scans | Internal IP-to-IP bursts, header length variance spikes |
| Command & Control | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) | DDoS LOIC, DoS Hulk, DoS GoldenEye, Slowloris | Periodic IAT intervals, persistent window size, flood volumes |
| Exfiltration | T1041 (Exfiltration Over C2), T1048 (Exfiltration Over Alt Protocol) | Heartbleed, Data exfiltration egress | Skewed down/up ratio, high backward packet lengths, TCP window changes |

---

## System Architecture

```mermaid
flowchart TB
    subgraph INGEST ["1. Telemetry Ingestion Layer"]
        L1["Live NIC Sniffer<br/>(Scapy / Npcap)"]
        L2["PCAP / PCAPNG<br/>(PcapReader)"]
        L3["CSV Flow Logs<br/>(Batch Upload)"]
    end

    subgraph PREPROC ["2. Flow Extraction & Normalization"]
        FE["22-Feature Extractor<br/>(Durations, Flags, IATs, Sizes)"]
        SC["StandardScaler<br/>(Train-Fitted Parameters)"]
        SB["Session Buffer<br/>(Sliding Window W=6)"]
        INGEST --> FE --> SC --> SB
    end

    subgraph CORE ["3. Deep World Model Core"]
        LSTM["2-Layer Stacked LSTM<br/>(Hidden=256, Dropout=0.25)"]
        H1["Next-State Head<br/>(Linear -> 22 Features)"]
        H2["Infiltration Head<br/>(MLP -> Risk Logit)"]
        H3["MITRE Stage Head<br/>(MLP -> 6 Classes)"]
        SB --> LSTM
        LSTM --> H1
        LSTM --> H2
        LSTM --> H3
    end

    subgraph FORECAST ["4. Forward Rollout & Explainability"]
        MC["Monte Carlo Simulator<br/>(k=6 Steps, N=20 Rollouts)"]
        AT["Adaptive Threshold<br/>(EMA + 2σ Baseline)"]
        SHAP["SHAP / Gradient<br/>Feature Attribution"]
        H1 --> MC
        H2 --> AT
        LSTM --> SHAP
    end

    subgraph SOC ["5. Decision Support & UI"]
        D1["Kill-Chain Radar"]
        D2["Monte Carlo Bands"]
        D3["Feature Attribution Bar"]
        D4["Forensic Reports (CSV/JSON)"]
        AT --> D1
        MC --> D2
        SHAP --> D3
        D1 & D2 & D3 --> D4
    end
```

---

## Quickstart

### Prerequisites
- Python 3.11 or 3.12
- Node.js 18+ and npm
- Npcap (Windows only, required for live packet capture)

### Option A: One-Click Launch (Windows PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\start_all.ps1
```
Activates the virtual environment, verifies model artifacts, and launches the FastAPI backend on `:8000` and the Vite frontend on `:5173`.

---

### Option B: Step-by-Step Manual Setup

#### 1. Backend Service
```bash
# Navigate to backend and create virtualenv
cd backend
python -m venv venv
.\venv\Scripts\activate       # On Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- Interactive Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health check: [http://localhost:8000/health](http://localhost:8000/health)

#### 2. Frontend Dashboard
```bash
# Open a new terminal
cd frontend
npm install
npm run dev
```
- Analyst dashboard: [http://localhost:5173](http://localhost:5173)

---

### Option C: Containerized Deployment (Docker Compose)

Spin up the entire stack (FastAPI backend, Vite/Nginx frontend, shared volume) with one command:

```bash
# Build and start all services
docker compose up --build -d

# Inspect running services
docker compose ps

# View backend logs
docker compose logs -f backend
```
- Frontend dashboard: [http://localhost:5173](http://localhost:5173)
- FastAPI backend: [http://localhost:8000](http://localhost:8000)

---

## Configuration & Environment Variables

Copy `.env.example` to `.env` to customize runtime parameters:

```bash
cp .env.example .env
```

| Variable | Default Value | Description |
|---|---|---|
| `ARTIFACTS_DIR` | `./backend/artifacts` | Path to serialized model weights, scaler, and config |
| `DB_DIR` | `./backend/data` | SQLite database directory (`forecaster.db`) |
| `ALERT_THRESHOLD` | `0.5` | Baseline probability threshold for attack alerts |
| `ADAPTIVE_THRESHOLD` | `1` | Enable dynamic baseline (mean + 2 std dev) thresholding |
| `API_KEY` | *(None / Empty)* | Optional header authentication (`X-API-Key`). Unset = demo mode |
| `FRONTEND_URL` | `http://localhost:5173` | Allowed CORS origins (comma-separated for multi-origin) |

---

## Running Automated Tests

Run the full backend test suite to verify inference, world model rollout, and explainability:

```bash
# Run all backend tests
backend/venv/Scripts/python.exe -m pytest backend/tests -v

# Run inference and forecast unit tests specifically
backend/venv/Scripts/python.exe -m pytest backend/tests/test_inference.py -v
```

---

## How to Demo (SIH 2026 Evaluation Flow)

A 5-stage workflow for live judge demonstrations:

```
[1. Simulator Mode] --> [2. Observe Forecasting] --> [3. Switch Live NIC] --> [4. Purge Simulated] --> [5. Archive Cycle]
```

1. **Launch in simulator mode.** Run `powershell -File .\start_all.ps1 -Mode simulator`. This starts both servers and immediately starts `demo/traffic_simulator.py`, injecting realistic multi-session attacks across all 6 MITRE stages.
2. **Show forecasting vs. detection.** In the SOC dashboard, show a session progressing through Reconnaissance to Initial Access. Highlight the k-step Monte Carlo forecast panel — it projects state vectors forward and predicts an impending transition to Lateral Movement or C2 before the corresponding attack packets occur.
3. **Inspect dual explainability.** Click the Explain tab on an active alert. Toggle between SHAP (Shapley game-theoretic attributions) and gradient×input attributions to show which flow features (`down_up_ratio`, `pkt_size_avg`, `rst_flag_cnt`, etc.) drove the risk score.
4. **Show live mode and purge.** Switch the system mode to live via the UI or API (`POST /system/mode`). Click "Purge Simulated Data" (`POST /system/purge-simulated`) to wipe synthetic demo flows from the operational database while keeping genuine live traffic.
5. **Cycle reset and archive.** Show the non-destructive telemetry cycle system: trigger "Archive Cycle" (`POST /system/cycle/start`), which snapshots the current state into historical archives (`/system/cycles`) and starts a fresh monitoring session without restarting the server.

## Live Traffic & PCAP Ingestion

### A. Upload PCAP / PCAPNG Files
Drop any standard Wireshark or tcpdump `.pcap` or `.pcapng` file directly into the dashboard UI, or stream via API:
```bash
curl -X POST http://localhost:8000/ingest/pcap \
  -F "file=@sample_attack.pcap" \
  -F "session_id=incident_042"
```

### B. Live NIC Sniffing
Capture and classify live traffic from your physical Ethernet or Wi-Fi interface:
```bash
# List available network interfaces
python capture/live_capture.py --list-interfaces

# Sniff on selected interface and stream flows to backend
python capture/live_capture.py --interface "Ethernet" --api http://localhost:8000
```

---

## Retraining & Experimentation

To reproduce the benchmark or train on custom PCAP/flow data:

```bash
# 1. Download official CIC-IDS2017 dataset (8 CSV files, ~844 MB)
python data/download_cicids.py

# 2. Preprocess with stratified attack preservation & session windowing
python data/preprocess_cicids.py --input-dir data/raw_cicids --output real_flows.csv --sample 40000

# 3. Augment Lateral Movement with real CIC-IDS2018 Infiltration data (~317MB download).
#    CIC-IDS2017 alone has only ~36 real Lateral Movement rows -- not enough to learn
#    from. Optional but strongly recommended; skip only if you don't need that stage.
python data/augment_lateral_movement.py --target real_flows.csv

# 4. Train MAX-configuration World Model
python pipeline_fixed.py \
  --data real_flows.csv \
  --out ./backend/artifacts \
  --epochs 20 \
  --batch-size 128 \
  --hidden-size 256 \
  --num-layers 2 \
  --dropout 0.25 \
  --lr 1e-3 \
  --weight-decay 1e-4 \
  --augment-stages "Exfiltration" \
  --augment-sessions-per-stage 300 \
  --class-weight-max 6.0 \
  --stage-loss focal \
  --focal-gamma 2.0
```

> [!TIP]
> All artifacts are serialized into `backend/artifacts/`:
> - `world_model.pt` — checkpointed LSTM PyTorch weights (hidden=256)
> - `scaler.pkl` — train-split fitted standard scaler
> - `config.json` — hyperparameters, feature indices, calibration bias, and git commit provenance
> - `benchmark_comparison.csv` — head-to-head metrics against baselines

---

## API Endpoints

> [!NOTE]
> All HTTP routes share a single global SlowAPI limit of 120 requests/minute per client IP (`backend/app/main.py`) — there is currently no differentiated per-endpoint throttling.

| Category | Method | Endpoint | Description |
|:---:|:---:|---|---|
| Health & Info | `GET` | `/health` | System status, device (CPU/CUDA), active features count |
| Forecasting | `POST` | `/predict` | Single-step state transition & stage prediction from a 6x22 window |
| | `POST` | `/forecast` | k-step Monte Carlo rollout with uncertainty intervals & EMA |
| | `GET` | `/forecast/view/html` | Printable in-browser HTML forecast trajectory dossier |
| | `GET` | `/forecast/export/html` | Download themed HTML forecast dossier |
| | `GET` | `/forecast/export/csv` | Download forecast steps as CSV |
| | `GET` | `/forecast/export/json` | Download forecast steps as JSON |
| Explainability | `POST` | `/explain` | Feature attribution (`method: "shap"` or `method: "gradient"`) |
| | `GET` | `/explain/view/html` | Printable in-browser HTML attribution dossier (SHAP/Gradient) |
| | `GET` | `/explain/export/html` | Download themed HTML explanation dossier |
| | `GET` | `/explain/export/csv` | Download feature attributions as CSV |
| | `GET` | `/explain/export/json` | Download feature attributions as JSON |
| Forensic Reports | `GET` | `/reports/view/html` | Printable in-browser HTML incident forensic dossier |
| | `GET` | `/reports/export/html` | Download themed HTML forensic report |
| | `GET` | `/reports/export/csv` | Export forensic CSV report for sessions and alerts |
| | `GET` | `/reports/export/json` | Export full structured JSON telemetry & kill-chain report |
| Ingestion | `POST` | `/ingest` | Ingest single flow telemetry record (gated by mode) |
| | `POST` | `/ingest/csv` | Bulk upload flow log CSV |
| | `POST` | `/ingest/pcap` | Upload raw `.pcap` file for Scapy flow reconstruction |
| System & Cycle | `GET/POST`| `/system/mode` | Query or toggle between `live` and `simulated` modes |
| | `POST` | `/system/purge-simulated` | Delete all simulated flows, sessions, and alerts |
| | `POST` | `/system/cycle/start` | Archive current monitoring cycle and start a fresh cycle |
| | `GET` | `/system/cycle/current` | Query the currently active monitoring cycle |
| | `GET` | `/system/cycles` | List historical cycle archives |
| Alerts & WS | `GET` | `/alerts` | Query active & historical alerts with triage status |
| | `GET` | `/alerts/stats` | Aggregate alert statistics |
| | `POST` | `/alerts/{id}/acknowledge` | Acknowledge alert with operator notes |
| | `WS` | `/ws/live` | WebSocket real-time flow telemetry stream |

---

## Repository Structure

```
Network_Attack_Detection/
├── backend/                         # FastAPI core service
│   ├── app/
│   │   ├── config.py                # Hyperparameters, paths & thresholds
│   │   ├── database.py              # SQLite + async SQLAlchemy session models
│   │   ├── inference.py             # World Model forward pass, MC rollout & SHAP
│   │   ├── ingestion.py             # Sliding window buffer & adaptive EMA threshold
│   │   ├── network_identity.py      # IP subnetting & loopback/private-range classification
│   │   ├── process_resolver.py      # Cross-platform (psutil) socket-to-PID & executable correlation
│   │   ├── signatures.py            # Re-export of capture/signatures.py (Docker/standalone packaging)
│   │   ├── main.py                  # App factory, SlowAPI rate limiter & CORS
│   │   ├── model_loader.py          # Dynamic artifact loader (hidden_size, scaler, calibration bias)
│   │   ├── schemas.py               # Pydantic request/response validation schemas
│   │   └── routes/                  # Modular endpoint routers
│   │       ├── alerts.py            # Alert triage & acknowledge
│   │       ├── explain.py           # SHAP / Gradient attribution & HTML/CSV/JSON dossiers
│   │       ├── forecast.py          # Prediction, MC rollout & HTML/CSV/JSON dossiers
│   │       ├── ingest.py            # Single & batch flow ingestion (mode-gated)
│   │       ├── pcap.py              # Scapy PcapReader flow reconstruction
│   │       ├── reports.py           # Forensic HTML dossiers & CSV/JSON exports
│   │       ├── system.py            # Mode switcher, purge & cycle reset/persistence/archive
│   │       └── ws.py                # Real-time WebSocket event broadcaster
│   ├── artifacts/                   # Serialized production models & metrics
│   │   ├── benchmark_comparison.csv # Baseline comparison table
│   │   ├── config.json              # Model hyperparameters, calibration bias & provenance
│   │   ├── scaler.pkl               # StandardScaler fitted on training set
│   │   └── world_model.pt           # Checkpointed PyTorch LSTM weights (256 units)
│   └── tests/
│       ├── test_inference.py        # Model/inference/explainability/calibration unit tests
│       ├── test_api_integration.py  # End-to-end API, ingestion & Heartbleed-alert flow tests
│       ├── test_flow_parity.py      # PCAP vs live-capture feature-extraction parity tests
│       └── test_signatures.py       # Deterministic Heartbleed (CVE-2014-0160) signature tests
│       # 35 tests total, currently passing
├── frontend/                        # React 18 + Vite SOC Dashboard
│   ├── src/
│   │   ├── components/              # Reusable UI components
│   │   │   ├── AlertFeed.jsx        # Live alert feed with triage buttons
│   │   │   ├── ExplainView.jsx      # SHAP / Gradient attribution toggle & charts
│   │   │   ├── ForecastChart.jsx    # Recharts Monte Carlo uncertainty bands
│   │   │   ├── IngestPanel.jsx      # PCAP & CSV upload interface
│   │   │   ├── KillChainTracker.jsx # Visual 6-stage ATT&CK progress radar
│   │   │   └── ReportsView.jsx      # CSV/JSON forensic report downloaders
│   │   ├── api.js                   # Axios client with auth & error handling
│   │   └── App.jsx                  # Main dashboard layout & state management
├── data/                            # Dataset management & preprocessing
│   ├── download_cicids.py           # Hugging Face mirror chunked downloader
│   ├── preprocess_cicids.py         # 22-feature mapper with stratified sampling
│   ├── augment_lateral_movement.py  # Real CIC-IDS2018 Infiltration data -> Lateral Movement
│   ├── augment_initial_access.py    # Real CIC-IDS2018 Web Attack data -> Initial Access
│   ├── raw_cicids/                  # 8 official CIC-IDS2017 CSV files (844 MB)
│   └── raw_cicids2018/              # CIC-IDS2018 infiltration-day and web-attack-day CSVs
├── experiments/                     # Side experiments, not part of the shipped model
│   ├── family_holdout_eval.py       # Unseen-attack-family generalization test
│   └── calibrate_stage_logits.py    # Post-hoc per-class logit-bias calibration search
├── capture/                         # Hardware & network capture tools
│   ├── live_capture.py              # Scapy-based live sniffer on Ethernet/Wi-Fi
│   ├── flow_state.py                # Shared 22-feature flow reconstruction (live capture + PCAP)
│   └── signatures.py                # Deterministic packet signatures (Heartbleed CVE-2014-0160)
├── demo/                            # Simulation & demo harnesses
│   └── traffic_simulator.py         # Multi-session kill-chain attack injector
├── pipeline_fixed.py                # MAX-configuration training pipeline
├── start_all.ps1                    # Unified single-command launcher
├── ARCHITECTURE.md                  # Architectural specification
├── PRESENTATION.md                  # SIH 2026 pitch deck
├── LAB_SETUP.md                     # Isolated VM lab guide for attack traffic
└── README.md                        # Project documentation
```

---

## Known Limitations & Enterprise Architecture Roadmap

For national-scale deployment or production CII environments, some architectural choices made for this prototype have a clear production upgrade path:

1. **Embedded datastore (SQLite + WAL mode).** Currently async SQLite (`sqlite+aiosqlite`) gives a self-contained, zero-external-dependency deployment for the hackathon prototype, without needing a local PostgreSQL service. In a 10Gbps+ enterprise perimeter, the database layer would move to a distributed time-series store such as TimescaleDB or ClickHouse, with Kafka ingestion buffering to handle millions of flows per second.
2. **Local transport security (HTTP/WS).** Currently plaintext HTTP and WebSocket (`ws://`) for local development and offline evaluator testing. In production, an Nginx or Traefik reverse proxy would handle TLS 1.3 / mTLS termination with strict HSTS headers and secure WebSockets (`wss://`).
3. **Capture privileges.** Currently Windows native raw socket packet capture requires administrator elevation (`RunAs`). In a production appliance, packet capture would run as a dedicated Linux system daemon using eBPF/AF_XDP or DPDK ring buffers with minimal Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`).

---

<div align="center">
  <sub>Built for the Smart India Hackathon (SIH) 2026 • National Technical Research Organisation (NTRO) • Problem Statement ID 26153</sub>
</div>
