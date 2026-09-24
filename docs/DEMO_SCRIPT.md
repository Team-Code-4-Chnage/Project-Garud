# Project Garud — SIH 2026 Evaluation Demo Script
**Problem Statement 26153: AI-based Network Attack Forecasting**  
*Team Code 4 Change // NetForecast World Model Engine*

---

## Evaluator Pitch (10-Second Hook)
> *"Traditional IDS/IPS tools are post-facto: they detect an intrusion only after files are encrypted or data is exfiltrated. Project Garud introduces an **LSTM World Model** that forecasts attack progression across the MITRE ATT&CK kill-chain **before** final compromise occurs, giving SOC analysts actionable lead-time to intervene."*

---

## 5-Minute Live Demonstration Flow

### Stage 1: The Concept & Problem Framing (1 Min)
1. **Open Dashboard (`http://localhost:5173`)**
   - Point out the terminal UI design system, showing live clock and telemetry indicators.
   - Explain the difference between **Detection** (classifying an isolated packet in the past) and **Forecasting** (modeling sequential temporal dynamics across a 6-flow window $W=6$ to predict future states $k$-steps ahead).
2. **Highlight System Health (`SYS_VIEW // [SETTINGS]`)**
   - Click **SETTINGS** in the sidebar.
   - Show the Evaluator the **MODEL_INFO** card:
     - 2-Layer LSTM with 256 hidden units and 22 standardized CIC-IDS features.
     - Monte Carlo dropout uncertainty sampling ($N=20$) and Adaptive EMA thresholding.
   - Note the SHA-256 Model Provenance hash displayed in `/health` confirming artifact integrity.

---

### Stage 2: Telemetry Ingestion & Real vs. Simulation Modes (1 Min)
1. **Show Source Control in Settings:**
   - Demonstrate the dual operating engine:
     - **LIVE ONLY:** Captures genuine packets off network adapters via `capture/live_capture.py` (Scapy / raw socket). In live mode, synthetic feeds to `/ingest` are rejected with HTTP 403 Forbidden.
     - **SIMULATION MODE:** Sandbox mode for demonstration and evaluation without a multi-VM lab.
   - Switch to **SIMULATED** mode and click `START SIMULATOR`.
2. **Observe Real-Time Streaming:**
   - Navigate to **LIVE_LOGS**.
   - Show incoming flows streaming over WebSocket in real time.
   - Explain the telemetry fields: Timestamp, Application / Process, Direction (`IN`/`OUT`/`INT`), IPs, Throughput, and instantaneous Infiltration Probability.

---

### Stage 3: Kill-Chain Forecasting & Rollout Trajectory (1.5 Min)
1. **Select an Active Attack Session:**
   - Return to **DASHBOARD**.
   - Note the session table sorted by risk or last seen.
   - Click on an active session undergoing an attack (e.g., advancing from *Reconnaissance* $\to$ *Initial Access*).
2. **Deep-Dive into Forecast View (`SYS_VIEW // [FORECAST]`):**
   - **Kill-Chain Visualizer:** Show the MITRE progression milestones:
     $$\text{Benign} \longrightarrow \text{Reconnaissance} \longrightarrow \text{Initial Access} \longrightarrow \text{Lateral Movement} \longrightarrow \text{C2} \longrightarrow \text{Exfiltration}$$
   - **Autoregressive Rollout Curve ($k$-Steps Ahead):**
     - Show the projected trajectory curve.
     - Explain how the LSTM's next-state head feeds $\hat{x}_{t+1}$ recursively into itself to simulate future flow dynamics.
   - **Confidence Intervals & Adaptive Threshold:**
     - Point out the shaded Monte Carlo uncertainty band ($\pm 1\sigma$).
     - Point out the horizontal Adaptive Threshold line ($\mu_{\text{EMA}} + k\cdot\sigma$). Show how it automatically adjusts to noisy baseline traffic to prevent alert fatigue.

---

### Stage 4: Feature Attribution & Explainability (1 Min)
1. **Explain the Model's Reasoning (`SYS_VIEW // [EXPLAINABILITY]`):**
   - Click **EXPLAINABILITY** in the sidebar.
   - Show the two complementary interpretability engines:
     - **FAST (GRADIENT):** Instantaneous saliency map ($g = \frac{\partial \mathcal{L}}{\partial x} \odot x$) rendered in sub-seconds.
     - **DEEP (SHAP):** Game-theoretic Shapley values via `KernelExplainer` computing marginal feature push toward Malicious (red) vs. Benign (green).
2. **Highlight Key Attack Features:**
   - Point out features driving the alert: e.g., elevated `flow_bytes_s`, spike in `syn_flag_cnt`, or abnormal `tcp_win_size`.
3. **Forensic Dossier Export:**
   - Click `VIEW REPORT` or `EXPORT FORENSIC HTML` to display the complete, printable forensic dossier.

---

### Stage 5: Incident Playbooks & Remediation (30 Sec)
1. **Triage Alerts (`SYS_VIEW // [ALERTS]`):**
   - Navigate to **ALERTS**.
   - Show prioritized alerts categorized by severity (`CRITICAL`, `HIGH`, `MEDIUM`).
   - Highlight the **RECOMMENDED PLAYBOOK ACTION**:
     - *Example:* For Reconnaissance: *"Investigate port scanning activity from 192.168.1.105. Check firewall logs for SYN sweeps targeting 10.0.0.5."*
   - Click **ACK** to acknowledge an alert.
2. **Network Wellbeing & Cycle Archival:**
   - Click **NEW_CYCLE** in the top bar to archive historical telemetry to disk and restart the monitoring baseline cleanly.
   - Open **WELLBEING** modal to show the overall composite health score of the network infrastructure.

---

## Backup Quick Commands

If running via terminal during live evaluation:

```powershell
# 1. Run all backend unit & API integration tests (55 tests)
backend\venv\Scripts\python.exe -m pytest backend/tests -v

# 2. Build and verify production frontend bundle
cd frontend; npm run build; cd ..

# 3. Start full system with Docker Compose
docker compose up -d --build
```
