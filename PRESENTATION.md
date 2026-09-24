# Project Garud: Autonomous Cyber Attack Forecasting
## SIH 2026 Presentation Deck — Problem Statement ID 26153 (NTRO)
**Team:** Code 4 Change • **Repository:** [Team-Code-4-Chnage/Project-Garud](https://github.com/Team-Code-4-Chnage/Project-Garud)
**Category:** Artificial Intelligence / Cybersecurity
**Focus:** Anticipatory Cyber Defense for Critical Information Infrastructure (CII)

---

### Slide 1: From Reactive Detection to a World Model

Traditional NIDS and SIEMs are reactive classifiers — they flag attacks after malicious payloads, signatures, or command-and-control beacons have already crossed the perimeter. In Critical Information Infrastructure (power grids, banking cores, defense networks), waiting for lateral movement or data exfiltration to finish is not an acceptable failure mode.

NetForecast takes a different approach. Instead of predicting a static label $P(\text{attack} \mid x)$ for the current packet, it learns the transition dynamics of the network itself:
$$s_{t+1} \sim \mathcal{W}(s_t, s_{t-1}, \dots)$$
That lets it forecast attacker progression $k$ steps into the future along the MITRE ATT&CK kill chain, giving security teams lead time before compromise completes rather than a notification after it did.

---

### Slide 2: End-to-End System Architecture

**Telemetry ingestion**, three sources:
- Live capture: real-time packet sniffing via Scapy and Npcap directly from host network interfaces.
- Offline forensics: PCAP / PCAPNG file upload with automatic flow reconstruction.
- Enterprise flow logs: bulk CSV ingestion of 22 CIC-IDS temporal and volumetric features.

**Session aggregation:**
- Bi-directional flow pairing using canonical 5-tuple hashing.
- RFC1918 private-range traffic direction analysis (inbound, outbound, internal).
- Sliding temporal window ($W=6$ timesteps) with opportunistic memory TTL eviction.

**Defense interface:**
- Low-latency WebSocket telemetry stream.
- React dashboard with MITRE ATT&CK kill-chain progression, Monte Carlo risk timelines, and one-click forensic report exports.

---

### Slide 3: World Model Architecture & Stochastic Forecasting

The core is a 2-layer stacked LSTM (`hidden_size=256`, inter-layer dropout `0.25`) trained on a joint, multi-head objective:

1. Next-state head — predicts the expected future telemetry vector $\hat{s}_{t+1} \in \mathbb{R}^{22}$ ($\mathcal{L}_{\text{MSE}}$).
2. Infiltration probability head — predicts the likelihood of an impending breach ($\mathcal{L}_{\text{BCE}}$).
3. MITRE ATT&CK stage head — classifies attack phase across 6 progression states ($\mathcal{L}_{\text{CE}}$).

For uncertainty quantification, it simulates future attack trajectories $k=6$ steps ahead via recursive autoregressive rollout, applying Gaussian perturbation noise ($\sigma=0.05$) across $N=20$ stochastic trajectories. This yields an expected risk curve $\mu_t$, uncertainty bounds $\pm \sigma_t$, and a modal stage consensus, instead of a single brittle point estimate.

---

### Slide 4: Empirical Benchmarks & Explainability

| Model | Technique | F1-Score | Precision | Recall | False Positive Rate (FPR) |
|---|---|---|---|---|---|
| Logistic Regression | Shallow Linear Baseline | 0.523 | 0.689 | 0.421 | 0.062 |
| Isolation Forest | Unsupervised Anomaly Detection | 0.402 | 0.374 | 0.434 | 0.235 |
| NetForecast (World Model) | 2-Layer LSTM + Multi-Head Rollout, Focal Loss + logit calibration | **0.861** | **0.862** | **0.860** | **0.045** |

Binary malicious-vs-benign detection on a held-out real test set from CIC-IDS2017 + CIC-IDS2018, using a proper 3-way train/val/test split so checkpoint selection never touches the reported test data (`backend/artifacts/benchmark_comparison.csv`). Per stage, Benign, Reconnaissance, C2, and Lateral Movement are all reliable — Lateral Movement reaches F1 0.92 after fixing it with real CIC-IDS2018 data (see `docs/model_card.md` §6). Initial Access precision improved from 6% to 54% across five fixes (real CIC-IDS2018 web-attack data, class-weight retuning, focal loss, post-hoc logit-bias calibration, and a root-cause fix to how the original CIC-IDS2017 rows were grouped into sessions — see `docs/model_card.md` §5) — still the weakest class, but no longer the open gap it was. Exfiltration isn't caught by the ML model at all (only 2 real examples exist in the test set) but is covered by a separate deterministic Heartbleed signature detector instead.

Every alert is explainable, not just scored: SHAP (KernelExplainer) computes Shapley values identifying which of the 22 telemetry features pushed the model toward predicting compromise, and gradient×input attribution gives an instantaneous alternative for high-throughput triage where a full SHAP pass is too slow. An adaptive EMA threshold ($\bar{p} + 2\sigma$) adjusts alert sensitivity to baseline network noise instead of using one fixed cutoff, which is what keeps the false positive rate down without hiding real alerts.

---

### Slide 5: Live Demonstration

The demo covers:
1. Live network capture — real-time packet parsing and feature streaming from physical Wi-Fi/Ethernet adapters.
2. A multi-stage attack scenario progressing automatically through the kill chain: $\text{Benign} \to \text{Reconnaissance} \to \text{Initial Access} \to \text{Lateral Movement} \to \text{C2} \to \text{Exfiltration}$.
3. Forensic export — one-click download of timestamped CSV/JSON incident reports for compliance and auditing.
4. Production-facing hardening: SlowAPI rate limiting, optional API key authentication, and containerized deployment via Docker.

NetForecast's goal is to move cyber defense for Critical Information Infrastructure from reactive incident response toward a predictive posture — flagging where a session is headed, not only where it currently sits.
