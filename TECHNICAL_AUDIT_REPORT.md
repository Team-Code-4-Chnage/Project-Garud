# INDEPENDENT TECHNICAL AUDIT REPORT

**Problem Statement ID:** 26153  
**Problem Statement Title:** AI Based Network Attack Forecasting from Network Traffic Data  
**Target Evaluation:** Smart India Hackathon (SIH) 2026 — Cybersecurity / Critical Information Infrastructure (CII) Track  
**Audit Standard:** Zero-Trust Verification (Source Code & Execution Flow Override Documentation)

---

## 1. Executive Summary & Dual-Horizon Pipeline Reconstruction

### 1.1 Executive Summary

This technical audit evaluates the codebase of **Project Garud** against the official requirements of **SIH Problem Statement 26153**. The evaluation is strictly evidence-based: documentation, variable names, and presentation claims were treated as unverified assertions until validated against executable source code.

The core finding of this audit is that the repository does not contain a single unified world model. Instead, it contains **two distinct, parallel model architectures** operating at different temporal granularities and abstraction levels:

1. **Track A: Flow/Session World Model (`world_model.pt`)**  
   _Implemented in:_ `pipeline_fixed.py`, `backend/app/inference.py`  
   _Scope:_ Operates on a sliding window of 6 consecutive network flows ($W=6 \times 22$ features) within a single 5-tuple TCP/UDP session. Predicts the normalized flow feature vector of flow $t+1$, alongside binary infiltration risk and attack stage proxies.
2. **Track B: Macro Network-State World Model (`network_world_model.pt`)**  
   _Implemented in:_ `worldmodel_v3/`, `backend/app/network_state.py`  
   _Scope:_ Aggregates all network traffic across all hosts into 1-minute time bins ($W=12 \times 45$ features: port entropy, host concentration, protocol shares) and projects macro network metrics 4 minutes into the future ($t+1 \dots t+4$).

While the architecture incorporates an autoregressive next-state transition head trained with Mean Squared Error (MSE), **it does not constitute a true probabilistic world model ($P(S(t+1) \mid S(t))$)**. Rather, it is a **deterministic recurrent state-space regression model with auxiliary multi-task classification heads**. Crucially, **MITRE ATT&CK progression is not learned by the neural network**; it is implemented via an analyst-written static lookup dictionary (`backend/app/mitre.py`).

---

### 1.2 Pipeline Reconstruction: Documented Claim vs. Code Reality

```
DOCUMENTED CLAIM (README & Architecture Diagrams):
Raw PCAP / Telemetry
    │
    ▼
Unified Ingestion & Flow Extraction
    │
    ▼
Learned Dynamic Network Graph
    │
    ▼
Probabilistic World Model P(S(t+1) | S(t))
    │
    ▼
Multi-Step Kill-Chain Forecasting (Recon -> Exfil)
    │
    ▼
Automated MITRE ATT&CK Stage Learning
    │
    ▼
Production Explainability (SHAP & Attention)
```

```
ACTUAL SOURCE CODE IMPLEMENTATION (Verified Execution Path):
Raw PCAP / Live Capture (Scapy / Npcap)
    │
    ▼
capture/flow_table.py (In-memory 5-tuple table, 100K flow limit)
    │
    ├───► [TRACK A: Single Connection Stream]
    │     │
    │     ▼
    │     pipeline_fixed.py: 6-flow window x 22 features
    │     │
    │     ▼
    │     2-Layer Stacked LSTM (Hidden=128, Dropout=0.25)
    │     │
    │     ├── Head 1 (Linear): Next Flow Feature Vector S(t+1) [MSE Loss]
    │     ├── Head 2 (MLP):    Infiltration Risk Probability [Focal Loss]
    │     └── Head 3 (MLP):    Attack Stage Proxy [Cross-Entropy]
    │
    └───► [TRACK B: Network-Wide Macro Grid]
          │
          ▼
          worldmodel_v3: 1-minute time aggregation x 45 macro features
          │
          ▼
          NetStateWorldModel (2-Layer LSTM, Hidden=128)
          │
          └── Rollout Head: Autoregressive Macro State Projection (t+1 .. t+4)

DOWNSTREAM CONSUMPTION:
Stage Head / Behavior Class ──► backend/app/mitre.py (Static Python Dictionary Lookup)
Inference Windows           ──► backend/app/inference.py (KernelExplainer with np.zeros(1, 132))
```

---

## 2. World Model Mathematical Verification

The official SIH Problem Statement specifies:
$$\text{World Model: } P(S_{t+1} \mid S_t) \quad \text{supporting forward simulation}$$

### 2.1 Formal Formulation in Code

In `pipeline_fixed.py` (lines 182–215), the recurrent model is mathematically constructed as:

$$X_t = [s_{t-W+1}, s_{t-W+2}, \dots, s_t] \in \mathbb{R}^{W \times D} \quad (W=6, D=22)$$
$$h_t, c_t = \text{LSTM}(X_t) \quad \text{where } h_t \in \mathbb{R}^{128}$$

Three parallel output heads branch directly from the recurrent latent state $h_t$:

1. **Next-State Head:**
   $$\hat{s}_{t+1} = W_s h_t + b_s \in \mathbb{R}^{22}$$
2. **Infiltration Risk Head:**
   $$\hat{y}_{\text{infil}} = \sigma\left(W_{i2} \text{GELU}(W_{i1} h_t + b_{i1}) + b_{i2}\right) \in [0, 1]$$
3. **Attack Stage Head:**
   $$\hat{y}_{\text{stage}} = \text{Softmax}\left(W_{c2} \text{GELU}(W_{c1} h_t + b_{c1}) + b_{c2}\right) \in \Delta^6$$

The overall training loss function is:
$$\mathcal{L} = \lambda_1 \text{MSE}(\hat{s}_{t+1}, s_{t+1}) + \lambda_2 \text{FocalLoss}(\hat{y}_{\text{infil}}, y_{\text{infil}}) + \lambda_3 \text{CrossEntropy}(\hat{y}_{\text{stage}}, y_{\text{stage}})$$

### 2.2 Mathematical Reality Check

| World Model Criterion          | SIH Requirement Expectation                                                                      | Actual Repository Implementation                                                                                | Verdict                                                                           |
| :----------------------------- | :----------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------- |
| **Probability Formulation**    | Density estimation $P(S_{t+1} \mid S_t)$ (e.g., GMM, VAE, diffusion, normalizing flows).         | Deterministic point estimation $\hat{s}_{t+1} = f(h_t)$ optimized via MSE loss.                                 | **CONTRADICTED BY CODE** (Deterministic regression, not a probability density).   |
| **State Representation**       | Global network state (topology, active nodes, host-to-host edges).                               | Flow-level: 22 normalized packet counters of a single connection.<br>Macro-level: 45 scalar summary statistics. | **PARTIALLY IMPLEMENTED** (Lacks graph topological representation).               |
| **Kill-Chain Conditioning**    | Attack progression conditioned on state transitions: $P(\text{Stage}_{t+1} \mid \hat{S}_{t+1})$. | Infiltration & Stage heads branch off $h_t$, **NOT** off $\hat{s}_{t+1}$. Auxiliary multi-task loss.            | **PARTIALLY IMPLEMENTED** (State prediction is an auxiliary reconstruction task). |
| **Multi-Step Rollout**         | Recursive simulation of future network dynamics $S_{t+k}$.                                       | Autoregressive loop: $\hat{s}_{t+1}$ re-injected as input to produce $h_{t+1}$.                                 | **VERIFIED** (Implemented in `inference.py`).                                     |
| **Uncertainty Quantification** | Formal predictive uncertainty over trajectory horizon.                                           | Monte Carlo dropout ($p=0.10$, 20 runs) in flow inference; static heuristics in macro state.                    | **PARTIALLY IMPLEMENTED**.                                                        |

> **Audit Finding:** The architecture is an **Autoregressive Recurrent Multi-Task Predictor with Auxiliary State Reconstruction**. It does not learn environment transition densities $P(S_{t+1} \mid S_t, a_t)$ in the foundational Reinforcement Learning / World Models (Ha & Schmidhuber) sense. An expert AI examiner will identify this as a stacked LSTM with next-step regression loss.

---

## 3. Data Pipeline & Timeline Integrity Audit

### 3.1 Ground Truth of Underlying Datasets (CIC-IDS2017 & 2018)

The documentation claims the system models temporal attack progression and multi-stage kill chains. An inspection of the training dataset reveals significant structural limitations:

1. **Absence of Real Kill Chains in CIC-IDS2017:**
   - CIC-IDS2017 traffic was generated using **isolated, scheduled attack scripts executed on specific calendar days**:
     - _Tuesday:_ FTP-Patator & SSH-Patator (Brute Force only).
     - _Wednesday:_ DoS (GoldenEye, Slowloris, Slowhttptest) & Heartbleed.
     - _Thursday:_ Web Attacks (XSS, SQLi) & Infiltration (Dropbox download).
     - _Friday:_ Botnet ARES, PortScan, and LOIC DDoS.
   - **There is no single host in the dataset that undergoes Recon $\to$ Initial Access $\to$ Lateral Movement $\to$ C2 $\to$ Exfiltration sequentially**.
   - Consequently, the stage head is not predicting progression through a live compromise; it is classifying isolated attack tool signatures.

2. **Synthetic Data Augmentation on Rare Classes:**
   - In raw CIC-IDS2017, the "Infiltration" class contains only 36 flows, and "Heartbleed" contains 11 flows.
   - In `pipeline_fixed.py` (lines 380–415, `augment_rare_stages`), the authors synthesize over 1,200 samples for rare classes by injecting Gaussian jitter ($\mathcal{N}(0, 0.05)$) into existing feature vectors.
   - _Implication:_ High recall on rare classes is heavily influenced by synthetic Gaussian clones of 11 original seed packets rather than learned temporal dynamics.

3. **Data Splitting & Leakage:**
   - In `pipeline_fixed.py` (lines 420–460), feature normalization parameters (`mean` and `std`) are fitted across the aggregated dataset prior to chronological chunking, introducing mild global distribution leakage into the test set.

---

## 4. Temporal Modeling & Sequence Dynamics

### 4.1 Windowing & Time Assumptions

- **Window Dimensions:** Fixed at $W=6$ consecutive flows per 5-tuple session (Track A) or $W=12$ one-minute time bins (Track B).
- **Temporal Distortion:** In Track A, flows within a TCP connection are indexed sequentially ($t, t+1, \dots, t+5$). The real-world inter-arrival time $\Delta t$ between flow $t$ and flow $t+1$ can vary from 1 millisecond to hours. The model treats discrete sequence steps as uniform time units, ignoring inter-flow real-time gaps in the recurrence.

### 4.2 Error Compounding in Multi-Step Rollout ($K$-Step)

When rolling forward $\hat{S}_{t+k}$ without ground-truth feedback, errors compound over successive steps. The project's empirical test logs in `experiments/eval_results.json` document the exact degradation:

| Rollout Horizon | Model MSE  | Persistence Baseline MSE | Model MAE  | Persistence Baseline MAE |              Evaluation Result              |
| :-------------: | :--------: | :----------------------: | :--------: | :----------------------: | :-----------------------------------------: |
|    **$t+1$**    | **0.5096** |          0.8949          |   0.2636   |        **0.2480**        | **Persistence Baseline beats Model on MAE** |
|    **$t+2$**    | **0.5316** |          0.9650          |   0.2755   |        **0.2733**        | **Persistence Baseline beats Model on MAE** |
|    **$t+3$**    | **0.5482** |          1.0076          | **0.2805** |          0.2888          |       Model beats Persistence by 2.8%       |
|    **$t+4$**    | **0.5598** |          1.0296          | **0.2815** |          0.2976          |       Model beats Persistence by 5.4%       |

> **Critical Finding:** While the LSTM achieves lower squared error (MSE), **the naive persistence baseline ($S_{t+k} = S_t$) achieves superior Mean Absolute Error (MAE) for steps $t+1$ and $t+2$**. A strict evaluator will challenge why a complex deep neural network cannot outperform a zero-compute identity copy on short horizons.

---

## 5. Attack Progression & MITRE ATT&CK Mapping

### 5.1 Verification of MITRE Progression

The documentation indicates that the world model forecasts adversary progression across MITRE ATT&CK kill-chain phases.

**Source Code Reality:**  
The source code in `backend/app/mitre.py` contains the following explicit docstring written by the authors:

```python
"""
MITRE ATT&CK interpretation layer.

This is an analyst-written lookup, not something the model learns or predicts. The pipeline is:

    model output (behaviour class or legacy stage name)
        -> behaviour interpretation (what the traffic actually is)
        -> MITRE technique(s)
        -> MITRE tactic(s)
...
`confidence` is the author's judgement of how well the technique fits the observed behaviour
(high / medium / low). It is not a model probability.
"""
```

### 5.2 Mechanics of Progression Mapping

1. The neural network outputs a softmax vector over 7 categorical classes: `['Benign', 'PortScan', 'BruteForce', 'DoS', 'DDoS', 'WebAttack', 'Bot']`.
2. The argmax class index is passed into `BEHAVIOUR_MAP` in `backend/app/mitre.py`.
3. The frontend displays a 5-phase kill chain (`Phase 1: Reconnaissance`, `Phase 2: Initial Access`, etc.).
4. **Behavioral Inconsistency:** Because transitions are not constrained by a state-transition matrix or directed acyclic graph (DAG), if an adversary conducts a port scan after an initial brute-force attempt, the UI immediately reverts from Phase 2 to Phase 1.

---

## 6. Forward Simulation & Early Warning Lead Time

The SIH challenge requires forecasting attacks _before compromise is completed_.

The repository's internal benchmark in `experiments/eval_results.json` records empirical early warning efficacy:

- **Total Eligible Attack Sessions:** 134
- **Early Warning Successfully Triggered:** 32 sessions (**23.8%**)
- **Attacks Missed (Zero Early Warning):** 102 sessions (**76.2%**)
- **Mean Lead Time when warned:** 75.3 seconds
- **False Alert Rate on Benign Sessions:** 1.42%

```
Eligible Attack Sessions:  [========================================] 134 (100%)
Successfully Warned:      [=========                           ] 32  (23.8%)
Missed Completely:        [===============================     ] 102 (76.2%)
```

> **Evaluation Warning:** Claiming reliable early warning forecasting is contradicted by the **76.2% early warning miss rate** recorded in the project's own evaluation artifacts.

---

## 7. Explainability & Interpretability Audit

In `backend/app/inference.py` (lines 320–380), two explainability mechanisms are implemented:

### 7.1 SHAP Implementation Flaws

1. **Zero-Baseline Reference:**
   ```python
   # backend/app/inference.py: line 324
   explainer = shap.KernelExplainer(predict_fn, np.zeros((1, 132)))
   ```
   KernelSHAP evaluates feature impact relative to a reference background. Supplying an all-zero vector of size 132 (`np.zeros((1, 132))`) represents an unstandardized, biologically null baseline. For z-score normalized features, 0 represents the mean; for min-max features, 0 represents the minimum. Passing a single zero vector violates the cooperative game theory axioms of SHAP.
2. **Under-Sampling:** The implementation sets `nsamples=30`. A 132-dimensional feature space requires significantly more perturbations ($>500$) for Shapley values to reach numerical stability.
3. **Fallback to Gradient $\times$ Input:**
   When SHAP computation exceeds 2.5 seconds, the engine switches to:
   $$\text{Attribution}_i = \left| x_i \cdot \frac{\partial \hat{y}}{\partial x_i} \right|$$
   This fallback is mathematically sound and computationally fast, though subject to gradient saturation in saturated activations.

---

## 8. Generalization & Out-of-Distribution Performance

The most critical technical finding is documented in the project's own Leave-One-Day-Out (LODO) experiment (`experiments/v3_lodo.json`):

| Evaluation Scheme                         | Detection Precision | Detection Recall | Detection F1 | False Positive Rate |  ROC-AUC  |
| :---------------------------------------- | :-----------------: | :--------------: | :----------: | :-----------------: | :-------: |
| **Chronological In-Distribution Split**   |        0.858        |      0.864       |  **0.861**   |        4.59%        | **0.955** |
| **Leave-One-Day-Out (Unseen Attack Day)** |        0.351        |      0.382       |  **0.366**   |     **26.01%**      | **0.608** |

### Operational Reality:

- When evaluated on held-out attack variations or different operational days, **ROC-AUC collapses from 0.955 to 0.608** (marginally above a random guess of 0.50).
- **The false positive rate surges to 26%**, generating an unmanageable false alert volume for enterprise SOC operators.
- **Root Cause:** The recurrent network overfits to subnet-specific IP masks, flow duration distributions, and recording artifacts present on specific days of the CIC-IDS2017 dataset.

---

## 9. Baselines & Benchmark Rigor

The project benchmarks against two baselines in `pipeline_fixed.py` (lines 138–175):

1. **Logistic Regression:** Implemented as a single linear layer in PyTorch, trained with Adam on flattened $6 \times 22 = 132$ feature vectors.
2. **Isolation Forest:** Implemented as a custom scratch decision-tree ensemble (`IsolationTree`).

### In-Distribution Test Split Benchmark:

- **Logistic Regression:** Precision = 0.541, Recall = 0.506, F1 = **0.523**
- **World Model LSTM:** Precision = 0.858, Recall = 0.864, F1 = **0.861**
- **Methodological Critique:** The Logistic Regression baseline is under-optimized: it is trained for only 15 epochs on flattened raw sequence data without standard regularization or PCA preprocessing. Comparing a 2-layer LSTM against an uncalibrated linear scratch model overstates the comparative advantage.

---

## 10. Enterprise & Critical Information Infrastructure (CII) Applicability

| Enterprise Dimension   | Implementation Status                    | Technical Bottleneck                                                                                                                              |
| :--------------------- | :--------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Network Throughput** | Python Scapy / Npcap wrapper             | Packets drop at rates exceeding 10,000 pkts/sec (~50–100 Mbps). Incapable of sustaining 1 Gbps or 10 Gbps enterprise backbones.                   |
| **Flow Table Memory**  | In-memory dict with 100,000 ceiling      | Vulnerable to state-exhaustion DoS attacks (e.g., SYN flooding filling hash table).                                                               |
| **Streaming Latency**  | WebSocket emitting 1-minute aggregations | Infiltration detection occurs at 1-minute intervals; automated adversary lateral movement (occurring in milliseconds) completes before detection. |
| **Protocol Coverage**  | TCP / UDP only                           | Encrypted protocols (QUIC/HTTP3, DoH) and non-IP layer protocols are dropped or unhandled.                                                        |

---

## 11. Documentation Claims vs. Code Evidence Verification Table

| No. | Claim in Documentation                                       | Code File & Line Reference       | Actual Implementation Reality                                                    |       Audit Verdict       |
| :-: | :----------------------------------------------------------- | :------------------------------- | :------------------------------------------------------------------------------- | :-----------------------: |
|  1  | "Learns network-state transition dynamics P(S(t+1) \| S(t))" | `pipeline_fixed.py:182`          | Deterministic linear projection with MSE loss; no probability density model.     | **CONTRADICTED BY CODE**  |
|  2  | "Predicts progression across MITRE ATT&CK stages"            | `backend/app/mitre.py:4-18`      | Analyst-written static lookup dictionary; not predicted or learned.              | **CONTRADICTED BY CODE**  |
|  3  | "K-step ahead autoregressive forward simulation"             | `backend/app/inference.py:220`   | Autoregressive loop rolling forward 4 to 6 steps.                                |       **VERIFIED**        |
|  4  | "Graph Neural Network / Dynamic Network Topology"            | `worldmodel_v3/state.py`         | State vector uses scalar entropy and degree metrics; no GNN or adjacency matrix. |    **NOT IMPLEMENTED**    |
|  5  | "SHAP Explainability for real-time inference"                | `backend/app/inference.py:324`   | KernelSHAP initialized with single zero-vector (`np.zeros((1, 132))`).           | **PARTIALLY IMPLEMENTED** |
|  6  | "Logistic Regression & Isolation Forest Baselines"           | `pipeline_fixed.py:138-165`      | Implemented in training pipeline.                                                |       **VERIFIED**        |
|  7  | "Real-time Live Packet Ingestion (PCAP/Live)"                | `capture/live_capture.py:50`     | Scapy sniffer implemented with real-time flow aggregation.                       |       **VERIFIED**        |
|  8  | "Generalizes to Unseen Attack Patterns"                      | `experiments/v3_lodo.json:51-60` | LODO ROC-AUC collapses to 0.608 with 26% False Positive Rate.                    | **CONTRADICTED BY CODE**  |
|  9  | "Dual-Track Architecture (Session & Network Macro)"          | `backend/app/network_state.py`   | Two distinct models: `world_model.pt` and `network_world_model.pt`.              |       **VERIFIED**        |

---

## 12. Official SIH Problem Statement Compliance Matrix

| Requirement from SIH PS 26153                                  |     Compliance Status     | Implementation Evidence & Gap Analysis                                                                                                                          |
| :------------------------------------------------------------- | :-----------------------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Ingest network traffic (Flow & Packet level)**               | **PARTIALLY IMPLEMENTED** | 22 bidirectional flow statistics extracted via Scapy. Packet headers extracted, but payload distributions, TCP options, and IP fragmentation flags are omitted. |
| **Represent network state using feature vectors or graphs**    | **PARTIALLY IMPLEMENTED** | Implemented as flat feature vectors ($D=22$ and $D=45$). Graph structure is approximated via degree/entropy scalars; no graph representation learning.          |
| **Learn state-transition dynamics (LSTM / Transformer / GNN)** |       **VERIFIED**        | Implemented via 2-layer stacked LSTM with next-state reconstruction head.                                                                                       |
| **Forecast future network states and attacker progression**    | **PARTIALLY IMPLEMENTED** | State forecast verified. Attacker progression is an auxiliary proxy classification, not an evolving multi-host kill chain.                                      |
| **Map predicted behaviour to MITRE ATT&CK**                    | **PARTIALLY IMPLEMENTED** | Static analyst mapping implemented in `backend/app/mitre.py`. Not learned dynamically by the model.                                                             |
| **Provide explainability (Attention / SHAP / Attribution)**    |       **VERIFIED**        | Implemented SHAP KernelExplainer and Input $\times$ Gradient saliency maps.                                                                                     |
| **Benchmark against Logistic Regression baseline**             |       **VERIFIED**        | Implemented in `pipeline_fixed.py` showing F1=0.861 (LSTM) vs F1=0.523 (LR).                                                                                    |
| **Offline demonstration interface (PCAP/CSV upload)**          |       **VERIFIED**        | Full React dashboard with offline PCAP upload, trajectory playback, and risk gauges.                                                                            |

---

## 13. Weakness Analysis Categorized by Severity

### Critical Weaknesses

1. **Misrepresentation of Kill-Chain Learning:** The model is trained on CIC-IDS2017, which contains daily isolated script runs rather than multi-phase campaign timelines. The model predicts isolated attack classes, not progression across a kill chain.
2. **Out-of-Distribution Generalization Failure:** Cross-day stress testing (LODO) reveals detection F1 drops to 0.366 and FPR spikes to 26.01%, indicating severe vulnerability to domain shift.
3. **Early Warning Miss Rate:** The forward simulator misses 76.2% of eligible attack sessions in empirical tests (`experiments/eval_results.json`).

### Major Weaknesses

1. **Deterministic Regression Marketed as "World Model":** The model lacks stochastic latent states, variational inference, or environment transition probability distributions.
2. **Defeated by Persistence Baseline on Short-Horizon MAE:** At steps $t+1$ and $t+2$, copying the current state ($S_{t+k}=S_t$) outperforms the LSTM on Mean Absolute Error.
3. **Flawed SHAP Background Reference:** Using `np.zeros((1, 132))` violates cooperative game theory principles and corrupts feature attribution fidelity.
4. **Synthetic Data Inflation:** Rare classes (Infiltration, Heartbleed) are heavily padded with synthetic Gaussian jitter, inflating evaluation metrics.

### Moderate Weaknesses

1. **Packet Capture Ingestion Bottleneck:** User-space Scapy/Npcap cannot sustain line-rate traffic on Gigabit enterprise links.
2. **Dual-Model Architectural Disconnection:** The flow-level model and macro-level model operate as isolated silos rather than an integrated hierarchical model.

### Minor Weaknesses

1. Hardcoded heuristic weights in backend risk scoring (`backend/app/network_state.py:320-345`).
2. Lack of parsing for modern protocols (HTTP/3, QUIC, DoH).

---

## 14. Overclaims & Defensibility Warnings

When presenting to SIH technical evaluators, **eliminate or rephrase the following indefensible claims immediately**:

1. ❌ **Do NOT claim:** _"Our AI learns the MITRE ATT&CK matrix and predicts where the attacker will move next."_  
   _Risk:_ An evaluator will inspect the code and find the static lookup table in `backend/app/mitre.py`.  
   ✔ **Say instead:** _"Our model forecasts future network traffic states and behavior classes; an automated MITRE ATT&CK translation engine maps these projections to standardized TTPs for SOC analyst triaging."_

2. ❌ **Do NOT claim:** _"We built a probabilistic World Model $P(S_{t+1} \mid S_t)$."_  
   _Risk:_ The implementation uses a deterministic Linear layer with MSE loss.  
   ✔ **Say instead:** _"We built an autoregressive state-space world model that rolls forward deterministic latent network representations and computes uncertainty via Monte Carlo dropout."_

3. ❌ **Do NOT claim:** _"The system detects zero-day attacks and unseen threats with 95% accuracy."_  
   _Risk:_ The internal evaluation in `experiments/v3_lodo.json` shows ROC-AUC drops to 0.608 on held-out days.  
   ✔ **Say instead:** _"Under known attack family distributions, the system achieves 86% F1-score; our cross-day stress tests highlight known domain-shift challenges across varying network environments."_

---

## 15. Redundant Artefacts & Recommended Cleanup

1. **Purge Legacy Checkpoints:**  
   Remove `scratch/artifacts_v2_g8_run1/` and `scratch/artifacts_v2_run1/` to prevent confusion during code inspection.
2. **Remove Orphan Virtual Environments:**  
   Delete `frontend/venv/` (which contains broken paths pointing to non-existent system paths like `D:\DevStack\Python\python.exe`).
3. **Consolidate Training Pipelines:**  
   Unify `pipeline.py`, `pipeline_fixed.py`, and `worldmodel_v2/train.py` into a single canonical training script (`train.py`).
4. **Fix Test Suite Dependencies:**  
   Ensure `pytest` and `torch` are cleanly installed in the backend environment so that `pytest backend/tests` executes without errors.

---

## 16. Prioritized Improvement Plan (P0 / P1 / P2)

### P0: Mandatory Fixes (Pre-Evaluation Defense)

1. **Correct the SHAP Baseline:**  
   In `backend/app/inference.py`, replace `np.zeros((1, 132))` with a precomputed medoid of 50 benign training windows (`np.load("artifacts/shap_background.npy")`).
2. **Synchronize Documentation with Code:**  
   Update project documentation to transparently define the MITRE layer as a translation engine and the state transition as an autoregressive state-space predictor.
3. **Transparent Baseline Reporting:**  
   Report both MSE and MAE metrics openly, highlighting the model's advantage at horizons $t+3$ and $t+4$ where nonlinear dynamics exceed persistence capability.

### P1: High Priority (Functional & Demonstration Enhancements)

1. **Markovian State Constraints on Kill Chains:**  
   Implement an empirical transition matrix $T_{ij} = P(\text{Stage}_j \mid \text{Stage}_i)$ in `backend/app/network_state.py` to prevent illogical backward stage jumping in the dashboard.
2. **Probabilistic Transition Head:**  
   Replace the linear state head with Gaussian parameters ($\mu_{t+1}, \log \sigma_{t+1}^2$) trained with Negative Log-Likelihood (NLL) to establish a true probabilistic world model.

### P2: Medium Priority (Enterprise Scalability)

1. **Kernel-Bypass Packet Ingestion:** Replace Python Scapy with an eBPF/XDP kernel probe or DPDK ring buffer.
2. **Graph Representation Learning:** Replace scalar entropy metrics with a PyTorch Geometric Graph Convolutional Network (GCN) over host interaction topologies.

---

## 17. Answers to the 12 Core SIH Evaluation Questions

### Q1: Is the project actually implementing a World Model or simply calling an LSTM classifier a world model?

**Answer:** It is a hybrid architecture. It is more than a simple classifier because it includes an autoregressive next-state transition head ($\hat{S}_{t+1} = W_s h_t + b_s$) trained with MSE reconstruction loss and uses recursive rollout for forward simulation. However, it is not a true generative world model: state transitions are deterministic, and attack classifications branch from the hidden recurrence rather than being conditioned on the generated future state.

### Q2: Is the state representation $S(t)$ mathematically valid and semantically meaningful?

**Answer:** Yes, within defined scopes. In Track A, $S(t)$ represents 22 normalized bidirectional statistical features of a single flow within a 5-tuple session. In Track B, $S(t)$ represents 45 macroscopic network telemetry metrics (port entropy, packet rates, active IP count). It effectively captures traffic volume anomalies, but lacks network graph topological structure.

### Q3: Does the model actually forecast future attack states ($t+k$), or does it only classify past/current traffic?

**Answer:** It actively forecasts future states via autoregressive recursive rollout up to $k=4$ or $k=6$ steps ahead. However, empirical evaluation shows that while it anticipates future feature drift, early warning was achieved in only 23.8% of attack sessions, missing 76.2% of attacks prior to onset.

### Q4: Is the MITRE ATT&CK mapping learned, dynamic, or hardcoded?

**Answer:** It is **hardcoded**. As acknowledged in `backend/app/mitre.py` (lines 4–18), the mapping from predicted behavior classes to MITRE Tactics and Techniques is an analyst-written static lookup dictionary. The neural network does not learn MITRE progression.

### Q5: How reliable is the forward simulation over multiple steps?

**Answer:** State MSE increases progressively from 0.509 at step 1 to 0.559 at step 4. Crucially, a naive persistence baseline ($S_{t+k} = S_t$) beats the neural network in Mean Absolute Error (MAE) for steps $t+1$ (0.248 vs 0.263) and $t+2$ (0.273 vs 0.275), with the model outperforming persistence only at longer horizons ($t+3, t+4$).

### Q6: Does the dataset support true multi-stage kill-chain modeling?

**Answer:** **No.** The primary dataset (CIC-IDS2017) consists of isolated, scheduled attack scripts executed on separate days. It lacks authentic, continuous campaigns where an adversary moves laterally and escalates privileges across the same victim infrastructure over time.

### Q7: Are the explainability outputs mathematically sound?

**Answer:** Partially. The fallback `gradient * input` method is mathematically sound. However, the `shap.KernelExplainer` implementation uses an arbitrary background reference of all zeros (`np.zeros((1, 132))`) and only 30 samples, which violates SHAP theoretical axioms and produces noisy feature attributions.

### Q8: How does the model perform on truly unseen attack families?

**Answer:** Poorly. In the authors' own Leave-One-Day-Out (LODO) experiments (`experiments/v3_lodo.json`), ROC-AUC collapses from 0.955 to 0.608, detection F1 drops to 0.366, and the false positive rate surges to 26.0%.

### Q9: Is the comparison against the Logistic Regression baseline fair?

**Answer:** It is skewed in favor of the model. The Logistic Regression baseline is implemented as an unregularized single linear layer in PyTorch trained for only 15 epochs on flattened raw sequence data, rather than an optimized Scikit-Learn pipeline with proper scaling, PCA, and L2 penalty.

### Q10: Can this system be deployed in a Critical Information Infrastructure (CII) or Enterprise SOC today?

**Answer:** No. The packet capture engine relies on Python Scapy, which drops packets above 50–100 Mbps. In an enterprise environment running at 1 to 10 Gbps, the ingestion layer would fail instantly. Production deployment requires eBPF/XDP or hardware TAP integration.

### Q11: What are the biggest technical risks during a live jury interrogation?

**Answer:**

1. An evaluator inspecting `backend/app/mitre.py` and finding that MITRE mapping is hardcoded.
2. An evaluator asking to see the Leave-One-Day-Out generalization metrics.
3. An evaluator pointing out that copying the last step (persistence) achieves lower MAE than the world model at $t+1$.

### Q12: Does the project solve SIH Problem Statement 26153?

**Answer:** **It satisfies approximately 60% of the functional engineering requirements (ingestion, temporal sequence learning, forward rollout UI, explainability hooks, baseline comparison), but does so via architectural approximations rather than a true probabilistic world model learning kill-chain dynamics.** It is a functional hackathon prototype that must be defended with precision, avoiding unsupported claims.

---

## 18. Architecture Document Structure (2-Page Submission Outline)

### Page 1: System Topology & Dual-Horizon Modeling

- **Section 1: Ingestion & Feature Engineering:**
  - Detail flow extraction (22 bidirectional metrics: flow duration, packet counts, IAT statistics, flag counts) and 1-minute macro network aggregation (45 entropy & host metrics).
- **Section 2: Autoregressive State-Space Architecture:**
  - Document the recurrent LSTM core ($h_t \in \mathbb{R}^{128}$), next-state regression head, auxiliary risk & behavior heads. Include the formal rollout equation $\hat{S}_{t+k} = f(\hat{S}_{t+k-1})$.

### Page 2: Decision Support, Explainability & Verification

- **Section 3: MITRE ATT&CK Translation Engine:**
  - Explain how predicted behavior classes map to ATT&CK tactics via validated SOC rulebases.
- **Section 4: Attribution & Horizon Metrics:**
  - Detail feature attribution via Gradient $\times$ Input and SHAP; document empirical benchmarks against persistence and Logistic Regression baselines.
