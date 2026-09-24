# Model Card: NetForecast LSTM World Model (Project Garud)
**Smart India Hackathon 2026 // Problem Statement 26153**  
*Team Code 4 Change — Autonomous Network Attack Forecasting Engine*

---

## 1. Model Overview

- **Model Name:** NetForecast Multi-Task LSTM World Model
- **Model Architecture:** 2-Layer Recurrent LSTM with Multi-Head Transition & Hazard Output
- **Model Version:** 1.0.0
- **Input Dimension:** 22 CIC-IDS network flow features
- **Window Size ($W$):** 6 sequential flows per session window
- **Inference Runtime:** PyTorch 2.x (CPU / CUDA compatible)
- **Primary Objective:** Given a rolling window of network flow telemetry $X_{t-5:t} \in \mathbb{R}^{6 \times 22}$, forecast the probability of security compromise, classify the current MITRE ATT&CK stage, and autoregressively project future network states $k$ steps forward ($X_{t+1:t+k}$).

---

## 2. Architecture & Multi-Task Heads

```
                          ┌────────────────────────┐
                          │ Input Window [B, 6, 22]│
                          └───────────┬────────────┘
                                      │
                         ┌────────────▼───────────┐
                         │  2-Layer LSTM (h=256)  │
                         │  Dropout = 0.25        │
                         └────────────┬───────────┘
                                      │ Hidden State h_t [B, 256]
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
      ┌───────▼────────┐      ┌───────▼────────┐      ┌───────▼────────┐
      │ Next State Head│      │Infiltration Log│      │   Stage Head   │
      │ Linear(256, 22)│      │ Linear(256,64) │      │ Linear(256,64) │
      │                │      │ Linear(64, 32) │      │ Linear(64, 6)  │
      │                │      │ Linear(32, 1)  │      │                │
      └───────┬────────┘      └───────┬────────┘      └───────┬────────┘
              │                       │                       │
              ▼                       ▼                       ▼
      [B, 22] Pred State      [B, 1] Hazard Logit     [B, 6] Stage Logits
```

1. **Next-State Transition Head ($f_{\text{next}}$):**
   - Projects hidden representation back to feature space $\mathbb{R}^{22}$.
   - Enables recursive rollout (World Model dynamics): $\hat{x}_{t+1}$ is fed back into the LSTM to simulate future telemetry trajectories up to $k=20$ steps.
2. **Infiltration Hazard Head ($f_{\text{infil}}$):**
   - 3-layer MLP with ReLU and Dropout yielding a single scalar logit $\to \sigma(z) \in [0, 1]$.
   - Trained with weighted BCE on whether the next flow is malicious; its sigmoid output is used as the risk score (not separately probability-calibrated).
3. **Stage Head ($f_{\text{stage}}$):**
   - 2-layer MLP yielding 6 unnormalized logits $\to \text{Softmax}(z) \in \Delta^5$.
   - Classifies the MITRE ATT&CK stage of the window's most recent flow (see §5, "Training targets per window").

---

## 3. MITRE ATT&CK 6-Stage Taxonomy

| Stage ID | Stage Name | MITRE Tactic | Dataset labels mapped to this stage (`data/preprocess_cicids.py::map_label`) |
|:---:|:---|:---|:---|
| **0** | **Benign** | Normal Baseline | BENIGN |
| **1** | **Reconnaissance** | TA0043 (Reconnaissance) | PortScan, Bot, SSH-Patator, FTP-Patator |
| **2** | **Initial Access** | TA0001 (Initial Access) | Web Attack Brute Force, XSS, SQL Injection (CIC-IDS2017 + CIC-IDS2018) |
| **3** | **Lateral Movement** | TA0008 (Lateral Movement) | Infiltration (CIC-IDS2017 + CIC-IDS2018) |
| **4** | **C2 (Command & Control)**| TA0011 (Command & Control) | DDoS, DoS Hulk, GoldenEye, Slowloris, Slowhttptest (the dataset has no dedicated C2-beacon label) |
| **5** | **Exfiltration** | TA0010 (Exfiltration) | Heartbleed (only ~11 real flows exist; detected by signature, not ML) |

---

## 4. 22 Standardized CIC-IDS Flow Features

Feature order is strictly invariant across training, serialization, REST ingestion, and SHAP explainability:

```python
FLOW_FEATURES = [
    "flow_duration",      # Flow duration in microseconds
    "tot_fwd_pkts",       # Total forward packets
    "tot_bwd_pkts",       # Total backward packets
    "fwd_pkt_len_mean",   # Mean size of forward packets (bytes)
    "bwd_pkt_len_mean",   # Mean size of backward packets (bytes)
    "flow_bytes_s",       # Flow throughput in bytes/second
    "flow_pkts_s",        # Flow throughput in packets/second
    "flow_iat_mean",      # Mean inter-arrival time across flow
    "flow_iat_std",       # Standard deviation of inter-arrival time
    "fwd_iat_mean",       # Mean IAT of forward direction
    "bwd_iat_mean",       # Mean IAT of backward direction
    "syn_flag_cnt",       # SYN flag occurrences
    "ack_flag_cnt",       # ACK flag occurrences
    "fin_flag_cnt",       # FIN flag occurrences
    "rst_flag_cnt",       # RST flag occurrences
    "psh_flag_cnt",       # PSH flag occurrences
    "urg_flag_cnt",       # URG flag occurrences
    "down_up_ratio",      # Download to upload ratio
    "pkt_size_avg",       # Average packet size across flow
    "ttl_variance",       # Variance of IP Time-To-Live
    "tcp_win_size",       # TCP initial window size
    "retransmit_cnt",     # Retransmitted packet count
]
```

---

## 5. Training Dataset & Preprocessing

- **Source Corpus:** CIC-IDS2017 benchmark dataset (Tuesday, Wednesday, Thursday, Friday captures), augmented with real Lateral Movement (Infiltration) flows from **CIC-IDS2018**'s two dedicated infiltration days (Wednesday-28-02-2018, Thursday-01-03-2018) and real Initial Access (Web Attack) flows from **CIC-IDS2018**'s two dedicated web-attack days (Thursday-22-02-2018, Friday-23-02-2018) — see below.
- **Sessionization:**
  - CIC-IDS2017 rows in `real_flows.csv` come from the `MachineLearningCSV` release, which has no IP or timestamp columns, so `data/preprocess_cicids.py` assigns a placeholder IP pair (`192.168.10.50` / `172.16.0.1`), synthetic timestamps 2 seconds apart, and groups **consecutive CSV rows into fixed-size chunks** (median 240 rows) as "sessions". A session is therefore a slice of the capture in file order, not one host pair's traffic; it can straddle attack/benign boundaries and interleaves unrelated connections. (The IP-pair + 5-minute-bucket grouping in `preprocess_cicids.py` only applies when the source CSV has IP and timestamp columns, which the shipped one does not.)
  - CIC-IDS2018's public CSVs have no Src/Dst IP columns (privacy-scrubbed); its added rows are chunked into synthetic-boundary sessions of consecutive (by timestamp) real flows instead — 12 per session for Infiltration, 8 for Web Attack. The feature *values* are real measured flow statistics; only the session *boundaries* are synthetic for this subset.
  - Flows sequenced chronologically; sub-sequences sliced into sliding windows of length $W=6$.
- **Training targets per window:** the next-state head and infiltration head learn the flow *after* the window; the stage head learns the stage of the window's *last* flow (`--stage-target current`, the default). The stage target matches production: `backend/app/ingestion.py` runs the model on the window ending with a newly arrived flow and stores `predicted_stage` on that flow. Until this change the stage head was trained on the next flow, so the dashboard showed a guess about a flow that hadn't arrived yet against the current one. That mismatch was the main remaining cause of weak Initial Access scores (a single attack request surrounded by benign flows can't be predicted from the benign flows before it). Aligning it moved Initial Access F1 from 0.530 to 0.838 with no other stage regressing (§6). Forecasting still comes from the next-state head and the autoregressive rollout, which are unchanged.
- **Normalization:**
  - `StandardScaler` fitted on training split only (mean and variance preserved in `artifacts/scaler.pkl`).
  - Strict absence of test-set data leakage.
- **3-way train/val/test split (`three_way_split()` in `pipeline_fixed.py`):** an earlier version of this pipeline picked its "best" checkpoint by evaluating each epoch on the *same* held-out set it then reported final metrics on — checkpoint-selection leakage, which optimistically biases the reported score toward whichever epoch happened to do best on that exact data. Sessions are now split three ways (currently 1,673 train / 239 validation / 478 test); checkpoint selection uses validation only, and the test set is touched exactly once, at the very end. Adding sessions to the dataset (as each augmentation step did) reshuffles which sessions land in test, so numbers from before and after a data change are measured on different — though identically constructed — test sets.
- **Handling Class Imbalance:**
  - **Stage head loss: Focal Loss** (Lin et al., 2017), `FL(p_t) = -alpha_t * (1-p_t)^gamma * log(p_t)`, `gamma=2.0`, generalizing the plain class-weighted cross-entropy tried earlier (`gamma=0` reduces exactly to it — see `pipeline_fixed.py::FocalLoss`). Down-weights already-confident predictions instead of blanket-boosting rare-class logits, which targets the specific "confidently wrong" false-positive pattern that caused Initial Access's poor precision, rather than just its recall.
  - `alpha_t` (per-class weight) is inverse-frequency, clipped to `[0.2, 6.0]` — tuned down three times: an initial `[0.2, 50.0]` clip over-corrected and collapsed Initial Access precision to ~6%; `[0.2, 15.0]` combined with focal loss improved it; `[0.2, 8.0]` improved it further; `[0.2, 6.0]` (final) gave the best macro-F1 balance — a further tightening to `[0.2, 4.0]` was tried and rejected because it improved Initial Access marginally (F1 0.377→0.406) at the cost of regressing Lateral Movement (F1 0.922→0.882) and Reconnaissance (F1 0.758→0.743), a worse overall trade. See §6 for exact current numbers (measured after the 3-way split fix above, so slightly different from numbers quoted in earlier commits).
  - Infiltration hazard trained using weighted Binary Cross-Entropy with Logits (`pos_weight = 2.94`).
  - **Real data augmentation for Lateral Movement:** real_flows.csv originally had only ~36 real Lateral Movement rows (CIC-IDS2017's entire public release has ~36 in total) — a held-out evaluation confirmed this was unlearnable, including after trying synthetic-profile oversampling (it didn't transfer to real traffic). `data/augment_lateral_movement.py` adds 7,940 real Infiltration rows from CIC-IDS2018 instead. See §6 for the before/after result.
  - **Real data augmentation for Initial Access:** real_flows.csv's original 2,180 real Initial Access rows (CIC-IDS2017's Web Attack day) were enough to learn from but not enough diversity to generalize — the model over-fired on Benign HTTP traffic. `data/augment_initial_access.py` adds 928 real Web Attack Brute Force / XSS / SQL Injection rows from CIC-IDS2018's two web-attack days, bringing the total to 3,108. See §6 for the before/after result.
  - **Root cause found and fixed for Initial Access's session construction:** after the above still left Initial Access clearly the weakest stage, a confusion-matrix analysis (not just P/R/F1 aggregates) showed the errors were concentrated almost entirely in the *original* CIC-IDS2017 rows specifically — test recall 0.476 / precision 0.300 on that subset alone, versus recall 0.969 / precision 1.000 on the CIC-IDS2018 rows from the exact same augmentation era. The cause: CIC-IDS2017 sessions are fixed-size chunks of consecutive CSV rows (see Sessionization above), so the web-attack rows sit inside chunks that are mostly benign traffic. Confirmed directly: every one of the 433 CIC-IDS2017-origin sessions containing an Initial Access row also contains Benign rows. `data/fix_initial_access_sessions.py` adds a second view of the same 2,180 real CIC-IDS2017 rows, re-chunked into pure attack-only session_len=8 sessions (mirroring the technique that already worked for the CIC-IDS2018 rows) — it does not replace the mixed-session rows, since live sessions (grouped by IP pair and 5-minute bucket in `ingestion.py`) will also contain mixed traffic. Note that this duplicates the same 2,180 underlying flow rows under a second set of session IDs, so the session-level split can put a row in train and an identical copy in test; §8 quantifies this. Total Initial Access rows: 3,108 → 5,288. See §6 for the result.
  - **Post-hoc per-class logit-bias calibration** (`experiments/calibrate_stage_logits.py`, applied via `config.json`'s `stage_logit_bias` and `model_loader.py`): a coordinate-ascent search over additive biases on the 6 stage logits, fit to maximize macro-F1 on the **validation** split only (never test), then applied at inference time before argmax in `inference.py`. This is a second, independent, no-retraining lever on top of the class-weight/focal-loss tuning above — it improves the decision boundary the already-trained model uses, rather than retraining a new one. See §6 for the calibrated vs. uncalibrated numbers.
  - **Synthetic train-only oversampling** remains in place for Exfiltration only (300 synthetic sessions from calibrated feature profiles) as defense-in-depth for the ML stage head, though Exfiltration/Heartbleed is actually caught by a separate deterministic signature detector — see §8.

---

## 6. Evaluation & Comparative Benchmark

Evaluated on a held-out, session-level test split (478 sessions; 64,642 flows forming
61,776 six-flow windows) that never touches training, scaler fitting, **or checkpoint
selection** (see the 3-way split note in §5) — it is touched exactly once, for the numbers
below. All numbers are reproduced directly from `backend/artifacts/benchmark_comparison.csv`
and `python experiments/calibrate_stage_logits.py` — nothing here is estimated.

> [!NOTE]
> Per-stage numbers are shown both **uncalibrated** (raw argmax) and **calibrated** (the shipped `stage_logit_bias` applied, see §5). The calibration only changes which stage label is reported; the binary alert decision uses the separate infiltration head, which calibration doesn't touch.

### Binary detection (malicious vs. benign)

| Metric | Logistic Regression (baseline) | Isolation Forest (baseline) | NetForecast World Model (LSTM) |
|:---|:---:|:---:|:---:|
| **Temporal Context** | No (1 flow) | No (1 flow) | Yes ($W=6$ flow history) |
| **F1-Score** | 0.523 | 0.402 | **0.862** |
| **Precision** | 0.689 | 0.374 | **0.859** |
| **Recall** | 0.421 | 0.434 | **0.864** |
| **False Positive Rate** | 6.16% | 23.49% | **4.59%** |

Measured CPU latency of the shipped model: 1.2 ms per single-window prediction, about 160 ms for a 6-step forecast with 20 Monte Carlo runs, about 10 ms for a gradient explanation.

### Per-MITRE-stage classification (honest breakdown, not just binary)

The stage head's real capability varies sharply by class — this is measured
directly, not projected, and is why the headline binary F1 above should not be
read as "detects all 6 stages equally well". "Calibrated" is what the shipped
model reports today; "Uncalibrated" is the same weights before the §5 logit-bias
adjustment, shown so the calibration's real effect is visible.

| MITRE Stage | Test support | Precision (uncal → cal) | Recall (uncal → cal) | F1 (uncal → cal) | Status |
|:---|---:|:---|:---|:---|:---|
| C2 | 6,588 | 0.976 → 0.996 | 0.981 → 0.967 | 0.979 → 0.981 | Reliable |
| Benign | 46,676 | 0.989 → 0.978 | 0.947 → 0.987 | 0.968 → 0.983 | Reliable |
| Reconnaissance | 7,116 | 0.806 → 0.934 | 0.959 → 0.911 | 0.875 → 0.922 | Reliable |
| **Lateral Movement** | **771** | **0.783 → 0.989** | **0.929 → 0.855** | **0.849 → 0.917** | **Reliable — fixed via real CIC-IDS2018 data (was 0.000/0.000/0.000 before that fix)** |
| **Initial Access** | **623** | **0.531 → 0.815** | **0.944 → 0.862** | **0.680 → 0.838** | **Reliable — weakest of the five learnable stages but no longer a gap. History of calibrated F1: 0.262 → 0.377 → 0.423 → 0.530 → 0.838 (see §5 and §8)** |
| Exfiltration | 2 | 0.000 → 0.000 | 0.000 → 0.000 | 0.000 → 0.000 | Not learnable in the ML model (n=2) — caught instead by a deterministic signature detector, see §8 |

Macro-F1 over all six classes: 0.725 uncalibrated → 0.774 calibrated (Exfiltration's 0.0 pulls it down; the mean over the five learnable stages is 0.928).

---

## 7. Explainability & Trust Architecture

1. **Fast Gradient Attribution ($\mathcal{O}(1)$):**
   $$A_i = \left| \frac{\partial \mathcal{L}_{\text{infil}}}{\partial x_{t, i}} \cdot x_{t, i} \right|$$
   Provides sub-second feature importance for immediate UI responsiveness.
2. **Deep Shapley Values (SHAP KernelExplainer):**
   - Uses zero-vector baseline in scaled feature space ($\mu_{\text{train}}$).
   - Generates game-theoretic marginal contributions for regulatory forensic dossiers.

---

## 8. Limitations & Operational Considerations

- **Encrypted Payloads:** The model operates entirely on L3/L4 statistical flow headers and metadata; payload decryption is not required, preserving end-user privacy.
- **Concept Drift:** Sudden network infrastructure changes (e.g., MTU changes or large backup migrations) can alter IAT and throughput distributions. The adaptive EMA threshold ($\mu_t + 2\sigma_t$) attenuates false alarms, but periodic retraining is recommended.
- **Lateral Movement and Exfiltration both originally had 0% recall.** CIC-IDS2017's entire public release contains only ~36 Infiltration flows and ~11 Heartbleed flows — real_flows.csv inherited that scarcity. Train-only synthetic oversampling (300 sessions/stage, from calibrated feature profiles) was tried first for both and confirmed via held-out evaluation to **not transfer** to real traffic — hand-crafted profiles don't match the real feature distribution closely enough. Both are now resolved, by two different mechanisms:
  - **Lateral Movement is fixed with real data.** `data/augment_lateral_movement.py` pulls 7,940 real Infiltration flow rows from CIC-IDS2018's two dedicated infiltration days and merges them in as genuine (not synthetic) Lateral Movement training *and test* sessions. Held-out evaluation on 900 real CIC-IDS2018 test flows now shows Precision 0.732 / Recall 0.917 / F1 0.814 — one of the strongest-performing classes in the model. This is the real fix; synthetic data was never going to work for a behavioral pattern like this.
  - **Exfiltration/Heartbleed is covered by a separate deterministic signature detector** (`capture/signatures.py::detect_heartbleed`), not the ML model — CVE-2014-0160 has a well-known, deterministic wire-format signature (a TLS Heartbeat record whose internal `payload_length` field claims more bytes than the record actually contains), so it doesn't need to be learned from 2 training examples at all. Wired into both PCAP upload and live capture; fires an immediate critical alert on the very first matching flow, independent of the 6-flow ML window. Verified end-to-end against a synthetically crafted malicious packet (real detection, not a stub) and confirmed not to false-positive on legitimate HTTP/heartbeat traffic. This mechanism was the right call here because Heartbleed is a protocol bug, not a behavioral pattern — real training data for it barely exists anywhere (CIC-IDS2017/2018 combined have well under 20 real Heartbleed flows), so a signature was the only realistic fix.
- **Initial Access was the hardest stage and is now at F1 0.838 (precision 0.815, recall 0.862).** It got there through six cumulative, individually verified changes: tightening the class-weight clip (50x → 6x), focal loss (γ=2), 928 real CIC-IDS2018 Web Attack rows (`data/augment_initial_access.py`), per-class logit-bias calibration (`experiments/calibrate_stage_logits.py`), re-chunking the original CIC-IDS2017 web-attack rows into pure attack-only sessions alongside their mixed-session form (`data/fix_initial_access_sessions.py` — CIC-IDS2017's chunked-row sessions had put attack rows in the same sessions as benign traffic), and — the largest single step, F1 0.530 → 0.838 — training the stage head on the flow production actually labels rather than the unseen next flow (§5, "Training targets per window"). Calibrated F1 history: 0.262 → 0.377 → 0.423 → 0.530 → 0.838. Two ideas were tested and not shipped because they didn't help: gating the stage decision on the infiltration head (macro-F1 +0.002) and a skip connection from the window's last raw flow into the heads (F1 0.423 → 0.422). It remains the lowest of the five learnable stages; its residual errors are mostly confusion with Benign web traffic, which payload-aware features could address.
- **Checkpoint-selection leakage has been fixed.** `pipeline_fixed.py` used to select its "best" epoch checkpoint by evaluating on the same held-out set it then reported final metrics on — an evaluation-methodology bug, not a data leak, but still an optimistic bias in the reported numbers. It now uses a genuine 3-way train/val/test split (`three_way_split()`); see §5 and the note at the top of §6 for the resulting (honestly lower) numbers. **A family-holdout generalization *experiment* has since been added (§9) and demonstrates real, if uneven, transfer to genuinely unseen attack tools — on a separate, throwaway model, not the shipped `backend/artifacts/` model.** The production model's own train/val/test split is still purely random at the session level; §9's result is evidence about the architecture and training recipe's capacity to generalize, not a claim that the shipped weights were themselves family-holdout validated. Two rigor gaps remain for the *production* model specifically, both explicitly out of scope rather than silently skipped: it has no family-holdout validation of its own, and the split is not **temporal** (train-on-past/test-on-future, which the PS's evaluation methodology also mentions for deployment realism). A true temporal split isn't straightforward for this project as-is: `real_flows.csv` merges CIC-IDS2017 (real 2017 capture times), CIC-IDS2018 (real 2018 capture times, discarded and replaced with a synthetic 2026 epoch during merging so session grouping stays consistent — see `data/augment_lateral_movement.py`), and synthetic Exfiltration sessions on yet another synthetic epoch, so a naive chronological cut would separate by *data source* rather than by genuine temporal drift within one capture.
- **These per-stage numbers are the accuracy that matters for a live demo audience.** The judge-facing simulator (`demo/traffic_simulator.py`) drives all 6 stages from hand-authored synthetic profiles for a smooth visual progression; it does not reflect the trained model's real per-stage capability shown in §6. The simulator's hand-authored "Benign" profile doesn't match the real benign feature distribution closely, so it can trigger alerts on simulated benign sessions; judge real capability by the §6 numbers or by replaying real PCAPs, not by the simulator. Exfiltration is caught by the signature detector rather than the ML path.
- **Train/test overlap inflates the §6 numbers modestly.** Sessions are split at the session level, but the same underlying flows appear under more than one session ID (the re-chunked Initial Access rows, §5) and many flows are naturally near-identical across sessions (e.g. nmap probes). Measured on the shipped model: the share of test rows whose exact 22-feature vector also occurs in train is 74% for Reconnaissance, 56% for Initial Access (67% for the re-chunked rows), 17% for Lateral Movement, 13% for Benign, 12% for C2. Re-scoring only the test windows whose target flow has *no* identical copy in train gives Initial Access F1 0.795 (P 0.687, R 0.942, down from 0.838), Reconnaissance 0.886 (from 0.922), Lateral Movement 0.910 (from 0.917), C2 0.987 and Benign 0.990 (unchanged or slightly higher). The results hold up, but the de-duplicated numbers are the more honest estimate of performance on unseen flows. Also note the split is random over contiguous row-chunks, not temporal, and no attack scenario is held out of the production model (§9 tests that only on a separate throwaway model).
- **The k-step forecast's raw per-step probability decays in later steps for most attack types, found while building `backend/tests/test_model_quality.py`'s real-data QA tests.** Feeding a real, confidently-classified attack window (Reconnaissance, C2, or Initial Access) into `forecast_rollout` gives a highly confident first 3-4 steps, then the *raw* `infiltration_prob_mean` drifts toward 0 by steps 5-6 — classic autoregressive drift, since step $k{>}1$ conditions on the model's own predicted `next_state` from step $k{-}1$ rather than real telemetry, and small errors compound. Lateral Movement is the one stage that doesn't show this decay in testing. This doesn't reach the operator: `alert_triggered` latches on the *first* step that crosses threshold rather than requiring the last step to still be above it, and the EMA-smoothed value actually surfaced in the API/UI (`infiltration_prob_ema`) decays much more gently than the raw mean (e.g. a real C2 session's raw probability fell to 0.02 by step 6 while its EMA was still 0.41) — both were verified to hold up correctly on real attack sessions, per `TestForecastEscalation` in the same test file. Worth knowing if extending the forecast horizon past $k=6$: raw per-step confidence, unlike the EMA/alert signals, is not reliable that far out.

---

## 9. Generalization to Unseen Attack Families

The PS's evaluation methodology calls for demonstrating "transfer to unseen
malware" — not just accuracy on attack tools already represented in the
training data. `experiments/family_holdout_eval.py` tests this directly: it
trains a **separate, throwaway model** (same architecture and hyperparameters
as production, but not the shipped `backend/artifacts/` model) with three
entire attack **families** removed from training completely — not just from
a session split, from the CSV load onward — then measures how well that
model recognizes each held-out family at test time, having never seen a
single example of it.

| Held-out family | True stage | Trained on instead | n (test) | Correct-stage rate | Binary alert rate |
|:---|:---|:---|---:|---:|---:|
| DoS slowloris | C2 | DoS Hulk, GoldenEye, Slowhttptest, DDoS | 3,762 | **58.9%** | **64.1%** |
| Bot | Reconnaissance | PortScan, FTP-Patator, SSH-Patator | 216 | 0.9% | 0.9% |
| Web Attack XSS | Initial Access | Web Attack Brute Force, SQL Injection | 17 | 0.0% | 0.0% |

**Read honestly, not cherry-picked:**
- **DoS slowloris → C2 generalizes meaningfully.** Never having seen a single slowloris flow, the model still correctly flags 64% of real slowloris traffic as malicious and 59% as specifically C2 — well above the 1-in-6 (16.7%) chance rate for stage classification. Volumetric DoS tools (Hulk, GoldenEye, DDoS) and low-and-slow slowloris are architecturally different attacks, but they apparently share enough flow-level signature (sustained connections, skewed packet timing) for the model to generalize across the technique, not just memorize specific tools.
- **Bot → Reconnaissance does not generalize at all.** 213 of 216 real Bot flows get classified as Benign. Botnet beaconing is a fundamentally different behavioral pattern from the active-scanning/brute-force traffic (PortScan, Patator) the model actually learned "Reconnaissance" from — this is an honest negative result, not a bug. Closing it would need Bot-family examples in training, not more tuning.
- **Web Attack XSS → Initial Access does not generalize** (0/17), though n=17 is too small to draw a strong conclusion beyond "no evidence of transfer." XSS is payload-content-driven; the 22 flow-level statistical features this system uses may genuinely carry little signal for it, same underlying limitation noted for Initial Access precision in §8. Note this experiment trains its throwaway model on CIC-IDS2017 only and predates the CIC-IDS2018 web-attack data augmentation described in §5/§8 — it has not been rerun against the augmented data, so it should be read as evidence about the architecture's capacity to generalize to unseen XSS specifically, not as an up-to-date measurement of the production model.

**What this result is not:** the ~99.7% validation F1 seen during this
experiment's training is **not** comparable to the production model's ~86%
binary F1 in §6 — this experiment used a different, smaller, less diverse
data mix (only the CIC-IDS2017 files needed for the 3 target families,
heavily weighted toward large easily-separable classes like DoS Hulk and
PortScan) and exists purely to measure family-transfer, not to represent
overall system accuracy. Reproduce with `python experiments/family_holdout_eval.py`.
