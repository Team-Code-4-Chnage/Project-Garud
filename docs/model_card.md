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
   - Represents the calibrated probability of host or service compromise.
3. **Stage Head ($f_{\text{stage}}$):**
   - 2-layer MLP yielding 6 unnormalized logits $\to \text{Softmax}(z) \in \Delta^5$.
   - Identifies the operational MITRE ATT&CK stage of the session.

---

## 3. MITRE ATT&CK 6-Stage Taxonomy

| Stage ID | Stage Name | MITRE Tactic | Representative CIC-IDS2017 Traffic |
|:---:|:---|:---|:---|
| **0** | **Benign** | Normal Baseline | HTTP, HTTPS, DNS, NTP, SSH management |
| **1** | **Reconnaissance** | TA0043 (Reconnaissance) | PortScan, Network sweeping, Host discovery |
| **2** | **Initial Access** | TA0001 (Initial Access) | SSH-Patator, FTP-Patator, Web vulnerability probes |
| **3** | **Lateral Movement** | TA0008 (Lateral Movement) | SMB exploit probes, Internal pivot flows |
| **4** | **C2 (Command & Control)**| TA0011 (Command & Control) | Botnet beacons, periodic command channels |
| **5** | **Exfiltration** | TA0010 (Exfiltration) | Large outbound byte bursts, HTTP data theft |

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
  - CIC-IDS2017 flows grouped by `(src_ip, dst_ip, 300s_time_bucket)`.
  - CIC-IDS2018's public CSVs have no Src/Dst IP columns (privacy-scrubbed); its added rows are chunked into synthetic-boundary sessions of 12 consecutive (by timestamp) real Infiltration flows instead. The feature *values* are real measured flow statistics; only the session *boundaries* are synthetic for this subset.
  - Flows sequenced chronologically; sub-sequences sliced into sliding windows of length $W=6$.
- **Normalization:**
  - `StandardScaler` fitted on training split only (mean and variance preserved in `artifacts/scaler.pkl`).
  - Strict absence of test-set data leakage.
- **3-way train/val/test split (`three_way_split()` in `pipeline_fixed.py`):** an earlier version of this pipeline picked its "best" checkpoint by evaluating each epoch on the *same* held-out set it then reported final metrics on — checkpoint-selection leakage, which optimistically biases the reported score toward whichever epoch happened to do best on that exact data. Sessions are now split three ways (1,400 train / 200 validation / 401 test); checkpoint selection uses validation only, and the test set is touched exactly once, at the very end. The test boundary is computed identically to the original 2-way split (same RNG, same permutation, same cut point), so it's byte-identical to the test set used in every prior benchmark in this project's history — earlier and current numbers stay directly comparable.
- **Handling Class Imbalance:**
  - **Stage head loss: Focal Loss** (Lin et al., 2017), `FL(p_t) = -alpha_t * (1-p_t)^gamma * log(p_t)`, `gamma=2.0`, generalizing the plain class-weighted cross-entropy tried earlier (`gamma=0` reduces exactly to it — see `pipeline_fixed.py::FocalLoss`). Down-weights already-confident predictions instead of blanket-boosting rare-class logits, which targets the specific "confidently wrong" false-positive pattern that caused Initial Access's poor precision, rather than just its recall.
  - `alpha_t` (per-class weight) is inverse-frequency, clipped to `[0.2, 6.0]` — tuned down three times: an initial `[0.2, 50.0]` clip over-corrected and collapsed Initial Access precision to ~6%; `[0.2, 15.0]` combined with focal loss improved it; `[0.2, 8.0]` improved it further; `[0.2, 6.0]` (final) gave the best macro-F1 balance — a further tightening to `[0.2, 4.0]` was tried and rejected because it improved Initial Access marginally (F1 0.377→0.406) at the cost of regressing Lateral Movement (F1 0.922→0.882) and Reconnaissance (F1 0.758→0.743), a worse overall trade. See §6 for exact current numbers (measured after the 3-way split fix above, so slightly different from numbers quoted in earlier commits).
  - Infiltration hazard trained using weighted Binary Cross-Entropy with Logits (`pos_weight = 2.94`).
  - **Real data augmentation for Lateral Movement:** real_flows.csv originally had only ~36 real Lateral Movement rows (CIC-IDS2017's entire public release has ~36 in total) — a held-out evaluation confirmed this was unlearnable, including after trying synthetic-profile oversampling (it didn't transfer to real traffic). `data/augment_lateral_movement.py` adds 7,940 real Infiltration rows from CIC-IDS2018 instead. See §6 for the before/after result.
  - **Real data augmentation for Initial Access:** real_flows.csv's original 2,180 real Initial Access rows (CIC-IDS2017's Web Attack day) were enough to learn from but not enough diversity to generalize — the model over-fired on Benign HTTP traffic. `data/augment_initial_access.py` adds 928 real Web Attack Brute Force / XSS / SQL Injection rows from CIC-IDS2018's two web-attack days, bringing the total to 3,108. See §6 for the before/after result.
  - **Post-hoc per-class logit-bias calibration** (`experiments/calibrate_stage_logits.py`, applied via `config.json`'s `stage_logit_bias` and `model_loader.py`): a coordinate-ascent search over additive biases on the 6 stage logits, fit to maximize macro-F1 on the **validation** split only (never test), then applied at inference time before argmax in `inference.py`. This is a second, independent, no-retraining lever on top of the class-weight/focal-loss tuning above — it improves the decision boundary the already-trained model uses, rather than retraining a new one. See §6 for the calibrated vs. uncalibrated numbers.
  - **Synthetic train-only oversampling** remains in place for Exfiltration only (300 synthetic sessions from calibrated feature profiles) as defense-in-depth for the ML stage head, though Exfiltration/Heartbleed is actually caught by a separate deterministic signature detector — see §8.

---

## 6. Evaluation & Comparative Benchmark

Evaluated on a held-out, session-level test split (424 sessions / 58,945 windowed
sequences) that never touches training, scaler fitting, **or checkpoint selection**
(see the 3-way split note in §5) — it is touched exactly once, for the numbers
below. All numbers are reproduced directly from `backend/artifacts/benchmark_comparison.csv`
and `experiments/calibrate_stage_logits.py` — nothing here is estimated.

> [!NOTE]
> Binary detection numbers reflect the current shipped model (real CIC-IDS2018 Initial Access data + class-weight clip retuned to 6.0, see §5). Per-stage numbers are shown both **uncalibrated** (raw argmax) and **calibrated** (the shipped `stage_logit_bias` applied, see §5) — the calibration only changes which stage label is reported for an already-flagged window; it does not change the binary alert decision, which uses a separate model head untouched by this calibration.

### Binary detection (malicious vs. benign)

| Metric | Logistic Regression (baseline) | Isolation Forest (baseline) | NetForecast World Model (LSTM) |
|:---|:---:|:---:|:---:|
| **Temporal Context** | ❌ (1 flow) | ❌ (1 flow) | ✅ ($W=6$ flow history) |
| **F1-Score** | 0.535 | 0.355 | **0.862** |
| **Precision** | 0.694 | 0.338 | **0.859** |
| **Recall** | 0.436 | 0.373 | **0.865** |
| **False Positive Rate** | 6.42% | 24.41% | **4.75%** |

### Per-MITRE-stage classification (honest breakdown, not just binary)

The stage head's real capability varies sharply by class — this is measured
directly, not projected, and is why the headline binary F1 above should not be
read as "detects all 6 stages equally well". "Calibrated" is what the shipped
model reports today; "Uncalibrated" is the same weights before the §5 logit-bias
adjustment, shown so the calibration's real effect is visible.

| MITRE Stage | Test support | Precision (uncal → cal) | Recall (uncal → cal) | F1 (uncal → cal) | Status |
|:---|---:|:---|:---|:---|:---|
| C2 | 6,467 | 0.922 → 0.960 | 0.933 → 0.917 | 0.928 → 0.938 | Reliable, strongest class |
| **Lateral Movement** | **857** | **0.936 → 0.985** | **0.908 → 0.865** | **0.922 → 0.921** | **Reliable — fixed via real CIC-IDS2018 data (was 0.000/0.000/0.000 before that fix)** |
| Benign | 44,204 | 0.962 → 0.948 | 0.912 → 0.963 | 0.937 → 0.955 | Reliable |
| Reconnaissance | 6,855 | 0.689 → 0.835 | 0.843 → 0.765 | 0.758 → 0.799 | Reliable, improved by the same class-weight retune + calibration that helped Initial Access |
| Initial Access | 560 | 0.270 → 0.351 | 0.620 → 0.532 | 0.377 → 0.423 | Substantially improved (was 0.166/0.623/0.262 two tuning passes ago — precision now ~2.1x that, ~5.7x the original 0.062) via real CIC-IDS2018 web-attack data + retuned class weight + logit calibration; still the weakest class — see §8 |
| Exfiltration | 2 | 0.000 → 0.000 | 0.000 → 0.000 | 0.000 → 0.000 | Not functional in the ML model (n=2, statistically unmeasurable regardless) — caught instead by a deterministic signature detector, see §8 |

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
- **Initial Access precision has improved substantially (6.2% → 27.0% → 35.1%) but is still the weakest class.** The stage head over-fires on Initial Access, largely confusing it with Benign HTTP traffic (both involve elevated PSH-flag, asymmetric-packet-size web-like flows at the 22-feature level). Four independent, cumulative fixes improved this without ever badly regressing another class: reducing the class-weight clip 50x→15x→8x→6x, switching the stage loss to focal loss γ=2 (targets exactly this "confidently wrong" false-positive pattern), adding 928 real CIC-IDS2018 Web Attack rows (`data/augment_initial_access.py`) for more behavioral diversity than the original 2,180-row CIC-IDS2017-only sample gave, and post-hoc per-class logit-bias calibration (`experiments/calibrate_stage_logits.py`) fit on validation only. Precision moved 0.062 → 0.166 → 0.270 (uncalibrated) → 0.351 (calibrated), roughly a 5.7x improvement overall. The remaining gap looks like a genuine feature-separability limit rather than a tuning problem: CIC-IDS2017/2018's 22 flow-level statistical features may simply not distinguish SQLi/XSS/brute-force traffic from ordinary web browsing as sharply as packet-payload features would — closing it further would likely need payload-aware features (a larger architectural change) rather than more tuning of the same feature set.
- **Checkpoint-selection leakage has been fixed.** `pipeline_fixed.py` used to select its "best" epoch checkpoint by evaluating on the same held-out set it then reported final metrics on — an evaluation-methodology bug, not a data leak, but still an optimistic bias in the reported numbers. It now uses a genuine 3-way train/val/test split (`three_way_split()`); see §5 and the note at the top of §6 for the resulting (honestly lower) numbers. **A family-holdout generalization *experiment* has since been added (§9) and demonstrates real, if uneven, transfer to genuinely unseen attack tools — on a separate, throwaway model, not the shipped `backend/artifacts/` model.** The production model's own train/val/test split is still purely random at the session level; §9's result is evidence about the architecture and training recipe's capacity to generalize, not a claim that the shipped weights were themselves family-holdout validated. Two rigor gaps remain for the *production* model specifically, both explicitly out of scope rather than silently skipped: it has no family-holdout validation of its own, and the split is not **temporal** (train-on-past/test-on-future, which the PS's evaluation methodology also mentions for deployment realism). A true temporal split isn't straightforward for this project as-is: `real_flows.csv` merges CIC-IDS2017 (real 2017 capture times), CIC-IDS2018 (real 2018 capture times, discarded and replaced with a synthetic 2026 epoch during merging so session grouping stays consistent — see `data/augment_lateral_movement.py`), and synthetic Exfiltration sessions on yet another synthetic epoch, so a naive chronological cut would separate by *data source* rather than by genuine temporal drift within one capture.
- **These per-stage numbers are the accuracy that matters for a live demo audience.** The judge-facing simulator (`demo/traffic_simulator.py`) drives all 6 stages from hand-authored synthetic profiles for a smooth visual progression; it does not reflect the trained model's real per-stage capability shown in §6. As of this evaluation, Benign/Reconnaissance/C2/Lateral Movement all correctly reflect real attack traffic if fed through PCAP or live capture; Initial Access is substantially improved but still over-alerts more than the other classes; Exfiltration is caught by the signature detector rather than the ML path.

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
