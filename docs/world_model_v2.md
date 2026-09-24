# World Model V2: Network-State Forecasting Experiment

Status: experimental. V2 is trained and evaluated offline. It is not wired into the API or dashboard; the shipped model is still V1 (`backend/artifacts/`). V1 is unchanged and is the baseline.

## What changed

| | V1 (shipped) | V2 (this experiment) |
|---|---|---|
| State S[t] | one flow, 22 features | aggregate of G=4 consecutive flows of a session, 44 features |
| Window | 6 flows | 6 states (24 flows) |
| Training targets | next flow (state, infiltration); current flow (stage) | states t+1..t+4, risk t+1..t+4, stage t+1..t+4 |
| Rollout in training | none (one step) | recursive, scheduled teacher forcing (true state fed with probability 1.0 falling to 0 by 60% of epochs) |
| Rollout at inference | recursive, MC noise | recursive (`NetStateWorldModel.rollout`), free-running |

Code: `worldmodel_v2/` (`state_features.py`, `model.py`, `data.py`, `train.py`, `evaluate.py`), tests in `backend/tests/test_worldmodel_v2.py`.

Loss: transition MSE weighted 1.0/0.8/0.6/0.5 for steps 1-4, plus BCE on future risk (pos_weight from train), plus 0.5 x cross-entropy on future stage (class weights clipped at 6.0). The weights were chosen up front and not tuned.

## Network-state features

Built only from the 22 flow features present in both training data and live capture. Full definitions and availability are in `worldmodel_v2/state_features.py` (`FEATURE_DOC`).

- 21 window means, one per flow feature (`retransmit_cnt` dropped, it is 0 in every training row).
- 23 aggregates: total packets and bytes; std/max of duration and IAT; packet-size, TCP-window and ttl_variance std; six flag-to-packet ratios; four flag-in-flow fractions; forward/backward packet and byte ratios; fraction of flows with 2 or fewer packets; flow-shape diversity (distinct packet-count/length tuples divided by G, a proxy for traffic uniformity, not a port count).
- All values are log1p-compressed, then standardized with a scaler fit on training states only.

Requested but not buildable from this dataset, and therefore NOT implemented (no invented values): unique source/destination IPs and ports, internal host counts, TCP/UDP/ICMP ratios, inbound/outbound bytes, connection rate and new-connection rate (timestamps are synthetic), real TTL statistics, retransmission rate (constant 0), source/destination diversity. The CSVs have no IP, port, protocol or direction columns. Adding these requires a dataset or PCAP source that carries those fields.

## Data used

Same session-level split and seed as V1, so both models see identical test sessions. Sessions shorter than 10 states (40 flows) cannot form a 6-state window plus 4 future states and are excluded from V2: 260 of 478 test sessions remain. Lateral Movement and Exfiltration live almost entirely in short sessions, so V2 has 24 Lateral Movement training windows and none for Exfiltration. V2 stage results therefore cover Benign, Reconnaissance, Initial Access and C2 only. No synthetic augmentation is used.

Windows are chronological within a session, targets are strictly later than inputs, and labels never enter features (unit-tested). The scaler is fit on train only. The split is by session, not by time, because CIC-IDS2017 timestamps are synthetic; a true chronological split is not possible with this data.

## Results (test split, single seed)

Run 1 overfit (validation loss rose after epoch ~24); it was caused by a trainer bug that restricted best-checkpoint selection to the last 40% of epochs. Run 2 selects on validation across all epochs. Both are kept in `experiments/` (`eval_v2_g4_run1_overfit.json`, `eval_v2_g4.json`). A G=8 sensitivity run (run 1 settings) was worse and is in `eval_v2_g8_run1_overfit.json`; it was not repeated.

### Early warning (lead in flows, 131 eligible test sessions)

The threshold for each model is chosen on validation as the smallest one keeping the alert rate on "quiet" windows (no attack within the window or the next horizon) at or under 5%. Test windows never influence it.

| | Warned before attack | Within 5 flows | Within 12 flows | Within 20 flows | Median lead |
|---|---|---|---|---|---|
| V1, fixed threshold 0.5 (earlier script, 134 sessions) | 23.9% | n/a | 3.7% | n/a | 70 |
| V1, same protocol as V2 | 54.2% | 9.2% | 18.3% | 27.5% | 97 |
| V2 | 70.2% | 36.6% | 38.2% | 41.2% | 24 |
| Logistic Regression on V2 states | 50.4% | 22.1% | 28.2% | 29.0% | 8 |

"Within N" means some window ending at most N flows before the first malicious flow alerted. Median lead is of the earliest alert; large values are largely early alerts that are indistinguishable from false alarms (see below).

### Transition error, scaled state space (V2 free-running rollout, all test windows)

| Step | V2 MSE | Persistence MSE | V2 MAE | Persistence MAE |
|---|---|---|---|---|
| +1 | 0.622 | 1.047 | 0.535 | 0.596 |
| +2 | 0.702 | 1.280 | 0.577 | 0.688 |
| +3 | 0.742 | 1.423 | 0.597 | 0.740 |
| +4 | 0.773 | 1.510 | 0.613 | 0.774 |

V2 beats persistence on both MSE and MAE at every horizon, and the error grows slowly with horizon. V1's MAE at step 1 did not beat persistence (0.264 vs 0.248), but the two are in different spaces (flow vs state) and are not directly comparable.

### Future risk and stage (de-duplicated windows)

| Step | Risk ROC-AUC | Risk PR-AUC | Stage macro-F1 | Stage persistence macro-F1 |
|---|---|---|---|---|
| +1 | 0.879 | 0.775 | 0.434 | 0.481 |
| +2 | 0.835 | 0.705 | 0.397 | 0.518 |
| +3 | 0.799 | 0.660 | 0.372 | 0.360 |
| +4 | 0.770 | 0.629 | 0.347 | 0.324 |

Risk degrades with horizon as expected. Stage forecasting is weak: it beats "the current stage continues" only at steps 3 and 4.

### Detection (does the next state contain malicious flows; threshold 0.5)

| | All windows F1 | De-duplicated F1 | De-duplicated ROC-AUC | De-duplicated FPR |
|---|---|---|---|---|
| V2 | 0.768 | 0.691 | 0.879 | 9.6% |
| Logistic Regression | 0.683 | 0.582 | 0.806 | 13.1% |
| "Label persists" | 0.800 | 0.726 | n/a | n/a |

V2 detection is worse than V1's flow-level F1 (0.838 de-duplicated). The tasks differ (a 4-flow window versus one flow), but V2 should not be presented as a detection improvement. Simply assuming the current state's label continues beats V2 at detection, which is why detection numbers on this data say little about forecasting.

### Data quality

11.6% of V2 test windows have a last input or first target state whose flows all appear in the training data (V1's flow-level overlap was 21.5%). Session-ID overlap between train and test is 0. The de-duplicated columns above are the headline.

## Conclusions and limitations

- The evidence that the architectural change helps is real but moderate: V2 warns before attack onset in 70% of eligible sessions versus 54% for V1 under an identical protocol, and warns within 12 flows in 38% versus 18%. The gap is larger than the sampling error at 131 sessions (about 4 percentage points), but it is one training seed.
- False alarms are not solved. With only 6 benign test sessions, both V1 and V2 raise at least one alert in every one of them at the 5% per-window budget. Because the alert rule is "any window fires", some of the "warned" sessions are early alarms indistinguishable from false ones. A lead-time claim needs a tighter alert rule (persistence or a sustained-score requirement) and a larger benign set.
- V2 overfits quickly: validation loss was best in the first few epochs and free-running state error barely improves with training. More regularisation or more diverse data is needed before trusting fine-grained numbers.
- V2 cannot forecast Lateral Movement or Exfiltration on this data, and its stage forecasts are weak.
- The requested network-level features (IPs, ports, protocols, direction, real rates) are not in the CIC-IDS2017/2018 CSVs. Until a dataset with them is used, V2's state is a window aggregate of flow statistics, not a full network state.
- Not verified: behaviour on live or PCAP traffic. The flow extractor now matches the training definitions (`docs/pcap_parity.md`), but V2 itself was never run on PCAP-derived flows.

## Reproduce

```
python -m worldmodel_v2.train --G 4 --epochs 30 --out backend/artifacts_v2
python -m worldmodel_v2.evaluate --v2 backend/artifacts_v2 --out experiments/eval_v2_g4.json
python -m pytest backend/tests/test_worldmodel_v2.py
```
