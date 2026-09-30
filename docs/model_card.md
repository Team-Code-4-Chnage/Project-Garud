# Model Card

Project Garud ships two models. This card lists what each was trained on, what was measured, and how to repeat each measurement. All figures below were produced by the scripts in this repository on 2026-09-30 unless a source is named.

## 1. Which model is used where

| Model | Artifacts | Used by |
| --- | --- | --- |
| Per-flow model | `backend/artifacts/` (`world_model.pt`, `scaler.pkl`, `config.json`) | `/predict`, `/forecast`, `/explain`, session scoring and alerts during ingestion |
| Network-state model | `backend/artifacts_v3/` (`network_world_model.pt`, `config.json`) | `/network/forecast`, the network forecast view, and the offline analysis forecast |
| Flow classifier | `backend/artifacts_flow/` (`flow_classifier.joblib`, `config.json`) | offline analysis: per-flow attack probability and behaviour, predicted labels |

## 2. Per-flow model

### Definition

- Input: 6 consecutive flows of one session, 22 CICFlowMeter-style features (order in `backend/app/config.py`), standardised with `scaler.pkl`.
- Architecture: 2-layer LSTM, hidden size 256, dropout 0.25; heads for next-flow features, malicious probability, and 6 stage classes (Benign, Reconnaissance, Initial Access, Lateral Movement, C2, Exfiltration). A per-class logit bias in `config.json` is applied to the stage logits.
- Recorded provenance in `config.json`: trained by `setup/run_all.py`, mode `scratch`, on `campaign_dataset.csv`, 60 epochs, 80 attack sessions and 120 benign sessions, timestamp 2026-09-29.

### Training data

`campaign_dataset.csv` (5,785 flows, 200 sessions) is synthetic. `setup/run_all.py` draws each flow from a normal distribution whose mean and standard deviation are hand-written per stage (`PROFILES_MEAN`, `PROFILES_STD`), and chains stages into sessions. It contains no captured traffic. The profiles are described in the code as CIC-IDS-calibrated; that calibration was not verified.

### Measured results

The same evaluation script (`experiments/evaluate_model.py`, seed 42, session-level split, threshold 0.5) was run on two data sets.

| | Synthetic `campaign_dataset.csv` | Real CIC-IDS2017 flows (`real_flows.csv`) |
| --- | --- | --- |
| Test sessions / windows | 40 / 1,016 (301 positive) | 477 / 61,776 (15,104 positive) |
| ROC-AUC | 0.995 | 0.532 |
| PR-AUC | 0.992 | 0.275 |
| Precision / recall | 0.997 / 0.980 | 0.259 / 0.922 |
| F1 | 0.988 | 0.404 |
| False-positive rate | 0.001 | 0.854 |
| Sessions warned before the first malicious flow | 0 of 6 | 134 of 134, but 1 of 134 within 12 flows of onset; 93% of windows of all-benign sessions alert |

Reading: the model separates its own synthetic classes almost perfectly. On real traffic its ROC-AUC is 0.53, which is chance level, and it flags 85% of benign windows. It should not be presented as a detector of real attacks. The next-state error on real data is in the millions in standardised units because the scaler was fitted on synthetic values; those numbers carry no meaning.

Test suite: `backend/tests/test_model_quality.py` (marked `requires_model`) checks the model on real CIC-IDS2017 sessions. 10 of its 41 tests fail against the current weights.

### History

Until 2026-09-27 the repository held a per-flow model trained on real CIC-IDS2017/2018 flows (last such commit: `af09eee`). It was replaced on 2026-09-28 by a fine-tune on the synthetic set and on 2026-09-29 by the current from-scratch synthetic training. Measured on the same real-data split as above, for that earlier model: ROC-AUC 0.955, F1 0.861, false-positive rate 0.046.

## 3. Network-state model

### Definition

- Input: 6 one-minute network-wide state vectors, 45 features (feature set `net_nodir`; list in `backend/artifacts_v3/config.json`). Features are counts, entropies, ratios and rates. No IP address is an input, and the direction-dependent features were removed after the ablation in section 14 of the V3 report.
- Architecture: 2-layer LSTM, hidden size 128, dropout 0.3, rolled out for 4 minutes; outputs future state, risk and a behaviour class (Benign, PortScan, BruteForce, DoS, DDoS, WebAttack, Bot, Infiltration, Heartbleed).
- Alert rule stored with the model: maximum predicted risk over the next 4 minutes at or above 0.518 for 5 consecutive minutes, chosen on validation segments with a budget of 0.5 false-alarm events per quiet hour.

### Training data

`data/netwin_1min.csv.gz`: one-minute windows built from the CIC-IDS2017 labelled flow files (five capture days, real timestamps at minute resolution). Split chronologically inside each day: first 60% train, next 15% validation, last 25% test.

### Measured results

Held-out segments (last 25% of each day), produced by `python -m worldmodel_v3.train_production`; seed 42. Attack families in these segments also occur in the training segments.

| Metric | Value |
| --- | --- |
| Test windows / windows with an attack | 570 / 63 |
| Detection (risk of next minute at 0.5): ROC-AUC / PR-AUC | 0.835 / 0.589 |
| Precision / recall / F1 / false-positive rate | 0.411 / 0.698 / 0.518 / 0.124 |
| Transition MSE at +1, +2, +3, +4 min (persistence in brackets) | 1.41 (1.42), 1.40 (1.65), 1.53 (1.80), 1.67 (1.90) |
| Attack episodes / warned within 20 min under the alert rule | 3 / 0 |
| False-alarm events / quiet hours | 3 / 7.27 (0.41 per quiet hour) |

Three episodes are too few to estimate early-warning skill; the result is reported, not interpreted.

Unseen attack days (leave-one-day-out, 5 seeds, feature set `net_nodir`; `python experiments/summarize_v3.py`, raw data in `experiments/v3_lodo_nodir.json`, discussion in [world_model_v3_report.md](world_model_v3_report.md)):

| Metric | Value (mean over seeds) |
| --- | --- |
| Detection F1 / ROC-AUC | 0.30 / 0.56 |
| Detection precision / recall / false-positive rate | 0.37 / 0.26 / 0.16 |
| Episodes warned within 20 minutes (20 episodes) | 34% |
| Median lead time of warned episodes | 14.8 min |
| False-alarm events per quiet hour | 0.88 |
| Transition MSE at +1 min vs persistence | 0.98 vs 1.22 |
| Logistic regression on the same states: detection F1 / ROC-AUC | 0.22 / 0.48 |
| Persistence of the current label: detection F1 | 0.84 |

Behaviour and stage forecasting: no skill over persistence at any horizon (report, section 11). No attack progression (Reconnaissance to Exfiltration) can be evaluated because CIC-IDS2017 contains no multi-stage campaign.

An end-to-end replay of one day through the API is described in the V3 report (section 15): no false alarm in 16 scored benign minutes, alert one minute after DDoS onset, no warning before onset.

### Correction recorded

Earlier versions of `backend/artifacts_v3/config.json` and of the dashboard's result panel showed a detection F1 of 0.86, ROC-AUC 0.885, three of three episodes warned and a table of baseline models. Re-running the training script with the committed weights and seed did not reproduce those values; the weights were identical and the measured values are those in the table above. The config now holds the measured values and the panel reads them from the config. The report [world_model_v3_report.md](world_model_v3_report.md) already contained the measured values.

## 4. Flow classifier

### Definition

`HistGradientBoostingClassifier` (400 iterations, learning rate 0.06, 127 leaves, L2 1.0; chosen among four configurations on validation segments) over the 22 features of one flow, nine classes (Benign, PortScan, BruteForce, DoS, DDoS, WebAttack, Bot, Infiltration, Heartbleed). Attack probability = 1 - P(Benign); flows at 0.5 or above are flagged. Class shares in training are restored by sample weights after capping each class at 120,000 rows, with a mild boost for rare attack classes. No session, address or time input.

### Training data and split

CIC-IDS2017 labelled flows with timestamps (`python data/fetch_cic2017_labelled.py`), converted by the same `flow_schema.adapt_frame` that serves uploads. The split is the network-state model's: per capture day the minutes are cut at 60% and 75% of the day's minute grid. Before 60%: fit. 60-75%: choose the configuration. After 75%: test, used for nothing else. The served model is refit on everything before the 75% cut (2,036,519 flows, 408,428 attacks). Rows whose label could not be interpreted (288,602 blank rows of the Thursday-morning file) are dropped.

### Measured results (held-out last 25% of every day, 794,224 flows, 149,218 attacks)

| Metric | Value |
| --- | --- |
| ROC-AUC / PR-AUC | 0.920 / 0.805 |
| Precision / recall / F1 at 0.5 | 0.800 / 0.672 / 0.731 |
| False-positive rate | 3.9% |
| At 0.8: precision / recall / false-positive rate | 0.964 / 0.290 / 0.25% |

| Family in the held-out segments | Flows | Detected | Named correctly | Rows of the family in training |
| --- | --- | --- | --- | --- |
| PortScan | 20,065 | 99.7% | 99.5% | 138,865 |
| BruteForce (SSH-Patator) | 1,097 | 95.9% | 95.8% | 12,738 (FTP- and SSH-Patator) |
| DDoS | 128,027 | 61.9% | 0% | 0 |
| Infiltration | 18 | 0% | 0% | 18 |
| Heartbleed | 11 | 0% | 0% | 0 |

Reading: families that were trained on are found with high accuracy; a family absent from training (DDoS) is found in about 62% of flows because it resembles DoS, but it is not named correctly; families with almost no examples are not found. The false-positive rate on the held-out segments is 3.9% at 0.5; the validation-optimal threshold (0.05) gave 6.1% there, so 0.5 was fixed beforehand as the natural boundary of the prior-restored probabilities.

### Other checks

| Data | Result |
| --- | --- |
| `data/samples/cic2017_tuesday_ssh_patator_heldout.csv.gz` (held out) | recall 0.959, precision 0.862, false-positive rate 0.35%, ROC-AUC 0.996 |
| CSE-CIC-IDS2018 infiltration sample (different year and environment) | ROC-AUC 0.445; not separable with these 22 features |


## 5. Offline analysis of a file

The Offline Analysis page and `POST /offline/analyze` apply the flow classifier to every flow and the network-state model to the file's own minute timeline (split at silences over an hour), and show the network model's output without the rules of the live forecast. When the file has labels, the report measures both models on it:

- flow level: precision, recall, false-positive rate, ROC-AUC per attack family;
- forecast back-test: every forecast issued inside the period (each window's risk for t+1..t+4) is compared with whether that minute really contained attack flows; ROC-AUC per horizon, the model's alert rule (risk at or above 0.518 for 5 minutes) for early warning and false alarms, and next-minute behaviour accuracy;
- state prediction: the model's mean squared error for the next four network states against repeating the last minute.

On the held-out Tuesday sample (61 minutes, 13 attack minutes) the forecast back-test gives ROC-AUC 0.63 to 0.64 for t+1..t+4 and the state prediction is better than repeating the last minute at every horizon (0.60 to 0.69 against 0.86 to 1.28). With 13 attack minutes and one episode these are indications, not estimates. Files without labels get predicted labels only.

## 6. Rules that shape what the dashboard shows

The values on the dashboard are not raw model output. Both paths add hand-written rules (plausibility rules for the per-flow path; rule-based threat scores, stage constants and projection rules for the network path). They are listed in [ARCHITECTURE.md](../ARCHITECTURE.md). They were not evaluated separately, so no accuracy claim is made for the combined system.

## 7. Intended use and limits

Intended use: research demonstration of flow-based monitoring, network-state forecasting and analyst tooling.

Not supported by the evidence in this repository:

- Detecting attacks on real traffic with the per-flow LSTM.
- Detecting attack families that are not in the training data of the flow classifier.
- Forecasting attack stages or kill-chain progression.
- Detecting attack families absent from training with usable accuracy.
- Performance on captures produced by the live extractor: the network-state features were validated on the CIC windows and on a replay of CIC flows, not on live captures.

## 8. Reproduce

```bash
# network-state model: retrain into a scratch directory and compare test_results in config.json
python -m worldmodel_v3.train_production --out /tmp/v3_check

# unseen-day study summary from the recorded runs
python experiments/summarize_v3.py

# per-flow model on real flows (needs real_flows.csv, built by data/preprocess_cicids.py)
python experiments/evaluate_model.py

# per-flow model on the synthetic set: run evaluate_model.py with real_flows.csv
# replaced by campaign_dataset.csv in the read_csv call

# flow classifier (needs data/cic2017_labelled from data/fetch_cic2017_labelled.py)
python -m flowclf.train

# offline analysis on the bundled real-data files
cd backend && python -m pytest tests/test_upload_formats.py

# model quality tests
cd backend && python -m pytest tests -m requires_model
```
