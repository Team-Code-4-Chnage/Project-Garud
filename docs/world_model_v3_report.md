# World Model V3: Dataset Upgrade, Network State and Evaluation Report

Status: the network-state model described in section 15 is served by the backend next to the V1 flow model; the rest of this document is the research that led to it. The results are a mixed picture and do not support a claim that NetForecast is SIH-complete. Every number below was measured by code in this repository; raw outputs are in `experiments/v3_lodo.json`, `experiments/v3_behaviour.json`, and the aggregation is `experiments/summarize_v3.py`.

## 1. Candidate dataset comparison

"Verified" means I inspected the actual files or listings in this session. "Not verified" means the statement is from general knowledge of the dataset and was not checked here.

| Dataset | Obtainable here | IP / port / protocol | Timestamps | Packet-level features | Attack timeline | Benign volume | Attack variety | Verdict |
|---|---|---|---|---|---|---|---|---|
| CIC-IDS2017 labelled flows (`traffic_labels/` on the Hugging Face mirror `Ariasyah/cic-ids-2017`) | Yes, 8 day-files, about 300 MB, downloaded and parsed | Yes: Source/Destination IP, Source/Destination Port, Protocol (verified) | Yes, but minute resolution (seconds are 0 except Monday); no time zone marker (verified) | Only what CICFlowMeter derives (flags, IAT, header lengths, initial window). No TTL, no retransmissions (verified) | Each family in its own time block on a known day; no multi-stage campaign (verified) | About 2.27 M benign flows, 8 h Monday benign-only (verified) | 14 labels: scan, brute force, 4 DoS, DDoS, web attacks, bot, infiltration, Heartbleed (verified) | Selected |
| CIC-IDS2017 MachineLearningCSV (what V1/V2 used) | Yes | No: columns dropped (verified) | No | Same features | No | Same | Same | Insufficient for network state |
| UNSW-NB15 (Hugging Face partitioned "training-set") | Yes for the partitioned CSV | No: `srcip`, `sport`, `dstip`, `dsport` are absent from the partitioned file (verified header). The 4 raw CSVs upstream do have them (not verified here, not on the mirror I checked) | Not in the partitioned file | Has `sttl`, `dttl`, `sloss`, `dloss`, `swin` | No timeline in the partitioned file | Moderate | 9 attack categories | Different feature space; usable as an external test only after a feature mapping, and not without IPs/timestamps for network state |
| CIC-DDoS2019 (mirror `bencorn/CICDDoS2019`) | Yes, CSV zips of 2.3 GB and 0.9 GB (verified listing) | Flow files include IPs and ports (not verified here) | Yes (not verified) | Same CICFlowMeter features | DDoS families on two days | Little benign traffic (not verified) | DDoS reflection/amplification only | Same tool family and only one attack theme; no help for multi-behaviour forecasting |
| CTU-13 | Official site failed the SSL certificate check from this machine (verified); not downloaded | NetFlow-style: IPs, ports, protocol (not verified) | Yes | No packet-level TCP flag detail (not verified) | One infected host per scenario, so a real infection timeline (not verified) | Background traffic present | Botnet only (C2, scanning, DDoS, spam) | The best fit for a true campaign timeline; deferred because it was not retrievable here |

Evaluation against the eight criteria you listed (temporal ordering, network aggregation, IP/port/protocol, packet-level features, attack timelines, benign traffic, multiple behaviours, generalization experiments): the CIC-IDS2017 labelled flows satisfy all except packet-level (partial: no TTL or retransmissions) and campaign timelines (none of the CIC datasets has one).

## 2. Recommended dataset and justification

CIC-IDS2017 labelled flows. They are the same flows and the same 22-feature definitions the shipped model was trained on, so results are comparable in kind; they add exactly the missing network context; and they contain a full benign Monday plus benign traffic on every attack day, which fixes the six-benign-session problem. Real timestamps let false alarms be counted per hour and lead time in minutes.

Limits stated up front:
- The data does not contain campaigns. Every attack occupies its own block: FTP/SSH-Patator on Tuesday, DoS and Heartbleed on Wednesday, web attacks and infiltration on Thursday, bot, port scan and DDoS on Friday. Attackers are essentially one address (172.16.0.1 behind NAT) against one victim (192.168.10.50). There is no Recon-to-Exfiltration chain, so campaign or kill-chain progression cannot be evaluated here.
- Some families are tiny: Infiltration 36 flows, SQL injection 21, Heartbleed 11.
- Because one attacker address dominates, raw IP identity would be a shortcut. The features contain only counts, entropies and ratios, never IP values.
- CIC-IDS2017 has documented labelling and flow-termination problems in the literature. I did not audit them, and the labels are used as given.
- 288,602 rows in the Thursday-morning file are blank padding (null timestamps, no fields). They were dropped and are not attack or benign data.

## 3. Exact missing fields

| Requested field | Status in the selected dataset |
|---|---|
| timestamp | Present, minute resolution |
| source / destination IP, ports, protocol | Present |
| direction | Derived: internal = 192.168.0.0/16, so inbound / outbound / internal |
| bytes, packets, duration, flags, IAT, TCP window | Present (CICFlowMeter) |
| TTL | Missing |
| retransmissions | Missing |
| sub-minute timing | Missing (seconds are 0) |
| attack timeline / stage | Only attack-type blocks by day; no stage or campaign labels |

## 4. Network-state schema

One state per minute, network-wide. All columns are computed by `data/build_network_windows.py`. Aggregation window is one minute of flow start times. Every column is available in training. Inference availability is "yes" if the same fields exist in the live pipeline (`capture/flow_state.py` produces IPs, ports, protocol, flags and timing) The flow extractor now reproduces CICFlowMeter's definitions (docs/pcap_parity.md), but the V3 network-state builder itself has not been run on live or PCAP input.

| Feature | Formula | Source fields |
|---|---|---|
| n_flows | count of flows | rows |
| f_total_packets, f_total_bytes | sum of (fwd+bwd) packets; sum of total length fwd+bwd | packet counts, lengths |
| f_dur_mean / std / max | mean, std, max of Flow Duration | Flow Duration |
| f_iat_mean / max / mean_std, f_iat_std_mean | mean, max, std of Flow IAT Mean; mean of Flow IAT Std | Flow IAT |
| f_pps_mean, f_bps_mean | mean of Flow Packets/s and Flow Bytes/s | rate columns |
| f_pkt_size_mean / std, f_down_up_mean | mean, std of Average Packet Size; mean Down/Up Ratio | size, ratio |
| f_tcp_win_mean / std | mean, std of Init_Win_bytes_forward | window |
| f_{syn,ack,fin,rst,psh,urg}_ratio | sum of flag count / total packets | flag counts |
| f_{synf,rstf,small}_flow_frac | fraction of flows with SYN>0, RST>0, packets<=2 | flags, packets |
| n_uniq_src_ip, n_uniq_dst_ip | distinct source / destination IPs | IPs |
| n_uniq_src_port, n_uniq_dst_port | distinct ports | ports |
| n_uniq_pairs | distinct (src, dst) IP pairs | IPs |
| n_uniq_internal_src / _dst | distinct 192.168.x.x sources / destinations | IPs |
| n_{tcp,udp,icmp,other_proto}_ratio | share of flows by protocol number (6, 17, 1, other) | Protocol |
| n_{inb,outb,intl}_flow_ratio | share of inbound, outbound, internal flows | IPs |
| n_inbound_bytes, n_outbound_bytes, n_in_out_byte_ratio | bytes by direction; inbound / (outbound + 1) | IPs, bytes |
| n_conn_rate | flows / 60 s (minute-resolution window) | count |
| n_new_conn_rate | flows with SYN>0 / 60 s | SYN, count |
| n_ent_dst_port, n_ent_src_ip, n_ent_dst_ip | Shannon entropy (bits) of the distribution | ports, IPs |
| n_top_src_share | flows of the busiest source / total | IPs |
| n_dst_port_diversity | distinct destination ports / flows | ports |
| n_dport_per_src_mean / max | per source, distinct destination ports; mean and max | IPs, ports |
| n_dst_per_src_mean / max | per source, distinct destination hosts; mean and max | IPs |

Not built (dataset lacks the input): TTL statistics, retransmission rate, sub-minute connection rates. Values are log1p-compressed and standardized on the training days of each fold only.

Two feature sets are compared with the identical model and protocol: "flow" (the 25 `f_*` columns, flow statistics per minute with no network context) and "net" (54 features, adds the `n_*` columns).

## 5. Sustained-alert design

Score = maximum predicted risk over the next 4 minutes. An alert is active when the score is at or above a threshold for N consecutive windows. For every fold the threshold and N (N in 1 to 5, thresholds from the 50th to 99.9th percentile of validation scores) are chosen on the validation day only: maximize the share of validation episodes warned within 20 minutes subject to at most 1 false-alarm event per quiet hour. The pair is then frozen and applied to the test day. Test data never influences it.

## 6. Benign-data strategy

Leave-one-day-out evaluation pools four held-out attack days. Test population measured: 1,447 benign windows (about 24 hours), 520 attack windows, 946 quiet windows (about 15.8 hours; a quiet window has no attack in it or in the following 20 minutes), 10 fully quiet 60-minute blocks, 20 attack episodes. Monday (benign only, 487 windows) is always in training and is not used as a test population; holding it out is a further improvement not done here. This is roughly 8 times the benign exposure of the earlier six-session evaluation, but 10 quiet hour-blocks is still small.

## 7. Multi-seed design

Seeds 42, 123, 456, 789, 2026; each seed trains a fresh model for each of 4 folds and 2 feature sets. Reported as mean +/- std [min, max] over seeds. The data split is fixed (chronological by day), so seeds capture training variance only, not data-sampling variance.

## 8. Attack-family holdout design

Leave-one-day-out. For a held-out day D the validation day is the next attack day (cyclic) and the training days are the rest plus Monday, so every family on D is unseen. Related families exist across days (Wednesday DoS versus Friday DDoS; Tuesday Patator versus Thursday web brute force), so it is a family holdout with some related-family leakage, not a strict zero-knowledge test. No claim of zero-day detection is made. No external-dataset test was run: UNSW-NB15 lacks network context in the retrievable copy, CTU-13 could not be fetched, and CIC-DDoS2019 was not downloaded.

## 9. Stage/behaviour forecasting design

The dataset has no stage or campaign labels, so MITRE stages cannot be forecast; only attack behaviour classes (Benign, PortScan, BruteForce, DoS, DDoS, WebAttack, Bot, Infiltration, Heartbleed) exist. Under leave-one-day-out the held-out day's behaviours are never in training by construction, so behaviour forecasting uses a second protocol: chronological within each day (first 60% train, next 15% validation, last 25% test, windows fully inside one segment). Baseline is persistence (predicted behaviour at t+k equals the behaviour now).

## 10. MITRE mapping design

Separate from model evaluation. `backend/app/mitre.py` interprets a behaviour class (or a legacy V1 stage) into technique and tactic with a description, rationale, confidence and an ambiguity flag; it is exposed at `GET /mitre/mapping` and `GET /mitre/lookup/{label}`. Rules enforced by tests: DoS and DDoS map to Impact, not Command and Control; brute force maps to Credential Access, not Reconnaissance; legacy stage labels that mix behaviours are flagged ambiguous. The dashboard reads the mapping from the API and no longer contains hard-coded technique IDs. The entries are the author's analytic judgement, not model output, and the technique IDs should be checked against the current ATT&CK release.

## 11. Results

Test population: 4 held-out days, 20 attack episodes. Episode = a run of attack minutes preceded by at least 6 attack-free minutes. Lead times are in real minutes.

### Early warning and false alarms (5 seeds, mean +/- std [min, max])

| Metric | flow features (25) | net features (54) |
|---|---|---|
| Warned within 20 min before onset | 0.35 +/- 0.10 [0.25, 0.50] | 0.43 +/- 0.10 [0.30, 0.55] |
| Within 5 min | 0.29 +/- 0.06 [0.25, 0.40] | 0.24 +/- 0.08 [0.10, 0.30] |
| Within 10 min | 0.30 +/- 0.06 [0.25, 0.40] | 0.35 +/- 0.09 [0.25, 0.45] |
| Within 12 min | 0.32 +/- 0.08 [0.25, 0.45] | 0.35 +/- 0.09 [0.25, 0.45] |
| Median lead of warned episodes (min) | 11.1 +/- 2.3 | 15.6 +/- 2.1 |
| False alarm events per quiet hour | 0.47 +/- 0.25 [0.13, 0.89] | 1.13 +/- 0.27 [0.83, 1.59] |
| Alert rate on quiet windows | 3.8% | 11.5% |
| Quiet 60-min blocks containing a false alarm | 32% (of 10) | 76% (of 10) |

With 20 episodes, one episode is 5 percentage points; the 95% interval on the flow-set mean (7.0 of 20 warned) is 0.18 to 0.57 and on the net-set mean (8.6 of 20) is 0.24 to 0.64. The two feature sets are not distinguishable on early warning: the seed ranges overlap. Adding network context raised the false-alarm rate to above the 1 per hour validation budget on test (1.13 per hour) and 76% of quiet hours had at least one false alarm. Logistic Regression on the same states warned 40% (flow) and 25% (net) within 20 minutes at 1.14 false alarms per hour.

A persistence baseline cannot warn: it only repeats the current label, so on a quiet window it predicts quiet.

### Detection (next-minute window contains an attack; unseen families; threshold 0.5)

| Metric | flow | net | Logistic Regression (flow / net) | Persistence of current label |
|---|---|---|---|---|
| F1 | 0.26 +/- 0.06 | 0.48 +/- 0.04 | 0.23 / 0.39 | 0.84 |
| Precision | 0.31 | 0.57 | | |
| Recall | 0.24 | 0.42 | | |
| FPR | 0.20 | 0.12 | | |
| ROC-AUC | 0.54 +/- 0.04 | 0.62 +/- 0.02 | 0.48 / 0.60 | |
| PR-AUC | 0.33 | 0.50 | | |

On unseen attack families, detection is weak. The flow-only model is close to chance (ROC-AUC 0.54). The 54-feature network set scores higher (F1 0.26 to 0.48, ROC-AUC 0.54 to 0.62), but section 14 shows most of that gain comes from direction features that encode the testbed layout (attacks come from outside the firewall); without them F1 is 0.30 and ROC-AUC 0.56. Persistence beats both because attacks last many minutes; that says persistence is a strong baseline, not that either model is good. Do not compare these numbers to the 0.86 F1 of V1, which was measured on held-out sessions from the same days with the attack families in training.

### Future-state transition error (scaled space, pooled over 4 held-out days)

| Horizon | flow: model MSE / persistence MSE | net: model MSE / persistence MSE | net MAE / persistence MAE |
|---|---|---|---|
| +1 min | 1.058 / 1.369 | 0.955 / 1.197 | 0.611 / 0.690 |
| +2 min | 1.070 / 1.472 | 0.979 / 1.286 | 0.618 / 0.706 |
| +3 min | 1.166 / 1.630 | 1.050 / 1.399 | 0.630 / 0.733 |
| +4 min | 1.229 / 1.596 | 1.108 / 1.385 | 0.643 / 0.715 |

The model beats persistence on MSE and MAE at every horizon for both feature sets, and the gap holds on unseen days. MSE is above 0.95 in standardized units, so absolute state prediction is imprecise: one-minute network state on an unseen day is only moderately predictable. Errors of the two feature sets are in different spaces and are not comparable to each other.

### Behaviour forecasting (chronological within-day split; 5 seeds)

Persistence wins at every horizon and the model shows no skill.

| | Model | Persistence |
|---|---|---|
| Accuracy at +1 (flow / net) | 0.39 / 0.70 | 0.89 |
| Macro-F1 over classes with at least 30 training windows (Benign, BruteForce), +1 | 0.23 / 0.40 | 0.94 |
| Macro-F1 over all classes present in the test targets, +1 | 0.08 / 0.13 | 0.59 |

Cause: the late-in-day test segments contain families with almost no training support (PortScan 2 windows, DDoS 0, Infiltration 0, Heartbleed 0), and the model never predicted BruteForce correctly. Some seeds collapsed to a single predicted class. There is no defensible behaviour or stage forecast from this data and none is claimed. The insufficient classes were not artificially balanced.

### Comparison summary (kept separate, no overall score)

| Question | Result |
|---|---|
| Detection on unseen families | Near chance for every feature set once the direction artefact is removed (ROC-AUC 0.54 to 0.56); the 0.62 of the full network set is mostly that artefact (section 14) |
| Transition modelling | Model beats persistence on all horizons |
| Early warning | About 35% to 43% of 20 episodes within 20 minutes; feature sets indistinguishable |
| False alarms | Flow 0.5 per quiet hour, net 1.1 per quiet hour; net set alarms in about three quarters of quiet hours |
| Behaviour / stage forecasting | No skill over persistence |
| V1 and V2 on the old data | Not comparable (different data, unit and protocol); their earlier numbers stand only as reported in their own documents |

## 12. Unverified and not done

- Behaviour of V3 on live or PCAP traffic: the flow extractor now matches CICFlowMeter (docs/pcap_parity.md), but the V3 network-state features were never built from live or PCAP input.
- External dataset test: not run.
- Attack-family holdout with the same-family generalization control (train and test on the same family, different time): not run.
- Holding out Monday as a benign-only test day: not run.
- The served model (section 15) was not evaluated on unseen attack families beyond the leave-one-day-out study of its feature set.
- One quirk to keep in mind: timestamps have no time zone marker and one-minute resolution, so lead times are accurate only to about a minute.

## 14. Direction-feature ablation

The CIC-IDS2017 testbed puts every attacker outside the firewall: 99.8% of malicious flows are inbound (external source, internal destination) against 16% of benign flows (counted over all labelled flows). Eight features depend on the internal/external split (`n_uniq_internal_src/dst`, `n_inb/outb/intl_flow_ratio`, `n_inbound/outbound_bytes`, `n_in_out_byte_ratio`) and one on single-host concentration (`n_top_src_share`; every attack comes from one address). They were removed ("net_nodir", 45 features) and the leave-one-day-out study re-run with the same 5 seeds (`experiments/v3_lodo_nodir.json`).

| Metric (mean over 5 seeds) | flow (25) | net_nodir (45) | net (54) |
|---|---|---|---|
| Detection F1, unseen days | 0.26 | 0.30 | 0.48 |
| Detection ROC-AUC | 0.54 | 0.56 | 0.62 |
| Warned within 20 min | 35% | 34% | 43% |
| Warned within 5 min | 29% | 17% | 24% |
| False alarms per quiet hour | 0.47 | 0.88 | 1.13 |
| Transition MSE +1 / persistence | 1.058 / 1.369 | 0.983 / 1.221 | 0.955 / 1.197 |

Reading: the improvement that the full network set appeared to give in detection and early warning is largely the direction artefact, which would not carry over to a network with a different layout (and the internal/external split is hard-coded to the testbed's 192.168.0.0/16). Without it, network context adds little over flow statistics on unseen attack families. The earlier statement in section 11 that network context "clearly helps" is withdrawn.

## 15. Served model

The backend serves one network-state model (`backend/artifacts_v3/`, trained by `worldmodel_v3/train_production.py`) through `GET /network/forecast` and the dashboard's NETWORK_FORECAST view. Choices:

- Feature set net_nodir (section 14): no dependence on the testbed address plan.
- Split: chronological within every capture day, 60% train, 15% validation, 25% test. The scaler, checkpoint and alert rule (threshold 0.518, 5 consecutive minutes, minimum 2, chosen on validation under a 0.5 false-alarm-per-quiet-hour budget) were frozen before the test segment was scored once. The saved weights are the tested ones. An earlier operating point (threshold 0.547, 1 consecutive minute, 1.0 budget) overshot to 1.38 false alarms per quiet hour on test; a more robust selection that maximises margin below budget and forbids single-minute alerts brought that to 0.41 with detection unchanged.
- The live state is computed by the same function as the training data (`worldmodel_v3/state.py`, verified to reproduce the committed windows exactly), from flows produced by the PCAP/live extractor, whose features match CICFlowMeter (`docs/pcap_parity.md`).

Test segment (570 windows, 63 with attacks; attack families seen in training, later in the same day):

| Metric | Value |
|---|---|
| Detection ROC-AUC / PR-AUC | 0.83 / 0.59 |
| Detection F1 / precision / recall / FPR | 0.52 / 0.41 / 0.70 / 12.4% |
| Transition MSE +1 / +2 / +3 / +4 (persistence) | 1.41 (1.42) / 1.40 (1.65) / 1.53 (1.80) / 1.67 (1.90) |
| Attack episodes in the test segments | 3; too few to estimate early warning |
| False alarms per quiet hour | 0.41 over 7.3 quiet hours (was 1.38 before operating-point tuning) |

At +1 minute the model's state prediction is no better than persistence; it is better at +2 to +4. The frozen alert rule now holds under its false-alarm budget on test (0.41 vs 0.5); the trade-off is that it needs 5 sustained minutes to confirm, so it alerts later. Three episodes are too few to estimate early warning. On unseen attack families the relevant numbers are the net_nodir column in section 14.

### End-to-end replay through the API (Friday DDoS)

`experiments/scenario_replay.py` pushed the 89,907 official flows of Friday 2017-07-07 18:35 to 19:05 UTC through `POST /ingest/csv` (one upload per minute, temporary database), then read `GET /network/forecast`. The flows use the training feature definitions, which the PCAP extractor reproduces (`docs/pcap_parity.md`); a raw capture of this window is several GB. DDoS appears only in Friday's test segment, so the served model never trained on DDoS (it did train on Wednesday's DoS).

| Minutes (UTC) | Traffic | Risk over next 4 min | Sustained alert |
|---|---|---|---|
| 18:35 to 18:39 | benign | not scored (fewer than 6 minutes) | no |
| 18:40 to 18:55 | benign, 103 to 1,386 flows/min | 0.24 to 0.49 (threshold 0.547) | no |
| 18:56 | DDoS starts, 2,438 of 3,671 flows | 0.29 | no |
| 18:57 to 19:04 | DDoS, about 6,500 attack flows/min | 0.70 to 0.86 | yes, every minute |

No false alarm in 16 scored benign minutes; alert one minute after onset; the forecast called the behaviour DoS (the closest trained family). There was no warning before onset: this replay shows fast detection of an unseen family, not early warning.

## 16. Reproduce

```
python data/fetch_cic2017_labelled.py --out data/cic2017_labelled
python data/build_network_windows.py --labels-dir data/cic2017_labelled     # needs pandas and pyarrow
python -m worldmodel_v3.run_lodo --out experiments/v3_lodo.json
python -m worldmodel_v3.run_behaviour --out experiments/v3_behaviour.json
python -m worldmodel_v3.run_lodo --feature-sets net_nodir --out experiments/v3_lodo_nodir.json
python experiments/summarize_v3.py
python -m worldmodel_v3.train_production --out backend/artifacts_v3
python experiments/scenario_replay.py export --labels <Friday DDoS and PortScan parquet files> --start "2017-07-07 18:35" --end "2017-07-07 19:05" --out fri.csv
python experiments/scenario_replay.py replay --csv fri.csv
python -m pytest backend/tests/test_worldmodel_v3.py backend/tests/test_mitre.py
```

`data/netwin_1min.csv.gz` (the built 1-minute windows) is committed so the experiments run without the 300 MB download.
