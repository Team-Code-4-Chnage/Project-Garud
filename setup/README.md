# Project Garud -- Setup

**SIH 2026 PS:26153 (NTRO) | AI-Based Network Attack Forecasting**

## One File. Zero Config. Just Run:

```
python setup\run_all.py
```

## What It Does (10 Phases)

| Phase | Name | What Happens |
|:---:|---|---|
| 0 | Prerequisites | Auto-installs torch, pandas, numpy, etc. |
| 1 | Network | Sets up VirtualBox host-only network (or simulated) |
| 2 | VMs | Downloads/imports Kali + Metasploitable (or simulated) |
| 3 | Config | Configures VM networking, SSH, snapshots |
| 4 | Validation | Dry-run + connectivity checks |
| 5 | Collection | Generates 80 attack + 120 benign campaign sessions |
| 6 | Extraction | Extracts 22 CIC-IDS flow features per flow |
| 7 | Merging | Combines campaign + base CIC-IDS data |
| 8 | Training | Fine-tunes or trains WorldModel from scratch |
| 9 | Calibration | Stage logit bias calibration |
| 10 | Verification | Saves artifacts, runs tests |

## All Commands

```
python setup\run_all.py                         # default: simulate + fine-tune
python setup\run_all.py --data my_dataset.csv   # retrain directly on your dataset!
python setup\run_all.py --data my_dataset.csv --mode finetune  # fine-tune existing model
python setup\run_all.py --data my_dataset.csv --mode scratch   # train brand new model from scratch
python setup\run_all.py --mode scratch           # generate data + train from scratch
python setup\run_all.py --mode generate-only     # just output CSV, no training
python setup\run_all.py --lab                    # real VirtualBox VMs
python setup\run_all.py --attack-sessions 200    # more attack data
python setup\run_all.py --combine-base           # merge with existing CIC-IDS
python setup\run_all.py --freeze-lstm            # safest fine-tune (head-only)
python setup\run_all.py --epochs 30 --lr 5e-4    # custom training params
```

## How to Provide Your Own Dataset

You can pass any custom CSV dataset using `--data`:

```powershell
python setup\run_all.py --data "path\to\your_dataset.csv"
```

Or using `pipeline_fixed.py`:
```powershell
python pipeline_fixed.py --data "path\to\your_dataset.csv" --out backend\artifacts
```

### Required Dataset Columns:
1. **Metadata columns**:
   - `session_id`: Unique integer/string grouping sequential flows into an attack session
   - `timestamp`: Date/time or chronological timestamp to order flows
   - `stage_label`: One of `Benign`, `Reconnaissance`, `Initial Access`, `Lateral Movement`, `C2`, `Exfiltration`
   - `is_malicious`: `0` for Benign, `1` for malicious (auto-calculated if omitted)
2. **22 CIC-IDS Flow Feature columns**:
   `flow_duration`, `tot_fwd_pkts`, `tot_bwd_pkts`, `fwd_pkt_len_mean`, `bwd_pkt_len_mean`, `flow_bytes_s`, `flow_pkts_s`, `flow_iat_mean`, `flow_iat_std`, `fwd_iat_mean`, `bwd_iat_mean`, `syn_flag_cnt`, `ack_flag_cnt`, `fin_flag_cnt`, `rst_flag_cnt`, `psh_flag_cnt`, `urg_flag_cnt`, `down_up_ratio`, `pkt_size_avg`, `ttl_variance`, `tcp_win_size`, `retransmit_cnt`

## 8 Campaign Templates

| Template | Kill Chain |
|---|---|
| APT Full Kill Chain | Benign > Recon > Access > Lateral > C2 > Exfil |
| Smash-and-Grab | Benign > Recon > Access > Exfil |
| Slow Recon + Lateral | Benign > Recon (long) > Access > Lateral (heavy) > C2 |
| C2 Persistent Backdoor | Benign > Recon > Access > C2 (long) > Exfil |
| Insider Lateral | Benign > Lateral > C2 > Exfil |
| Recon-Only Probe | Benign > Recon > Benign (attacker backs off) |
| Ransomware | Benign > Recon > Access > Lateral > Exfil (mass) |
| Watering Hole + C2 | Benign > Access > C2 (long) > Lateral > Exfil |

## After Training

```
powershell -File .\start_all.ps1
```
