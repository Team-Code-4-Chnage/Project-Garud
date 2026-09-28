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
python setup\run_all.py --mode scratch           # train from scratch
python setup\run_all.py --mode generate-only     # just output CSV, no training
python setup\run_all.py --lab                    # real VirtualBox VMs
python setup\run_all.py --attack-sessions 200    # more attack data
python setup\run_all.py --combine-base           # merge with existing CIC-IDS
python setup\run_all.py --freeze-lstm            # safest fine-tune (head-only)
python setup\run_all.py --epochs 30 --lr 5e-4    # custom training params
```

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
