# Project Garud -- Setup & Retraining

**SIH 2026 PS:26153 (NTRO) | AI-Based Network Attack Forecasting**

---

## Quick Start -- One Command, Zero Setup

```powershell
python setup\run_all.py
```

That's it. No VMs. No Wireshark. No VirtualBox. No configuration.

---

## What `run_all.py` Does

| Step | What Happens |
|:---:|---|
| 1 | Auto-installs missing packages (torch, pandas, numpy) |
| 2 | Generates 80 attack + 120 benign sessions using 8 realistic campaign templates |
| 3 | Fine-tunes (or trains from scratch) the WorldModel |
| 4 | Saves updated artifacts to `backend/artifacts/` with auto-backup |

### Campaign Templates Used

| Template | Kill Chain |
|---|---|
| APT Full Kill Chain | Benign > Recon > Access > Lateral > C2 > Exfil |
| Smash-and-Grab | Benign > Recon > Access > Exfil |
| Slow Recon + Lateral | Benign > Recon (long) > Access > Lateral (heavy) > C2 |
| C2 Persistent Backdoor | Benign > Recon > Access > C2 (long) > Exfil |
| Insider Lateral Movement | Benign > Lateral > C2 > Exfil |
| Reconnaissance Only | Benign > Recon > Benign (attacker backs off) |
| Ransomware Kill Chain | Benign > Recon > Access > Lateral > Exfil (mass) |
| Watering Hole + C2 | Benign > Access > C2 (long) > Lateral > Exfil |

---

## All Commands

```powershell
# Default: generate campaign data + fine-tune existing model
python setup\run_all.py

# Train from scratch instead of fine-tune
python setup\run_all.py --mode scratch

# Just generate dataset CSV, no training
python setup\run_all.py --mode generate-only

# More data (bigger dataset)
python setup\run_all.py --attack-sessions 150 --benign-sessions 200

# Combine with existing CIC-IDS base data
python setup\run_all.py --combine-base

# Fine-tune with frozen LSTM backbone (safest, head-only)
python setup\run_all.py --freeze-lstm

# Custom training params
python setup\run_all.py --epochs 30 --lr 5e-4 --patience 8

# Full custom run
python setup\run_all.py --mode scratch --attack-sessions 200 --benign-sessions 300 --epochs 30 --combine-base
```

---

## Fine-Tune vs Train From Scratch

### Use Fine-Tune (default) when:
- You have the existing trained model in `backend/artifacts/`
- Lab/campaign data is small (< 10K flows)
- You want to preserve existing detection quality (F1=0.862)

### Use From Scratch when:
- You have 20+ attack sessions (10K+ flows)
- You changed the feature set or architecture
- Fine-tuned model degraded on test set

| | Fine-Tune | From Scratch |
|---|---|---|
| **Existing F1=0.862** | Preserved | Risk of regression |
| **Data needed** | 2K-10K flows | 10K+ flows |
| **Training time** | ~5-10 min | ~20-40 min |
| **LR** | 1e-4 (auto) | 1e-3 |
| **Risk** | Low | Higher with small data |

---

## Files in This Folder

| File | Purpose |
|---|---|
| **`run_all.py`** | **THE ONE FILE** -- generates data + trains model, zero config |
| `lab_setup_and_retrain.ps1` | Full VM lab automation (if you want real traffic) |
| `finetune_model.py` | Standalone fine-tuning script |
| `train_from_scratch.py` | Standalone from-scratch wrapper |
| `merge_lab_flows.py` | Merge lab flows with CIC-IDS data |

---

## Expected Results

| Metric | Before | After Fine-Tune | After From-Scratch |
|---|:---:|:---:|:---:|
| Binary F1 | 0.862 | 0.85 - 0.88 | 0.80 - 0.87 |
| Early Warning Rate | 23.9% | 35 - 45% | 30 - 50% |
| Per-stage macro-F1 | 0.928 | 0.90 - 0.93 | 0.85 - 0.92 |
| FPR | 4.59% | 3 - 5% | 3 - 6% |

---

## After Training -- Next Steps

```powershell
# 1. Start the system
powershell -File .\start_all.ps1

# 2. Test with a sample
curl -X POST http://localhost:8000/ingest/pcap -F "file=@dataset\run_001\traffic.pcap"

# 3. Open dashboard
# http://localhost:3000
```

---

## Advanced: Full VM Lab (Optional)

If you want real captured traffic instead of simulated data:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\lab_setup_and_retrain.ps1
```

This sets up VirtualBox VMs (Kali + Metasploitable2), runs actual attacks, captures PCAPs, extracts flows, and retrains. Requires ~20GB disk and 30-60 minutes.
