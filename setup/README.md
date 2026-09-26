# Project Garud — Setup: Lab Harness + Model Retraining

**SIH 2026 PS:26153 (NTRO) • AI-Based Network Attack Forecasting**

This folder contains everything needed to collect real multi-stage attack
campaign data in an isolated VirtualBox lab and retrain the WorldModel.

---

## 📁 Files in This Folder

| File | Purpose |
|---|---|
| `lab_setup_and_retrain.ps1` | **Master script** — Fully automated Windows PowerShell pipeline (Phases 0-10) |
| `finetune_model.py` | Fine-tune existing model on combined CIC-IDS + lab data (recommended) |
| `train_from_scratch.py` | Train a new model from scratch on combined data |
| `merge_lab_flows.py` | Merge lab campaign `flows.csv` files with CIC-IDS `real_flows.csv` |
| `README.md` | This file |

---

## 🤔 Fine-Tune vs. Train From Scratch?

### ✅ RECOMMENDED: Fine-Tune (default)

```powershell
python setup\finetune_model.py --data combined_flows.csv
```

**Why fine-tune is better for your case:**

| Factor | Fine-Tune | From Scratch |
|---|---|---|
| **Existing detection quality** | Preserved (F1=0.862) | Risk of regression |
| **Lab data size** | Works with 2K-10K flows | Needs 10K+ flows minimum |
| **Training time** | ~5-10 min (10 epochs) | ~20-40 min (25 epochs) |
| **What it learns** | Campaign transitions | Everything from zero |
| **Risk** | Low — worst case matches original | High — may overfit to small lab data |
| **SIH demo value** | Shows transfer learning sophistication | Shows data-centric ML |

**Three fine-tuning modes:**

```powershell
# Mode 1: Full fine-tune (recommended) — all weights updated with low LR
python setup\finetune_model.py --data combined_flows.csv --lr 1e-4 --epochs 10

# Mode 2: Head-only (safest) — LSTM frozen, only risk+stage heads retrained
python setup\finetune_model.py --data combined_flows.csv --freeze-lstm --epochs 15

# Mode 3: Aggressive (if 20+ lab runs) — higher LR, refit scaler
python setup\finetune_model.py --data combined_flows.csv --lr 5e-4 --epochs 20 --refit-scaler
```

### 🔄 When to Train From Scratch Instead

Use `train_from_scratch.py` only if:
- You collected **20+ lab runs** (10K+ campaign flows)
- You changed `FLOW_FEATURES` (different feature set)
- You changed model architecture (hidden_size, num_layers)
- Fine-tuned model **degraded** on the CIC-IDS test split

```powershell
python setup\train_from_scratch.py --data combined_flows.csv --epochs 30
```

---

## 🚀 Quick Start (Full Automated Pipeline)

### On Windows — One Command

```powershell
# Runs everything: install tools → create VMs → collect data → merge → retrain
powershell -ExecutionPolicy Bypass -File setup\lab_setup_and_retrain.ps1
```

The PS1 script auto-elevates to Administrator and auto-installs:
- VirtualBox (via winget)
- Wireshark/dumpcap (via winget)
- 7-Zip (via winget)
- Python packages (torch, scapy, shap, etc.)
- OpenSSH client

### Resume From Any Phase

```powershell
# VMs already configured — skip to collection + retrain:
powershell -ExecutionPolicy Bypass -File setup\lab_setup_and_retrain.ps1 -SkipNetwork -SkipVMSetup

# Data already collected — skip to merge + retrain:
powershell -ExecutionPolicy Bypass -File setup\lab_setup_and_retrain.ps1 -SkipToTraining

# More runs / more epochs:
powershell -ExecutionPolicy Bypass -File setup\lab_setup_and_retrain.ps1 -Runs 10 -Epochs 30
```

---

## 🧪 Manual Step-by-Step (Without the PS1)

If you prefer running each step yourself:

### Step 1: Collect Lab Data
```powershell
cd Project-Garud
python lab\reset_lab.py --config lab\lab_config.json
python lab\collect_dataset.py --config lab\lab_config.json --out dataset
```

### Step 2: Extract Flows
```powershell
python lab\extract_flows.py --dataset dataset
```

### Step 3: Merge with CIC-IDS
```powershell
python setup\merge_lab_flows.py --dataset dataset --base real_flows.csv --output combined_flows.csv
```

### Step 4a: Fine-Tune (recommended)
```powershell
python setup\finetune_model.py --data combined_flows.csv
```

### Step 4b: OR Train From Scratch
```powershell
python setup\train_from_scratch.py --data combined_flows.csv
```

### Step 5: Calibrate
```powershell
python experiments\calibrate_stage_logits.py
```

### Step 6: Verify
```powershell
python -m pytest backend\tests -v
```

---

## 📊 Expected Results After Retraining

### With Fine-Tuning on 5 Lab Runs (~5K campaign flows)

| Metric | Before | After (Expected) | Notes |
|---|:---:|:---:|---|
| Binary F1 | 0.862 | 0.85-0.88 | Should stay stable |
| Early Warning Rate | 23.9% | 35-45% | **Primary target improvement** |
| Lead Time (12 flows) | 3.7% | 15-25% | Real campaigns help |
| Per-stage macro-F1 | 0.928 | 0.90-0.93 | May dip slightly |
| Unseen family AUC | 0.56 | 0.65-0.75 | Real transitions help |
| FPR | 4.59% | 3-5% | Should stay stable |

### Why Early Warning Improves
The existing model was trained on CIC-IDS where each attack type is isolated
in its own time block — no real Recon→Access→Lateral→C2→Exfil progression.
Lab campaigns contain **actual kill chain transitions**, which is exactly what
the world model's next-state prediction head needs to learn forecasting.

---

## ⚠️ Important Notes

1. **Backup**: Both scripts automatically back up `backend/artifacts/` before overwriting.
   Backups are timestamped: `backend/artifacts/backup_20260927_150000/`

2. **Calibration**: After retraining, run `experiments/calibrate_stage_logits.py` and
   manually copy the bias values into `backend/artifacts/config.json`.

3. **Test fixtures**: Some backend tests may fail after retraining because they reference
   the old model's exact outputs. Update test fixtures if the model's predictions changed.

4. **Lab isolation**: The lab VMs use host-only networking with no internet access.
   **Never** add NAT or bridged adapters to lab VMs.

5. **Scaler**: By default, fine-tuning uses the existing CIC-IDS scaler. Only use
   `--refit-scaler` if lab features have significantly different distributions.
