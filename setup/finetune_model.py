"""
Fine-tune the existing trained WorldModel on new lab campaign data.

WHY FINE-TUNE INSTEAD OF TRAIN FROM SCRATCH:
─────────────────────────────────────────────
1. Your existing model already has strong detection (F1=0.862, ROC-AUC=0.948)
   learned from ~40K+ CIC-IDS2017/2018 flows. Training from scratch risks
   losing those learned flow patterns if lab data is small.

2. Lab campaign data is typically small (~500-2000 flows/run × 5 runs = 2500-10000
   flows) vs CIC-IDS base (~40K+). From-scratch would massively overfit to
   the smaller lab set.

3. Fine-tuning with a low learning rate (10x lower) preserves existing knowledge
   while teaching the model real multi-stage campaign transitions — exactly what
   the SIH PS asks for: "forecasting attack progression".

4. The LSTM backbone has already learned flow feature representations. Fine-tuning
   only needs to adjust the heads (risk + stage) to recognize real campaign
   transition patterns, not relearn what TCP SYN scans look like.

WHEN TO USE TRAIN-FROM-SCRATCH INSTEAD:
────────────────────────────────────────
- If you collect 20+ lab runs (10K+ campaign flows) — enough data to learn from
- If you change the feature set (different FLOW_FEATURES)
- If you change model architecture (hidden_size, num_layers)
- If fine-tuned model degrades on CIC-IDS test set

Usage:
    # Fine-tune on combined data (recommended):
    python setup/finetune_model.py --data combined_flows.csv

    # Fine-tune on lab data only (risky, small dataset):
    python setup/finetune_model.py --data combined_flows.csv --lab-only

    # Fine-tune with frozen LSTM (safest, only retrain heads):
    python setup/finetune_model.py --data combined_flows.csv --freeze-lstm

    # Compare with from-scratch baseline:
    python setup/train_from_scratch.py --data combined_flows.csv
"""
import argparse
import copy
import json
import os
import pickle
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

# Add project root to path so we can import from pipeline_fixed
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline_fixed import (
    SEED, DEVICE, STAGES, STAGE2ID, FLOW_FEATURES, WINDOW,
    WorldModel, FlowSeqDataset, FocalLoss, StandardScaler,
    build_sequences, three_way_split, compute_metrics,
    augment_rare_stages, forward_simulate, monte_carlo_rollout,
    ema_smooth, pick_demo_session,
)

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)


def load_existing_model(artifacts_dir):
    """Load the existing trained model, scaler, and config."""
    artifacts = Path(artifacts_dir)

    # Load config
    config_path = artifacts / "config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"No config.json in {artifacts_dir}")
    with open(config_path) as f:
        config = json.load(f)

    # Load scaler
    scaler_path = artifacts / "scaler.pkl"
    if not scaler_path.exists():
        raise FileNotFoundError(f"No scaler.pkl in {artifacts_dir}")
    with open(scaler_path, "rb") as f:
        scaler_data = pickle.load(f)
    scaler = StandardScaler(mean=scaler_data["mean"], scale=scaler_data["scale"])

    # Load model
    model_path = artifacts / "world_model.pt"
    if not model_path.exists():
        raise FileNotFoundError(f"No world_model.pt in {artifacts_dir}")

    hidden = config.get("hidden_size", 256)
    num_layers = config.get("num_layers", 2)
    dropout = config.get("lstm_dropout", 0.25)

    model = WorldModel(
        n_features=len(FLOW_FEATURES),
        hidden=hidden,
        num_layers=num_layers,
        dropout=dropout,
    ).to(DEVICE)
    model.load_state_dict(torch.load(model_path, map_location=DEVICE, weights_only=True))

    print(f"Loaded model from {artifacts_dir}:")
    print(f"  Architecture: {num_layers}-layer LSTM, hidden={hidden}, dropout={dropout}")
    print(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")

    return model, scaler, config


def freeze_lstm_backbone(model):
    """Freeze LSTM weights, only train the 3 heads."""
    frozen, trainable = 0, 0
    for name, param in model.named_parameters():
        if name.startswith("lstm."):
            param.requires_grad = False
            frozen += param.numel()
        else:
            trainable += param.numel()
    print(f"  Frozen (LSTM): {frozen:,} params")
    print(f"  Trainable (heads): {trainable:,} params")


def finetune(model, train_loader, val_loader, args, scaler):
    """Fine-tune the model with low learning rate and early stopping."""

    # Compute class weights from training data
    all_stages = []
    for _, _, _, ys in train_loader:
        all_stages.extend(ys.numpy())
    ys_train = np.array(all_stages)

    all_mals = []
    for _, _, ym, _ in train_loader:
        all_mals.extend(ym.numpy())
    ym_train = np.array(all_mals)

    stage_counts = np.bincount(ys_train, minlength=len(STAGES))
    total_samples = len(ys_train)
    raw_weights = total_samples / (len(STAGES) * np.maximum(stage_counts, 1).astype(np.float32))
    class_weights = np.clip(raw_weights, 0.2, args.class_weight_max)
    stage_weight_t = torch.tensor(class_weights, dtype=torch.float32).to(DEVICE)

    ce_loss = FocalLoss(alpha=stage_weight_t, gamma=args.focal_gamma)

    num_pos = np.sum(ym_train == 1)
    num_neg = np.sum(ym_train == 0)
    pos_weight_val = float(num_neg) / max(float(num_pos), 1.0)
    pos_weight = torch.tensor([pos_weight_val], dtype=torch.float32).to(DEVICE)
    bce_loss = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    mse_loss = nn.MSELoss()

    # Lower learning rate for fine-tuning (10x lower than from-scratch)
    lr = args.lr
    print(f"\n  Fine-tune LR: {lr:.1e} (vs from-scratch: {lr * 10:.1e})")
    print(f"  Focal loss γ={args.focal_gamma}, class_weight_max={args.class_weight_max}")
    print(f"  Stage weights: {np.round(class_weights, 2)}")
    print(f"  pos_weight (infiltration head): {pos_weight_val:.2f}")

    opt = torch.optim.AdamW(
        filter(lambda p: p.requires_grad, model.parameters()),
        lr=lr,
        weight_decay=args.weight_decay,
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs, eta_min=1e-6)

    best_val_f1 = -1.0
    best_state = None
    patience_counter = 0

    print(f"\n{'='*70}")
    print(f"  FINE-TUNING for {args.epochs} epochs (patience={args.patience})")
    print(f"{'='*70}\n")

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0.0
        for xb, yn_b, ym_b, ys_b in train_loader:
            xb, yn_b = xb.to(DEVICE), yn_b.to(DEVICE)
            ym_b, ys_b = ym_b.to(DEVICE), ys_b.to(DEVICE)
            opt.zero_grad()
            pred_next, inf_logit, stage_logits = model(xb)
            loss = mse_loss(pred_next, yn_b) + bce_loss(inf_logit, ym_b) + ce_loss(stage_logits, ys_b)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            opt.step()
            total_loss += loss.item() * xb.size(0)

        epoch_loss = total_loss / len(train_loader.dataset)

        # Validate
        model.eval()
        val_preds, val_true = [], []
        with torch.no_grad():
            for xb, _, ym_b, _ in val_loader:
                _, inf_logit, _ = model(xb.to(DEVICE))
                probs = torch.sigmoid(inf_logit).cpu().numpy()
                val_preds.extend((probs > 0.5).astype(int))
                val_true.extend(ym_b.numpy().astype(int))

        val_metrics = compute_metrics(np.array(val_true), np.array(val_preds))
        val_f1 = val_metrics["f1"]
        scheduler.step()
        curr_lr = opt.param_groups[0]["lr"]

        checkpoint_marker = ""
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_state = copy.deepcopy(model.state_dict())
            patience_counter = 0
            checkpoint_marker = " ★ NEW BEST"
        else:
            patience_counter += 1

        print(
            f"  Epoch {epoch+1:2d}/{args.epochs} — loss: {epoch_loss:.4f} | "
            f"val_f1: {val_f1:.4f}  prec: {val_metrics['precision']:.4f}  "
            f"rec: {val_metrics['recall']:.4f}  fpr: {val_metrics['fpr']:.4f} "
            f"(lr: {curr_lr:.2e}){checkpoint_marker}"
        )

        if patience_counter >= args.patience:
            print(f"\n  Early stopping at epoch {epoch+1} (no improvement for {args.patience} epochs)")
            break

    if best_state is not None:
        model.load_state_dict(best_state)
        print(f"\n  Loaded best checkpoint (val_f1={best_val_f1:.4f})")

    return model, best_val_f1


def main():
    ap = argparse.ArgumentParser(description="Fine-tune the WorldModel on lab campaign data")
    ap.add_argument("--data", required=True, help="Path to combined CSV (CIC-IDS + lab flows)")
    ap.add_argument("--artifacts", default=str(ROOT / "backend" / "artifacts"),
                    help="Path to existing model artifacts (default: backend/artifacts)")
    ap.add_argument("--out", default=str(ROOT / "backend" / "artifacts"),
                    help="Output directory for fine-tuned artifacts")
    ap.add_argument("--epochs", type=int, default=10,
                    help="Fine-tuning epochs (default: 10, lower than from-scratch)")
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--lr", type=float, default=1e-4,
                    help="Learning rate (default: 1e-4, 10x lower than from-scratch)")
    ap.add_argument("--weight-decay", type=float, default=1e-4)
    ap.add_argument("--focal-gamma", type=float, default=2.0)
    ap.add_argument("--class-weight-max", type=float, default=6.0)
    ap.add_argument("--patience", type=int, default=5,
                    help="Early stopping patience (epochs without improvement)")
    ap.add_argument("--freeze-lstm", action="store_true",
                    help="Freeze LSTM backbone, only fine-tune heads (safest)")
    ap.add_argument("--augment-stages", default="Exfiltration",
                    help="Stages to oversample with synthetic data")
    ap.add_argument("--augment-sessions", type=int, default=300)
    ap.add_argument("--refit-scaler", action="store_true",
                    help="Refit scaler on new data (use if lab features differ significantly)")
    args = ap.parse_args()

    print("=" * 70)
    print("  PROJECT GARUD — FINE-TUNE WORLD MODEL")
    print("  SIH 2026 PS:26153 (NTRO)")
    print("=" * 70)

    # ── Load existing model ──
    print("\n[1/6] Loading existing model...")
    model, scaler, config = load_existing_model(args.artifacts)

    if args.freeze_lstm:
        print("\n[1b] Freezing LSTM backbone (head-only fine-tuning)...")
        freeze_lstm_backbone(model)

    # ── Load data ──
    print(f"\n[2/6] Loading training data: {args.data}")
    df = pd.read_csv(args.data, parse_dates=["timestamp"])
    print(f"  Shape: {df.shape}")
    print(f"  Sessions: {df['session_id'].nunique()}")
    print(f"  Stage distribution:\n{df['stage_label'].value_counts().to_string()}")

    # ── Split ──
    print("\n[3/6] Splitting data (3-way: train/val/test)...")
    unique_sids = df["session_id"].unique()
    train_sids, val_sids, test_sids = three_way_split(unique_sids, val_size=0.1, test_size=0.2)
    train_df = df[df["session_id"].isin(train_sids)].copy()
    val_df = df[df["session_id"].isin(val_sids)].copy()
    test_df = df[df["session_id"].isin(test_sids)].copy()
    print(f"  Train: {len(train_df)} flows ({len(train_sids)} sessions)")
    print(f"  Val:   {len(val_df)} flows ({len(val_sids)} sessions)")
    print(f"  Test:  {len(test_df)} flows ({len(test_sids)} sessions)")

    # Augment rare stages
    augment_stages = [s.strip() for s in args.augment_stages.split(",") if s.strip()]
    if augment_stages:
        synth = augment_rare_stages(augment_stages, n_sessions_per_stage=args.augment_sessions)
        train_df = pd.concat([train_df, synth], ignore_index=True)

    # ── Scale features ──
    if args.refit_scaler:
        print("\n  Refitting scaler on new combined data...")
        scaler = StandardScaler()
        train_df[FLOW_FEATURES] = scaler.fit_transform(train_df[FLOW_FEATURES])
    else:
        print("\n  Using existing scaler (preserving CIC-IDS normalization)...")
        train_df[FLOW_FEATURES] = scaler.transform(train_df[FLOW_FEATURES])

    val_df[FLOW_FEATURES] = scaler.transform(val_df[FLOW_FEATURES])
    test_df[FLOW_FEATURES] = scaler.transform(test_df[FLOW_FEATURES])

    train_df["stage_id"] = train_df["stage_label"].map(STAGE2ID)
    val_df["stage_id"] = val_df["stage_label"].map(STAGE2ID)
    test_df["stage_id"] = test_df["stage_label"].map(STAGE2ID)

    train_sorted = train_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    val_sorted = val_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    test_sorted = test_df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)

    X_train, yn_train, ym_train, ys_train = build_sequences(train_sorted)
    X_val, yn_val, ym_val, ys_val = build_sequences(val_sorted)
    X_test, yn_test, ym_test, ys_test = build_sequences(test_sorted)
    print(f"  Sequences — Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")

    train_loader = DataLoader(FlowSeqDataset(X_train, yn_train, ym_train, ys_train),
                              batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(FlowSeqDataset(X_val, yn_val, ym_val, ys_val),
                            batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(FlowSeqDataset(X_test, yn_test, ym_test, ys_test),
                             batch_size=args.batch_size, shuffle=False)

    # ── Fine-tune ──
    print("\n[4/6] Fine-tuning...")
    model, best_val_f1 = finetune(model, train_loader, val_loader, args, scaler)

    # ── Evaluate on test set ──
    print("\n[5/6] Evaluating on held-out test set...")
    model.eval()
    all_preds, all_true = [], []
    all_stage_preds, all_stage_true = [], []
    with torch.no_grad():
        for xb, _, ym_b, ys_b in test_loader:
            _, inf_logit, stage_logits = model(xb.to(DEVICE))
            probs = torch.sigmoid(inf_logit).cpu().numpy()
            all_preds.extend((probs > 0.5).astype(int))
            all_true.extend(ym_b.numpy().astype(int))
            all_stage_preds.extend(torch.argmax(stage_logits, dim=1).cpu().numpy())
            all_stage_true.extend(ys_b.numpy())

    test_metrics = compute_metrics(np.array(all_true), np.array(all_preds))
    print(f"\n  ┌──────────────────────────────────────────────┐")
    print(f"  │  FINE-TUNED MODEL — TEST METRICS             │")
    print(f"  ├──────────────────────────────────────────────┤")
    print(f"  │  F1:        {test_metrics['f1']:.4f}                        │")
    print(f"  │  Precision: {test_metrics['precision']:.4f}                        │")
    print(f"  │  Recall:    {test_metrics['recall']:.4f}                        │")
    print(f"  │  FPR:       {test_metrics['fpr']:.4f}                        │")
    print(f"  └──────────────────────────────────────────────┘")

    # Per-stage metrics
    print("\n  Per-stage accuracy:")
    for stage_name, stage_id in STAGE2ID.items():
        mask = np.array(all_stage_true) == stage_id
        if mask.sum() > 0:
            correct = (np.array(all_stage_preds)[mask] == stage_id).sum()
            acc = correct / mask.sum()
            print(f"    {stage_name:20s}: {acc:.4f} ({correct}/{mask.sum()})")

    # Demo Monte Carlo rollout
    demo_sid = pick_demo_session(test_sorted)
    if demo_sid is not None:
        demo_session = test_sorted[test_sorted["session_id"] == demo_sid]
        demo_feats = demo_session[FLOW_FEATURES].values
        if len(demo_feats) >= WINDOW:
            mc_mean, mc_std, mc_stages = monte_carlo_rollout(
                model, demo_feats[:WINDOW], k_steps=6, n_samples=20
            )
            print(f"\n  Demo forecast (session {demo_sid}):")
            for i in range(6):
                print(f"    t+{i+1}: risk={mc_mean[i]:.3f}±{mc_std[i]:.3f}  stage={mc_stages[i]}")

    # ── Save artifacts ──
    print(f"\n[6/6] Saving fine-tuned artifacts → {args.out}")
    os.makedirs(args.out, exist_ok=True)

    torch.save(model.state_dict(), os.path.join(args.out, "world_model.pt"))

    with open(os.path.join(args.out, "scaler.pkl"), "wb") as f:
        pickle.dump({"mean": scaler.mean_, "scale": scaler.scale_}, f)

    # Update config
    config["provenance"]["fine_tuned_from"] = str(args.artifacts)
    config["provenance"]["fine_tune_data"] = str(args.data)
    config["provenance"]["fine_tune_epochs"] = args.epochs
    config["provenance"]["fine_tune_lr"] = args.lr
    config["provenance"]["fine_tune_freeze_lstm"] = args.freeze_lstm
    config["provenance"]["fine_tune_best_val_f1"] = best_val_f1
    config["provenance"]["fine_tune_test_metrics"] = test_metrics
    config["provenance"]["fine_tune_refit_scaler"] = args.refit_scaler

    with open(os.path.join(args.out, "config.json"), "w") as f:
        json.dump(config, f, indent=2)

    print(f"\n{'='*70}")
    print(f"  FINE-TUNING COMPLETE")
    print(f"  Test F1: {test_metrics['f1']:.4f}")
    print(f"  Artifacts: {args.out}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
