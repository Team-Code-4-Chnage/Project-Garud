"""
Train the WorldModel FROM SCRATCH on combined data.

This is a thin wrapper around pipeline_fixed.py with campaign-optimized defaults.
Use this when:
  - You have collected 20+ lab runs (10K+ campaign flows)
  - You changed the feature set or model architecture
  - Fine-tuning degraded performance

Usage:
    python setup/train_from_scratch.py --data combined_flows.csv
    python setup/train_from_scratch.py --data combined_flows.csv --epochs 30
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser(description="Train WorldModel from scratch with campaign-optimized defaults")
    ap.add_argument("--data", required=True, help="Path to training CSV (combined_flows.csv)")
    ap.add_argument("--out", default=str(ROOT / "backend" / "artifacts"),
                    help="Output directory for model artifacts")
    ap.add_argument("--epochs", type=int, default=25,
                    help="Training epochs (default: 25)")
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--hidden-size", type=int, default=256)
    ap.add_argument("--num-layers", type=int, default=2)
    ap.add_argument("--dropout", type=float, default=0.25)
    ap.add_argument("--lr", type=float, default=1e-3,
                    help="Learning rate (default: 1e-3, standard from-scratch rate)")
    ap.add_argument("--weight-decay", type=float, default=1e-4)
    ap.add_argument("--class-weight-max", type=float, default=6.0)
    ap.add_argument("--stage-loss", choices=["weighted_ce", "focal"], default="focal")
    ap.add_argument("--focal-gamma", type=float, default=2.0)
    ap.add_argument("--stage-target", choices=["current", "next"], default="current")
    ap.add_argument("--augment-stages", default="Exfiltration")
    ap.add_argument("--augment-sessions", type=int, default=300)
    args = ap.parse_args()

    # Backup existing artifacts
    from datetime import datetime
    artifacts = Path(args.out)
    if artifacts.exists() and (artifacts / "world_model.pt").exists():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = artifacts / f"backup_{ts}"
        print(f"Backing up existing model → {backup}")
        import shutil
        shutil.copytree(artifacts, backup, dirs_exist_ok=True)

    # Build pipeline_fixed.py command
    pipeline = str(ROOT / "pipeline_fixed.py")
    cmd = [
        sys.executable, pipeline,
        "--data", args.data,
        "--out", args.out,
        "--epochs", str(args.epochs),
        "--batch-size", str(args.batch_size),
        "--hidden-size", str(args.hidden_size),
        "--num-layers", str(args.num_layers),
        "--dropout", str(args.dropout),
        "--lr", str(args.lr),
        "--weight-decay", str(args.weight_decay),
        "--class-weight-max", str(args.class_weight_max),
        "--stage-loss", args.stage_loss,
        "--focal-gamma", str(args.focal_gamma),
        "--stage-target", args.stage_target,
        "--augment-stages", args.augment_stages,
        "--augment-sessions-per-stage", str(args.augment_sessions),
    ]

    print("=" * 70)
    print("  PROJECT GARUD — TRAIN FROM SCRATCH")
    print("  SIH 2026 PS:26153 (NTRO)")
    print("=" * 70)
    print(f"\n  Data:   {args.data}")
    print(f"  Output: {args.out}")
    print(f"  Config: {args.num_layers}L LSTM h={args.hidden_size} d={args.dropout}")
    print(f"          {args.stage_loss}(γ={args.focal_gamma}), lr={args.lr}, epochs={args.epochs}")
    print(f"\n  Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
