"""
Train the V2 network-state world model with genuine multi-step targets.

Loss = sum_k w_k * MSE(S_hat[t+k], S[t+k])            transition, k=1..H
     + risk_w * mean_k BCE(risk_k, any-malicious[t+k]) future risk
     + stage_w * mean_k CE(stage_k, stage[t+k])        future stage (clipped class weights)
Rollout is recursive during training with scheduled teacher forcing
(true state fed with probability tf, decayed linearly to 0 by 60% of training).

Run: python -m worldmodel_v2.train --G 4 --out backend/artifacts_v2
"""
import argparse
import json
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as Fn

from worldmodel_v2.data import REPO_ROOT, W, load_sessions, make_windows, scaler_from
from worldmodel_v2.model import NetStateWorldModel
from worldmodel_v2.state_features import STATE_DIM, STATE_FEATURES

H_DEFAULT = 4
STEP_WEIGHTS = [1.0, 0.8, 0.6, 0.5]  # nearer steps weigh more; far steps are noisier targets


def losses(model, b, H, tf, pos_w, cls_w):
    S, R, C = model.rollout(b["X"], H, b["F"], tf)
    w = torch.tensor(STEP_WEIGHTS[:H])
    trans = (((S - b["F"]) ** 2).mean(dim=(0, 2)) * w).sum() / w.sum()
    risk = Fn.binary_cross_entropy_with_logits(R, b["yr"].float(), pos_weight=pos_w)
    stage = Fn.cross_entropy(C.reshape(-1, C.shape[-1]), b["ys"].reshape(-1), weight=cls_w)
    return trans, risk, stage


def tensors(w):
    return dict(X=torch.tensor(w["X"]), F=torch.tensor(w["F"]), yr=torch.tensor(w["yr"]),
                ys=torch.tensor(w["ys"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--G", type=int, default=4, help="flows per network-state window")
    ap.add_argument("--H", type=int, default=H_DEFAULT)
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--risk-w", type=float, default=1.0)
    ap.add_argument("--stage-w", type=float, default=0.5)
    ap.add_argument("--out", default="backend/artifacts_v2")
    args = ap.parse_args()
    torch.manual_seed(42)
    np.random.seed(42)
    H = args.H

    ss = load_sessions(args.G)
    mean, std = scaler_from(ss["train"])
    tr = make_windows(ss["train"], mean, std, H)
    va = make_windows(ss["val"], mean, std, H)
    print(f"G={args.G} H={H} train windows {len(tr['X'])} val windows {len(va['X'])} dim {STATE_DIM}", flush=True)
    Ttr, Tva = tensors(tr), tensors(va)

    pos = tr["yr"].mean()
    pos_w = torch.tensor((1 - pos) / max(pos, 1e-6)).float()
    cnt = np.bincount(tr["ys"].reshape(-1), minlength=6).astype(np.float64)
    cw = np.where(cnt > 0, cnt.sum() / (6 * np.maximum(cnt, 1)), 0.0)
    cw = np.clip(cw / cw[cw > 0].min(), 0, 6.0)  # same clip as V1; absent classes get weight 0
    cls_w = torch.tensor(cw, dtype=torch.float32)
    print("pos_weight", float(pos_w), "class weights", np.round(cw, 2), flush=True)

    model = NetStateWorldModel(STATE_DIM)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)
    n = len(Ttr["X"])
    best, best_state, bad = 1e9, None, 0
    for ep in range(args.epochs):
        t0 = time.time()
        tf = max(0.0, 1.0 - ep / (0.6 * args.epochs))
        model.train()
        perm = torch.randperm(n)
        for i in range(0, n, args.batch):
            idx = perm[i:i + args.batch]
            b = {k: v[idx] for k, v in Ttr.items()}
            tr_l, rk_l, st_l = losses(model, b, H, tf, pos_w, cls_w)
            loss = tr_l + args.risk_w * rk_l + args.stage_w * st_l
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
        model.eval()
        with torch.no_grad():  # validation is always free-running (tf=0)
            v = [losses(model, {k: x[j:j + 1024] for k, x in Tva.items()}, H, 0.0, pos_w, cls_w)
                 for j in range(0, len(Tva["X"]), 1024)]
        vt, vr, vs = (float(np.mean([x[i].item() for x in v])) for i in range(3))
        vloss = vt + args.risk_w * vr + args.stage_w * vs
        print(f"ep {ep + 1:02d} tf={tf:.2f} val trans={vt:.4f} risk={vr:.4f} stage={vs:.4f} "
              f"total={vloss:.4f} ({time.time() - t0:.0f}s)", flush=True)
        # Validation is always free-running, so every epoch is comparable. (Run 1 only allowed the last
        # 40% of epochs, which forced selection of overfit checkpoints; see docs/model_card.md 6.2.)
        if vloss < best:
            best, bad = vloss, 0
            best_state = {k: x.clone() for k, x in model.state_dict().items()}
        else:
            bad += 1
            if bad >= 8:
                break
    if best_state is None:
        best_state = model.state_dict()
    out = REPO_ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    torch.save(best_state, out / "world_model_v2.pt")
    np.savez(out / "scaler_v2.npz", mean=mean, std=std)
    json.dump(dict(version="v2_network_state_world_model", G=args.G, window=W, horizon=H, dim=STATE_DIM,
                   hidden=256, layers=2, dropout=0.25, features=STATE_FEATURES, step_weights=STEP_WEIGHTS[:H],
                   risk_w=args.risk_w, stage_w=args.stage_w, best_val_loss=best,
                   split="session-level, seed 42, identical sessions to V1"),
              open(out / "config_v2.json", "w"), indent=2)
    print("saved", out, "best val", best)


if __name__ == "__main__":
    main()
