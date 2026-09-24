"""
V3 network-state world model: data handling, training, alert protocol and metrics.

Input: data/netwin_1min.csv.gz built by data/build_network_windows.py
(1-minute, network-wide windows of CIC-IDS2017 labelled flows with real IP/port/protocol context).

Feature sets compared with the identical model and protocol:
  "flow" : f_* columns only (flow statistics aggregated per minute; no IP/port/protocol information)
  "net"  : f_* plus n_* columns (adds unique hosts/ports, protocol mix, direction, rates, entropies)
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as Fn

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from worldmodel_v2.model import NetStateWorldModel  # noqa: E402

W, H = 6, 4
STEP_W = [1.0, 0.8, 0.6, 0.5]
BEHAVIOURS = ["Benign", "PortScan", "BruteForce", "DoS", "DDoS", "WebAttack", "Bot", "Infiltration", "Heartbleed"]
B2ID = {b: i for i, b in enumerate(BEHAVIOURS)}
QUIET = 6          # attack-free windows required before an episode onset
LOOKBACK = 20      # maximum minutes before onset in which a warning is counted
WITHIN = [5, 10, 12, 20]
DAYS = ["2017-07-04", "2017-07-05", "2017-07-06", "2017-07-07"]  # attack days; 07-03 is benign only


def load(feature_set):
    df = pd.read_csv(REPO_ROOT / "data" / "netwin_1min.csv.gz", parse_dates=["minute"])
    f_cols = [c for c in df.columns if c.startswith("f_")]
    n_cols = [c for c in df.columns if c.startswith("n_")]
    cols = f_cols if feature_set == "flow" else f_cols + n_cols
    days = {}
    for date, g in df.groupby("date"):
        g = g.sort_values("minute")
        X = np.log1p(np.maximum(g[cols].values.astype(np.float64), 0.0)).astype(np.float32)
        days[date] = dict(X=X, y=(g["y_n_mal"].values > 0).astype(np.int64),
                          beh=g["y_behaviour"].map(B2ID).values.astype(np.int64), minute=g["minute"].values)
    return days, cols


def windows(seqs, mean, std, mask_fn=None):
    """Sliding windows over each day. Returns dict with X, F(uture states), yr, yb and position info.
    mask_fn(day, i) may veto a window (used to purge boundaries in the chronological protocol)."""
    X, Fu, YR, YB, day_of, end = [], [], [], [], [], []
    for date, d in seqs.items():
        S = (d["X"] - mean) / std
        n = len(S)
        for i in range(n - W - H + 1):
            if mask_fn is not None and not mask_fn(date, i):
                continue
            X.append(S[i:i + W]); Fu.append(S[i + W:i + W + H])
            YR.append(d["y"][i + W:i + W + H]); YB.append(d["beh"][i + W:i + W + H])
            day_of.append(date); end.append(i + W - 1)
    return dict(X=np.array(X, np.float32), F=np.array(Fu, np.float32), yr=np.array(YR), yb=np.array(YB),
                day=np.array(day_of), end=np.array(end))


def fit_scaler(seqs):
    S = np.concatenate([d["X"] for d in seqs.values()])
    m, s = S.mean(0), S.std(0)
    s[s == 0] = 1.0
    return m.astype(np.float32), s.astype(np.float32)


def _tensors(w):
    return {k: torch.tensor(w[k]) for k in ("X", "F", "yr", "yb")}


def _losses(model, b, tf, pos_w, cls_w):
    S, R, C = model.rollout(b["X"], H, b["F"], tf)
    w = torch.tensor(STEP_W)
    trans = (((S - b["F"]) ** 2).mean(dim=(0, 2)) * w).sum() / w.sum()
    risk = Fn.binary_cross_entropy_with_logits(R, b["yr"].float(), pos_weight=pos_w)
    beh = Fn.cross_entropy(C.reshape(-1, C.shape[-1]), b["yb"].reshape(-1), weight=cls_w)
    return trans, risk, beh


def train(tr, va, dim, seed, epochs=40, batch=64, lr=1e-3, wd=1e-4, hidden=128, dropout=0.3, patience=8):
    """Train with recursive multi-step rollout and scheduled teacher forcing (1.0 -> 0.0 over 60% of epochs).
    Checkpoint = lowest FREE-RUNNING validation loss over all epochs."""
    torch.manual_seed(seed); np.random.seed(seed)
    Ttr, Tva = _tensors(tr), _tensors(va)
    pos = float(tr["yr"].mean())
    pos_w = torch.tensor((1 - pos) / max(pos, 1e-6)).float()
    cnt = np.bincount(tr["yb"].reshape(-1), minlength=len(BEHAVIOURS)).astype(np.float64)
    cw = np.where(cnt > 0, cnt.sum() / (len(BEHAVIOURS) * np.maximum(cnt, 1)), 0.0)
    cw = np.clip(cw / cw[cw > 0].min(), 0, 6.0)
    cls_w = torch.tensor(cw, dtype=torch.float32)
    model = NetStateWorldModel(dim, hidden=hidden, layers=2, dropout=dropout, n_stages=len(BEHAVIOURS))
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=wd)
    n = len(Ttr["X"])
    best, best_state, bad = 1e9, None, 0
    for ep in range(epochs):
        tf = max(0.0, 1.0 - ep / (0.6 * epochs))
        model.train()
        perm = torch.randperm(n)
        for i in range(0, n, batch):
            idx = perm[i:i + batch]
            b = {k: v[idx] for k, v in Ttr.items()}
            t, r, s = _losses(model, b, tf, pos_w, cls_w)
            loss = t + r + 0.5 * s
            opt.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
        model.eval()
        with torch.no_grad():
            t, r, s = _losses(model, Tva, 0.0, pos_w, cls_w)
        v = float(t + r + 0.5 * s)
        if v < best:
            best, bad = v, 0
            best_state = {k: x.clone() for k, x in model.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    model.load_state_dict(best_state)
    model.eval()
    return model


@torch.no_grad()
def rollout(model, X):
    S, R, C = model.rollout(torch.tensor(X), H)
    return S.numpy(), torch.sigmoid(R).numpy(), C.numpy()


def input_windows(d, mean, std):
    """All input windows of a day (no future requirement). Window i ends at minute index i+W-1."""
    S = (d["X"] - mean) / std
    return np.array([S[i:i + W] for i in range(len(S) - W + 1)], np.float32)


def sustained(flag, N):
    """flag: bool array over consecutive windows. True where the last N flags are all True."""
    out = np.zeros(len(flag), bool)
    run = 0
    for i, f in enumerate(flag):
        run = run + 1 if f else 0
        out[i] = run >= N
    return out


def episodes(y):
    """Onset indices j (minute index) with y[j]=1 and >= QUIET attack-free minutes before it; returns list
    of (onset, end) where the run continues until QUIET consecutive attack-free minutes."""
    eps, i, n = [], 0, len(y)
    while i < n:
        if y[i] == 1 and i >= QUIET and y[i - QUIET:i].sum() == 0:
            j = i
            while j < n and y[j:j + QUIET].sum() > 0:
                j += 1
            eps.append((i, j))
            i = j
        else:
            i += 1
    return eps


def evaluate_alerts(score_by_day, y_by_day, thr, N):
    """score_by_day[d][t] is the risk score of the window ending at minute t (NaN for t < W-1).
    Returns dict of episode / false-alarm statistics under a sustained-alert rule."""
    res = dict(eligible=0, within={n: 0 for n in WITHIN}, leads=[], fa_events=0, quiet_windows=0,
               fa_windows=0, quiet_hours_blocks=0, fa_hours_blocks=0, attack_windows=0, benign_windows=0)
    for d, score in score_by_day.items():
        y = y_by_day[d]
        n = len(y)
        valid = ~np.isnan(score)
        flag = np.zeros(n, bool)
        flag[valid] = score[valid] >= thr
        act = sustained(flag, N)
        # a window "ending at t" is quiet if the window and the next LOOKBACK minutes contain no attack
        lo = np.arange(n) - (W - 1)
        quiet = np.array([valid[t] and y[max(lo[t], 0):min(t + LOOKBACK, n - 1) + 1].sum() == 0 for t in range(n)])
        res["quiet_windows"] += int(quiet.sum())
        res["fa_windows"] += int((act & quiet).sum())
        res["attack_windows"] += int((y == 1).sum())
        res["benign_windows"] += int((y == 0).sum())
        edge = act & ~np.concatenate([[False], act[:-1]])
        res["fa_events"] += int((edge & quiet).sum())
        # non-overlapping 60-minute blocks that are entirely quiet
        for s in range(0, n - 59, 60):
            blk = slice(s, s + 60)
            if quiet[blk].all():
                res["quiet_hours_blocks"] += 1
                res["fa_hours_blocks"] += int(act[blk].any())
        for onset, _end in episodes(y):
            res["eligible"] += 1
            cand = [t for t in range(max(W - 1, onset - LOOKBACK), onset)
                    if y[max(t - (W - 1), 0):t + 1].sum() == 0]
            fired = [t for t in cand if act[t]]
            if fired:
                res["leads"].append(onset - min(fired))
                for nn in WITHIN:
                    res["within"][nn] += int(any(onset - t <= nn for t in fired))
    return res


def choose_operating_point(val_scores, val_y, fa_per_hour_budget=1.0):
    """Pick (thr, N) on VALIDATION ONLY: maximise the share of episodes warned within LOOKBACK minutes
    subject to false-alarm events per quiet hour <= budget. Ties: fewer false alarms, then smaller N."""
    allv = np.concatenate([s[~np.isnan(s)] for s in val_scores.values()])
    thrs = np.unique(np.quantile(allv, np.linspace(0.5, 0.999, 60)))
    best = None
    for N in (1, 2, 3, 4, 5):
        for thr in thrs:
            r = evaluate_alerts(val_scores, val_y, thr, N)
            hours = max(r["quiet_windows"] / 60.0, 1e-9)
            fa_h = r["fa_events"] / hours
            warned = (len(r["leads"]) / r["eligible"]) if r["eligible"] else 0.0
            ok = fa_h <= fa_per_hour_budget
            key = (ok, warned if ok else -fa_h, -fa_h, -N)
            if best is None or key > best[0]:
                best = (key, thr, N, warned, fa_h)
    return float(best[1]), int(best[2]), float(best[3]), float(best[4])
