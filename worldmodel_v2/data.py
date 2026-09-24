"""Dataset construction for the V2 world model (shared by train and evaluate)."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from pipeline_fixed import STAGE2ID, three_way_split  # noqa: E402
from worldmodel_v2.state_features import FLOW_FEATURES, session_states  # noqa: E402

SEED = 42
W = 6


def load_sessions(G):
    """Return {split: {session_id: dict(states, y_risk, y_stage, flows_raw, mal)}} using the same
    session-level split (seed 42) as V1, so both models are evaluated on identical sessions."""
    df = pd.read_csv(REPO_ROOT / "real_flows.csv", low_memory=False)
    df["stage_id"] = df["stage_label"].map(STAGE2ID)
    df = df.sort_values(["session_id", "timestamp"]).reset_index(drop=True)
    tr, va, te = three_way_split(df["session_id"].unique(), val_size=0.1, test_size=0.2, random_state=SEED)
    out = {"train": {}, "val": {}, "test": {}}
    which = {**{s: "train" for s in tr}, **{s: "val" for s in va}, **{s: "test" for s in te}}
    for sid, g in df.groupby("session_id", sort=False):
        flows = g[FLOW_FEATURES].values.astype(np.float64)
        mal = g["is_malicious"].values.astype(np.int64)
        st = g["stage_id"].values.astype(np.int64)
        S, yr, ys, first = session_states(flows, mal, st, G)
        out[which[sid]][int(sid)] = dict(states=S, y_risk=yr, y_stage=ys, flows=flows, mal=mal, stage=st)
    return out


def scaler_from(train_sessions):
    S = np.concatenate([d["states"] for d in train_sessions.values() if len(d["states"])])
    mean, std = S.mean(0), S.std(0)
    std[std == 0] = 1.0
    return mean.astype(np.float32), std.astype(np.float32)


def make_windows(sessions, mean, std, H):
    """Sliding windows S[i:i+W] -> S[i+W:i+W+H]. Sessions shorter than W+H states are skipped."""
    X, F, YR, YS, SID, END, CUR, CURS = [], [], [], [], [], [], [], []
    for sid, d in sessions.items():
        S = (d["states"] - mean) / std
        n = len(S)
        for i in range(n - W - H + 1):
            X.append(S[i:i + W])
            F.append(S[i + W:i + W + H])
            YR.append(d["y_risk"][i + W:i + W + H])
            YS.append(d["y_stage"][i + W:i + W + H])
            CUR.append(d["y_risk"][i + W - 1])
            CURS.append(d["y_stage"][i + W - 1])
            SID.append(sid)
            END.append(i + W - 1)
    return dict(X=np.array(X, np.float32), F=np.array(F, np.float32), yr=np.array(YR), ys=np.array(YS),
                sid=np.array(SID), end=np.array(END), cur=np.array(CUR), curs=np.array(CURS))
