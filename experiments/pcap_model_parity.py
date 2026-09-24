"""
Model-level PCAP parity: does the shipped model (backend/artifacts) give the same answers when fed features
extracted from raw packets as when fed the official CICFlowMeter features of the same flows?

Input: CSVs written by `experiments/pcap_parity.py --dump` (matched flows, with pcap_* and csv_* columns).
Flows are grouped into sessions the way backend/app/ingestion.py does (source IP, destination IP, 5-minute
bucket), ordered by start time, and scored with 6-flow windows. The same windows are scored twice, once
with each feature source.

Run: python experiments/pcap_model_parity.py matched_thu_web.csv matched_fri_ddos.csv ...
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "experiments"))
from calibrate_stage_logits import FLOW_FEATURES, STAGES, WorldModel  # noqa: E402

W = 6


def load_model():
    art = ROOT / "backend" / "artifacts"
    cfg = json.load(open(art / "config.json"))
    raw = pickle.load(open(art / "scaler.pkl", "rb"))
    model = WorldModel(22, cfg["hidden_size"], 6, cfg["num_layers"], cfg["lstm_dropout"])
    model.load_state_dict(torch.load(art / "world_model.pt", map_location="cpu", weights_only=True))
    model.eval()
    bias = np.array([cfg["stage_logit_bias"][s] for s in STAGES], np.float32)
    return model, np.asarray(raw["mean"], np.float32), np.asarray(raw["scale"], np.float32), bias


def windows(df, prefix, mean, scale):
    X, lab = [], []
    df = df.assign(bucket=(df["start"] // 300).astype(int)).sort_values("start")
    for _, g in df.groupby(["src", "dst", "bucket"], sort=False):
        f = ((g[[prefix + c for c in FLOW_FEATURES]].values - mean) / scale).astype(np.float32)
        for i in range(W, len(g) + 1):
            X.append(f[i - W:i])
            lab.append(g["label"].iloc[i - 1])
    return np.array(X), np.array(lab)


def main():
    model, mean, scale, bias = load_model()
    rows = []
    for path in sys.argv[1:]:
        df = pd.read_csv(path)
        Xp, lab = windows(df, "pcap_", mean, scale)
        Xc, _ = windows(df, "csv_", mean, scale)
        if len(Xp) == 0:
            print(f"{Path(path).name}: no session has {W} matched flows")
            continue
        with torch.no_grad():
            _, lp, sp = model(torch.tensor(Xp))
            _, lc, sc = model(torch.tensor(Xc))
        pp, pc = torch.sigmoid(lp).numpy(), torch.sigmoid(lc).numpy()
        stp, stc = (sp.numpy() + bias).argmax(1), (sc.numpy() + bias).argmax(1)
        attack = lab != "BENIGN"
        r = dict(capture=Path(path).stem.replace("matched_", ""), windows=len(pp), attack_windows=int(attack.sum()),
                 alert_agreement=float(((pp >= 0.5) == (pc >= 0.5)).mean()),
                 stage_agreement=float((stp == stc).mean()),
                 max_abs_prob_diff=float(np.abs(pp - pc).max()), mean_abs_prob_diff=float(np.abs(pp - pc).mean()),
                 alert_rate_pcap=float((pp >= 0.5).mean()), alert_rate_csv=float((pc >= 0.5).mean()))
        if attack.any():
            r["attack_alert_rate_pcap"] = float((pp[attack] >= 0.5).mean())
            r["attack_alert_rate_csv"] = float((pc[attack] >= 0.5).mean())
        if (~attack).any():
            r["benign_alert_rate_pcap"] = float((pp[~attack] >= 0.5).mean())
            r["benign_alert_rate_csv"] = float((pc[~attack] >= 0.5).mean())
        rows.append(r)
    out = pd.DataFrame(rows)
    pd.set_option("display.width", 250)
    print(out.round(4).to_string(index=False))


if __name__ == "__main__":
    main()
