"""
End-to-end scenario: replay a window of real CIC-IDS2017 flows through the running API and read back what
the network-state world model says minute by minute.

The flows are the official labelled CICFlowMeter records converted to the 22 model features exactly as
data/preprocess_cicids.py does; experiments/pcap_parity.py shows the PCAP extractor produces the same
features from the packets (95-100% agreement). Replaying the flow records is used because a continuous
multi-minute raw capture of these windows is several GB.

  export (needs pandas + pyarrow):
    python experiments/scenario_replay.py export --labels Fri-DDos.parquet Fri-PortScan.parquet
        --start "2017-07-07 18:35" --end "2017-07-07 19:05" --out fri_ddos_scenario.csv
  replay (backend environment; uses a temporary database):
    python experiments/scenario_replay.py replay --csv fri_ddos_scenario.csv
"""
import argparse
import io
import os
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_bytes_s",
    "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "urg_flag_cnt", "down_up_ratio",
    "pkt_size_avg", "ttl_variance", "tcp_win_size", "retransmit_cnt",
]


def export(args):
    sys.path.insert(0, str(ROOT / "experiments"))
    from pcap_parity import training_features
    d = pd.concat([pd.read_parquet(p) for p in args.labels]).dropna(subset=["Timestamp"])
    d = d[(d["Timestamp"] >= args.start) & (d["Timestamp"] < args.end)].sort_values("Timestamp")
    feats = pd.DataFrame([training_features(r) for _, r in d.iterrows()])
    out = pd.concat([feats.reset_index(drop=True), pd.DataFrame({
        "src_ip": d["Source IP"].values, "dst_ip": d["Destination IP"].values,
        "src_port": d["Source Port"].astype(int).values, "dst_port": d["Destination Port"].astype(int).values,
        "protocol": d["Protocol"].astype(int).values,
        "timestamp": d["Timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S").values,
        "label": d["Label"].astype(str).str.replace(r"[^ -~]", "-", regex=True).values})], axis=1)
    out.to_csv(args.out, index=False)
    print(f"wrote {len(out)} flows to {args.out}")


def replay(args):
    os.environ["DB_DIR"] = tempfile.mkdtemp(prefix="netforecast_scenario_")
    sys.path.insert(0, str(ROOT / "backend"))
    from fastapi.testclient import TestClient

    from app.main import app
    from app.model_loader import artifacts
    from app.network_state import tracker

    if not artifacts.is_loaded:
        artifacts.load()
    tracker.reset()
    df = pd.read_csv(args.csv)
    truth = df.assign(minute=df["timestamp"].str[:16], attack=(df["label"] != "BENIGN").astype(int))
    truth = truth.groupby("minute").agg(flows=("attack", "size"), attack_flows=("attack", "sum"))
    t0 = time.time()
    with TestClient(app) as client:
        for minute, chunk in df.groupby(df["timestamp"].str[:16], sort=True):  # one upload per minute
            buf = io.StringIO()
            chunk.drop(columns=["label"]).to_csv(buf, index=False)
            r = client.post("/ingest/csv", files={"file": ("m.csv", buf.getvalue().encode(), "text/csv")})
            assert r.status_code == 200, r.text
        res = client.get("/network/forecast", params={"source": "csv_upload"}).json()
    print(f"replayed {len(df)} flows in {time.time() - t0:.0f} s")
    rows = []
    for i, m in enumerate(res["minutes"]):
        key = m[:16]
        tr = truth.loc[key] if key in truth.index else None
        rows.append(dict(minute=m[11:16], flows=int(tr["flows"]) if tr is not None else 0,
                         attack_flows=int(tr["attack_flows"]) if tr is not None else 0,
                         risk_next_4min=None if res["risk_score"][i] is None else round(res["risk_score"][i], 3),
                         alert=res["alert"][i]))
    tl = pd.DataFrame(rows)
    print(tl.to_string(index=False))
    onset = tl.index[tl["attack_flows"] > 0]
    first_alert = tl.index[tl["alert"]]
    if len(onset):
        o = onset[0]
        pre = [i for i in first_alert if i < o]
        post = [i for i in first_alert if i >= o]
        print(f"\nattack onset {tl.minute[o]}; alerts before onset at: {[tl.minute[i] for i in pre]}; "
              f"first alert at or after onset: {tl.minute[post[0]] if post else None}")
    last = res["forecast"]
    print("forecast from", res["current"]["minute"][11:16], [(s["minute"][11:16], round(s["risk"], 3),
                                                              s["behaviours"][0]["behaviour"]) for s in last])
    print("top drivers:", [(e["feature"], round(e["contribution"], 3)) for e in res["explanation"][:5]])


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--labels", nargs="+", required=True)
    e.add_argument("--start", required=True)
    e.add_argument("--end", required=True)
    e.add_argument("--out", required=True)
    r = sub.add_parser("replay")
    r.add_argument("--csv", required=True)
    args = ap.parse_args()
    export(args) if args.cmd == "export" else replay(args)


if __name__ == "__main__":
    main()
