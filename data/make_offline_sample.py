"""
Builds the two real-data files in data/samples/ for trying the offline analysis.

1. cic2017_tuesday_ssh_patator_heldout.csv.gz
   CIC-IDS2017 labelled flows (data/cic2017_labelled/Tuesday-WorkingHours.parquet), Tuesday 2017-07-04
   from 17:59 to 19:00, every flow, unchanged. This stretch lies inside the held-out last 25% of that day
   for both served models (network-state model and flow classifier), so neither has seen these minutes.
   It holds the end of the SSH-Patator attack (1,097 flows, until about 18:13) followed by benign traffic.
   Real addresses, minute timestamps (day-first), original CICFlowMeter column names, real labels. Columns
   the converter does not use are left out to keep the file small.

2. cic2018_infiltration_sample.csv
   CSE-CIC-IDS2018 Wednesday-28-02-2018.csv (data/raw_cicids2018), 09:40 to 11:40, every 30th flow, original
   CICFlowMeter columns. The dataset has no addresses, so this file exercises the conversion of a table
   without them. Sub-sampling changes the per-minute counts, and the infiltration flows are hard to
   separate: it is a difficult, out-of-domain case, not a showcase.

Run: python data/make_offline_sample.py
"""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "samples"

KEEP_2017 = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp",
             "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
             "Total Length of Bwd Packets", "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Bytes/s",
             "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Mean", "Bwd IAT Mean", "SYN Flag Count",
             "ACK Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "URG Flag Count",
             "Down/Up Ratio", "Average Packet Size", "Fwd Header Length", "Bwd Header Length",
             "Init_Win_bytes_forward", "Subflow Fwd Packets", "Label"]


def sample_2017():
    src = ROOT / "data/cic2017_labelled/Tuesday-WorkingHours.parquet"
    d = pd.read_parquet(src)
    w = d[(d["Timestamp"] >= "2017-07-04 17:59") & (d["Timestamp"] < "2017-07-04 19:00")]
    w = w.sort_values("Timestamp", kind="stable")[KEEP_2017].copy()
    w["Timestamp"] = w["Timestamp"].dt.strftime("%d/%m/%Y %H:%M")
    out = OUT / "cic2017_tuesday_ssh_patator_heldout.csv.gz"
    w.to_csv(out, index=False, compression="gzip")
    print(out.name, len(w), w["Label"].value_counts().to_dict())


def sample_2018(step=30):
    src = ROOT / "data/raw_cicids2018/Wednesday-28-02-2018.csv"
    df = pd.read_csv(src, low_memory=False)
    df = df[df["Timestamp"] != "Timestamp"]
    t = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df[(t >= "2018-02-28 09:40:00") & (t < "2018-02-28 11:40:00")].assign(_t=t).sort_values("_t", kind="stable")
    sample = df.drop(columns="_t").iloc[::step]
    out = OUT / "cic2018_infiltration_sample.csv"
    sample.to_csv(out, index=False)
    print(out.name, len(sample), sample["Label"].value_counts().to_dict())


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    sample_2017()
    sample_2018()
