"""
Download the CIC-IDS2017 labelled flow files (with Source/Destination IP, ports,
protocol and timestamp) from the Hugging Face mirror Ariasyah/cic-ids-2017,
folder traffic_labels/. Total about 300 MB. Resumable, verifies final size.

The MachineLearningCSV files used for V1/V2 training drop those columns; these
files are the same CICFlowMeter flows with the network context kept.

Run: python data/fetch_cic2017_labelled.py --out data/cic2017_labelled
"""
import argparse
import json
import os
import urllib.request

REPO = "Ariasyah/cic-ids-2017"


def get(url, rng=None):
    h = {"User-Agent": "netforecast"}
    if rng:
        h["Range"] = rng
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=120).read()


def download(url, out, total, step=4_000_000):
    pos = os.path.getsize(out) if os.path.exists(out) else 0
    if pos > total:
        pos = 0
        open(out, "wb").close()
    with open(out, "ab") as f:
        while pos < total:
            end = min(pos + step, total) - 1
            b = None
            for _ in range(6):
                try:
                    b = get(url, f"bytes={pos}-{end}")
                    break
                except Exception as e:  # noqa: BLE001 - network flakiness, retry
                    print("retry", os.path.basename(out), pos, e)
            if not b:
                raise SystemExit(f"failed at {pos}")
            f.write(b)
            pos += len(b)
    assert os.path.getsize(out) == total, "size mismatch"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/cic2017_labelled")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    tree = json.loads(get(f"https://huggingface.co/api/datasets/{REPO}/tree/main/traffic_labels"))
    for item in tree:
        name = item["path"].split("/")[-1].replace(".pcap_ISCX.csv.parquet", ".parquet")
        dest = os.path.join(args.out, name)
        print("fetch", name, item["size"])
        download(f"https://huggingface.co/datasets/{REPO}/resolve/main/{item['path']}", dest, item["size"])
    print("done")


if __name__ == "__main__":
    main()
