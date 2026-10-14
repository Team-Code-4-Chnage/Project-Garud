"""
Reset the lab to a clean state: power off every configured VM and restore its clean snapshot.

Use it before a collection session, or after an interrupted run, so no VM is left powered on or dirty.
Standard library only.

    python lab/reset_lab.py --config lab/lab_config.json
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def vms(cfg):
    return [(cfg["attacker"]["vm"], cfg["attacker"]["snapshot"])] + [(t["vm"], t["snapshot"]) for t in cfg["targets"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="lab/lab_config.json")
    args = ap.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    for vm, snap in vms(cfg):
        print(f"resetting {vm} -> snapshot '{snap}'")
        subprocess.run(["VBoxManage", "controlvm", vm, "poweroff"], capture_output=True, text=True)
        time.sleep(2)
        p = subprocess.run(["VBoxManage", "snapshot", vm, "restore", snap], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"  WARNING: could not restore {vm}: {p.stderr.strip()[:200]}", file=sys.stderr)
    print("lab reset complete")


if __name__ == "__main__":
    main()
