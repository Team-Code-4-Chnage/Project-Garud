"""
NetForecast isolated-lab dataset collector.

Runs on the lab host (the capable machine, not necessarily the one that trains the model). Standard library
only, so it can be copied to the lab machine on its own. Drives VirtualBox (VBoxManage) and Wireshark's
dumpcap; runs each scenario over SSH on the attacker VM.

Per run it: reverts the VMs to a clean snapshot, boots them, starts a packet capture, runs the configured
scenarios in order while recording each one's exact start/stop time, stops the capture, saves the pcap plus
metadata.json and timeline.json, then reverts the VMs again. Flows are extracted later by lab/extract_flows.py
(kept separate so the raw pcap is never modified and this script needs no ML dependencies).

SAFETY: every scenario target must be inside `lab_subnet`. The harness refuses to start otherwise. It only
touches the VMs named in the config. It never scans, exploits, or sends traffic to anything outside the lab.
Use it only on an isolated host-only network of VMs you own. See LAB_SETUP.md.

    python lab/collect_dataset.py --config lab/lab_config.json --out dataset
    python lab/collect_dataset.py --config lab/lab_config.json --dry-run     # validate config, run nothing
"""
import argparse
import ipaddress
import json
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc)


def iso(t):
    return t.replace(microsecond=0).isoformat()


def log(msg):
    print(f"[{iso(now())}] {msg}", flush=True)


class LabError(RuntimeError):
    pass


def run(cmd, timeout=None, check=True):
    """Run a local command (list form). Returns CompletedProcess; raises LabError on failure when check."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise LabError(f"command not found: {cmd[0]} ({e})")
    except subprocess.TimeoutExpired:
        raise LabError(f"timed out: {' '.join(cmd)}")
    if check and p.returncode != 0:
        raise LabError(f"failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr.strip()[:400]}")
    return p


# ---------------------------------------------------------------- validation
def validate(cfg):
    subnet = ipaddress.ip_network(cfg["lab_subnet"], strict=False)
    machine_ips = {cfg["attacker"]["ip"], *[t["ip"] for t in cfg["targets"]]}
    for ip in machine_ips:
        if ipaddress.ip_address(ip) not in subnet:
            raise LabError(f"machine IP {ip} is outside lab_subnet {subnet}; refusing to run")
    target_ips = {t["ip"] for t in cfg["targets"]} | {cfg["attacker"]["ip"]}
    for sc in cfg["scenarios"]:
        t = sc["target"]
        if ipaddress.ip_address(t) not in subnet:
            raise LabError(f"scenario '{sc['id']}' target {t} is outside lab_subnet {subnet}; refusing to run")
        if t not in target_ips:
            raise LabError(f"scenario '{sc['id']}' target {t} is not one of the configured lab machines")
        if "{target}" not in sc["command"]:
            raise LabError(f"scenario '{sc['id']}' command must address the target via {{target}}")
    log(f"config OK: {len(cfg['scenarios'])} scenarios, all targets inside {subnet}")


# ---------------------------------------------------------------- VirtualBox
def vbox(*args):
    return run(["VBoxManage", *args])


def revert_vm(vm, snapshot):
    subprocess.run(["VBoxManage", "controlvm", vm, "poweroff"], capture_output=True, text=True)
    time.sleep(2)
    vbox("snapshot", vm, "restore", snapshot)


def start_vm(vm):
    vbox("startvm", vm, "--type", "headless")


def poweroff_vm(vm):
    subprocess.run(["VBoxManage", "controlvm", vm, "poweroff"], capture_output=True, text=True)


def ping_once(ip):
    flag = "-n" if platform.system() == "Windows" else "-c"
    p = subprocess.run(["ping", flag, "1", ip], capture_output=True, text=True)
    return p.returncode == 0


def wait_reachable(ip, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if ping_once(ip):
            return True
        time.sleep(3)
    return False


# ---------------------------------------------------------------- capture
class Capture:
    def __init__(self, cfg, out_pcap):
        self.cfg = cfg["capture"]
        self.out = out_pcap
        self.proc = None

    def start(self):
        cmd = [self.cfg["dumpcap"], "-i", self.cfg["interface"], "-w", str(self.out), "-q"]
        bpf = self.cfg.get("filter")
        if bpf:
            cmd += ["-f", bpf]
        log(f"starting capture -> {self.out}")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(3)
        if self.proc.poll() is not None:
            raise LabError(f"dumpcap exited immediately: {self.proc.stderr.read()[:400]}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        time.sleep(1)
        if not self.out.exists() or self.out.stat().st_size == 0:
            raise LabError("capture produced no data")
        log(f"capture stopped, {self.out.stat().st_size} bytes")


# ---------------------------------------------------------------- scenarios
def run_scenario(cfg, sc):
    """Run one scenario on the attacker VM over SSH. Returns (start, end) as datetimes."""
    command = sc["command"].replace("{target}", sc["target"])
    where = sc.get("run_on", "attacker")
    if where != "attacker":
        raise LabError(f"scenario '{sc['id']}' run_on={where}; only 'attacker' is supported")
    ssh_target = cfg["attacker"]["ssh"]
    remote = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", ssh_target, command]
    log(f"scenario {sc['id']} ({sc['label']}) -> {sc['target']}")
    start = now()
    subprocess.run(remote, capture_output=True, text=True, timeout=sc["duration_s"] + 120)
    end = now()
    log(f"scenario {sc['id']} done in {(end - start).total_seconds():.0f}s")
    return start, end


# ---------------------------------------------------------------- one run
def do_run(cfg, run_dir, run_id, seed):
    vms = [(cfg["attacker"]["vm"], cfg["attacker"]["snapshot"])] + [(t["vm"], t["snapshot"]) for t in cfg["targets"]]
    ips = [cfg["attacker"]["ip"]] + [t["ip"] for t in cfg["targets"]]

    log(f"--- {run_id}: reverting and booting {len(vms)} VMs")
    for vm, snap in vms:
        revert_vm(vm, snap)
    for vm, _ in vms:
        start_vm(vm)
    for ip in ips:
        if not wait_reachable(ip, cfg.get("boot_wait_seconds", 60)):
            raise LabError(f"VM {ip} not reachable after boot")

    cap = Capture(cfg, run_dir / "traffic.pcap")
    timeline = []
    started = now()
    try:
        cap.start()
        for sc in cfg["scenarios"]:
            time.sleep(cfg.get("gap_seconds", 30))  # quiet gap so each scenario is separable in time
            if not ping_once(sc["target"]):
                raise LabError(f"target {sc['target']} unreachable before scenario {sc['id']}")
            s, e = run_scenario(cfg, sc)
            timeline.append(dict(scenario_id=sc["id"], label=sc["label"], target=sc["target"],
                                 start=iso(s), end=iso(e), command=sc["command"].replace("{target}", sc["target"])))
        time.sleep(cfg.get("gap_seconds", 30))
    finally:
        try:
            cap.stop()
        except LabError as e:
            log(f"WARNING: {e}")
    finished = now()

    (run_dir / "timeline.json").write_text(json.dumps(dict(run_id=run_id, scenarios=timeline), indent=2))
    (run_dir / "metadata.json").write_text(json.dumps(dict(
        run_id=run_id, seed=seed, lab_subnet=cfg["lab_subnet"], capture_interface=cfg["capture"]["interface"],
        attacker=cfg["attacker"]["ip"], targets=[t["ip"] for t in cfg["targets"]],
        started=iso(started), finished=iso(finished), pcap="traffic.pcap",
        scenario_count=len(timeline), host=platform.node(),
        note="Isolated lab capture. Labels are defined by timeline.json, not by inspecting packets."), indent=2))
    for vm, snap in vms:  # leave the lab clean
        revert_vm(vm, snap)
    log(f"{run_id}: wrote {len(timeline)} scenarios to {run_dir}")
    return len(timeline)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="lab/lab_config.json")
    ap.add_argument("--out", default="dataset")
    ap.add_argument("--dry-run", action="store_true", help="validate the config and environment, run nothing")
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text())
    validate(cfg)
    if not args.dry_run:
        for tool in ("VBoxManage", cfg["capture"]["dumpcap"], "ssh"):
            if shutil.which(tool) is None:
                raise LabError(f"required tool not found on PATH: {tool}")
    if args.dry_run:
        log("dry run OK; no VMs touched, no capture started")
        return

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    existing = sorted(int(p.name.split("_")[1]) for p in out.glob("run_*") if p.name.split("_")[1].isdigit())
    next_id = (existing[-1] + 1) if existing else 1
    target_runs = cfg.get("runs", 1)
    completed, failures = 0, 0
    for i in range(target_runs):
        run_id = f"run_{next_id + i:03d}"
        run_dir = out / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            n = do_run(cfg, run_dir, run_id, seed=1000 + next_id + i)
            completed += 1 if n > 0 else 0
        except LabError as e:
            failures += 1
            log(f"ERROR in {run_id}: {e}")
            (run_dir / "ERROR.txt").write_text(str(e))
            for vm in [cfg["attacker"]["vm"]] + [t["vm"] for t in cfg["targets"]]:
                poweroff_vm(vm)
            if failures >= 2:
                log("stopping: two runs failed; check the lab before retrying")
                break
    log(f"done: {completed}/{target_runs} runs collected, {failures} failed. Extract flows with lab/extract_flows.py")


if __name__ == "__main__":
    try:
        main()
    except LabError as e:
        print(f"LAB ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(130)
