"""
Project Garud — Dataset-Grounded Network Attack Traffic Simulator
SIH 2026 PS:26153 (NTRO) | Team: Code 4 Change

Feeds realistic, ground-truth flow records to the backend /ingest endpoint in real-time.

Key Capabilities:
  1. Dataset-Grounded Replay: Samples genuine feature vectors directly from real_flows.csv
     (fallback to calibrated CIC-IDS empirical distributions if CSV is missing).
  2. True Flow-by-Flow Progression: Emits flows sequentially (1 per cadence step)
     allowing the 6-flow sliding window to demonstrate genuine attack forecasting
     and early warning alerts as the window transitions from Benign into Attack.
  3. Multi-Scenario Kill-Chain Presets: Full Kill Chain, Recon Sweep, Brute Force,
     Lateral Spread, Exfiltration, or Pure Benign Baseline.
  4. Rich SOC Dashboard Alignment: Realistic IP pairs, port allocations, and MITRE mapping.

Usage:
  python demo/traffic_simulator.py                          # default: localhost:8000, full_kill_chain
  python demo/traffic_simulator.py --scenario full_kill_chain --speed 0.5
  python demo/traffic_simulator.py --scenario recon_sweep --sessions 2
  python demo/traffic_simulator.py --scenario benign_baseline --speed 0.2
"""
import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import numpy as np
import requests

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]

SRC_IPS = [
    "185.220.101.5",   # External Tor / Adversary Scanner (Frankfurt, Germany)
    "194.26.29.112",   # External Brute Force Origin (Amsterdam, Netherlands)
    "45.33.32.156",    # External C2 Server (Dallas, USA)
    "192.168.0.24",    # Defended Internal Host (Pune NOC, India)
    "10.0.1.45",       # Internal Asset (Pune NOC, India)
]
DST_IPS = [
    "192.168.0.24",    # Defended Primary Host (Pune, India)
    "10.0.1.45",       # Internal Server (Pune, India)
    "45.33.32.156",    # External C2 Server (Dallas, USA)
    "198.51.100.88",   # External Exfiltration Drop (Frankfurt, Germany)
    "104.199.241.202", # External Web/Cloud Endpoint (San Francisco, USA)
]

RECON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 8000, 8080, 8443, 8888, 9000,
]
BENIGN_PORTS = [80, 443, 8080, 53]
AUTH_PORTS = [22, 3389, 445, 80]
LATERAL_PORTS = [445, 135, 3389, 5985, 22]
C2_PORTS = [443, 8443, 53]
EXFIL_PORTS = [443, 8080, 80]

# Empirical fallback profiles based directly on CIC-IDS dataset means
CALIBRATED_PROFILES_MEAN = {
    "Benign":          [11400000, 7, 7, 65, 300, 1200000, 67000, 1150000, 2500000, 2260000, 1570000, 0.04, 0.3, 0.06, 0.01, 0.26, 0.1, 0.7, 200, 60, 8192, 0.0],
    "Reconnaissance":  [ 2070000, 4, 2, 60,  40,   15000,   120,    3000,    2000,    4000,    8000, 0.45, 0.21, 0.00, 0.05, 0.79, 0.0, 0.2,  80, 20, 1024, 0.0],
    "Initial Access":  [ 6530000, 11, 8, 150, 120,   18000,    40,   20000,   15000,   25000,   30000, 0.12, 0.08, 0.05, 0.02, 0.92, 0.0, 0.8, 300, 40, 8192, 1.0],
    "Lateral Movement":[78400000, 830, 600, 180, 200, 10000,    35,   30000,   20000,   35000,   40000, 0.20, 0.83, 0.10, 0.05, 0.17, 0.0, 1.5, 350, 50, 16384, 1.0],
    "C2":              [36350000, 5, 4, 100,  90,    3000,    15,   90000,    5000,   95000,   95000, 0.00, 0.60, 0.00, 0.00, 0.28, 0.0, 1.1, 200, 20, 8192, 0.0],
    "Exfiltration":    [119000000, 2800, 2000, 200, 1200, 80000, 25, 40000,   30000,   45000,   42000, 0.00, 1.00, 0.00, 0.00, 0.00, 0.0, 0.3, 1100, 30, 65535, 2.0],
}


class FlowPool:
    """Manages ground-truth flow samples for each MITRE ATT&CK stage."""

    def __init__(self, csv_path: Path | None = None):
        self.pools: dict[str, list[dict]] = {
            "Benign": [],
            "Reconnaissance": [],
            "Initial Access": [],
            "Lateral Movement": [],
            "C2": [],
            "Exfiltration": [],
        }
        self.loaded_from_csv = False

        resolved_path = None
        candidates = [
            csv_path,
            Path("real_flows.csv"),
            Path(__file__).resolve().parent.parent / "real_flows.csv",
            Path("data/real_flows.csv"),
        ]
        for c in candidates:
            if c and Path(c).exists():
                resolved_path = Path(c)
                break

        if resolved_path:
            try:
                import pandas as pd
                print(f"Loading ground-truth flows from {resolved_path.name}...")
                cols_to_read = FLOW_FEATURES + ["stage_label"]
                df = pd.read_csv(resolved_path, usecols=cols_to_read, low_memory=False)
                for stage in self.pools:
                    sub = df[df["stage_label"] == stage]
                    if len(sub) > 0:
                        records = sub[FLOW_FEATURES].to_dict(orient="records")
                        self.pools[stage] = records
                        print(f"  Pool [{stage:<16}]: {len(records):>6} real flows loaded")
                self.loaded_from_csv = True
            except Exception as e:
                print(f"  Warning: Could not read {resolved_path}: {e}")

        if not self.loaded_from_csv:
            print("Notice: real_flows.csv not found; using calibrated empirical distributions.")

    def get_flow(self, stage: str) -> dict:
        """Sample a flow from the ground-truth pool, or generate from calibrated distribution."""
        pool = self.pools.get(stage, [])
        if pool:
            # Pick a real flow and add slight jitter so values are not exact duplicates
            base = random.choice(pool).copy()
            for k in ["flow_duration", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean"]:
                if k in base:
                    base[k] = max(0.0, float(base[k]) * (1.0 + random.uniform(-0.05, 0.05)))
            return base

        # Fallback to calibrated profile
        means = CALIBRATED_PROFILES_MEAN.get(stage, CALIBRATED_PROFILES_MEAN["Benign"])
        flow = {}
        for feat, mean in zip(FLOW_FEATURES, means):
            std = max(1.0, mean * 0.15) if mean > 0 else 0.05
            val = max(0.0, np.random.normal(mean, std))
            flow[feat] = round(float(val), 4)
        return flow


def get_ports_for_stage(stage: str, step_idx: int) -> tuple[int, int, str]:
    """Returns (src_port, dst_port, protocol) suitable for the MITRE stage."""
    src_port = random.randint(49152, 65535)
    if stage == "Reconnaissance":
        dst_port = RECON_PORTS[step_idx % len(RECON_PORTS)]
        protocol = "TCP"
    elif stage == "Initial Access":
        dst_port = AUTH_PORTS[step_idx % len(AUTH_PORTS)]
        protocol = "TCP"
    elif stage == "Lateral Movement":
        dst_port = LATERAL_PORTS[step_idx % len(LATERAL_PORTS)]
        protocol = "TCP"
    elif stage == "C2":
        dst_port = random.choice(C2_PORTS)
        protocol = "UDP" if dst_port == 53 else "TCP"
    elif stage == "Exfiltration":
        dst_port = random.choice(EXFIL_PORTS)
        protocol = "TCP"
    else:  # Benign
        dst_port = random.choice(BENIGN_PORTS)
        protocol = "UDP" if dst_port == 53 else "TCP"
    return src_port, dst_port, protocol


def build_scenario_stages(scenario: str) -> list[str]:
    """Defines the sequential stage progression for the selected scenario."""
    if scenario == "benign_baseline":
        return ["Benign"] * 24
    elif scenario == "recon_sweep":
        return ["Benign"] * 6 + ["Reconnaissance"] * 14
    elif scenario == "brute_force":
        return ["Benign"] * 6 + ["Reconnaissance"] * 4 + ["Initial Access"] * 12
    elif scenario == "lateral_spread":
        return ["Benign"] * 6 + ["Reconnaissance"] * 3 + ["Initial Access"] * 3 + ["Lateral Movement"] * 10
    elif scenario == "exfiltration":
        return ["Benign"] * 6 + ["C2"] * 4 + ["Exfiltration"] * 12
    else:  # full_kill_chain (The standard APT progression)
        return (
            ["Benign"] * 6 +              # Fill window cleanly: zero false alarms
            ["Reconnaissance"] * 6 +      # Port sweeps: early warning escalates
            ["Initial Access"] * 5 +      # Web exploit / credential brute force
            ["Lateral Movement"] * 5 +    # Pivot across internal hosts
            ["C2"] * 4 +                  # Periodic beaconing heartbeat
            ["Exfiltration"] * 4          # Bulk egress transfer
        )


def run_simulator(api_url: str, speed: float, session_count: int, scenario: str, flows_file: str | None):
    pool = FlowPool(Path(flows_file) if flows_file else None)

    print(f"\n{'='*75}")
    print("  PROJECT GARUD — Dataset-Grounded Kill-Chain Streamer")
    print(f"  Target API:       {api_url}")
    print(f"  Preset Scenario:  {scenario.upper()}")
    print(f"  Concurrent Ssns:  {session_count}")
    print(f"  Cadence Speed:    {speed}s per flow")
    print(f"  Flow Engine:      {'Real Flow Pool (real_flows.csv)' if pool.loaded_from_csv else 'Calibrated Profiles'}")
    print(f"{'='*75}\n")

    # Set backend to simulated mode so it accepts simulation traffic
    try:
        requests.post(f"{api_url}/system/mode", json={"mode": "simulated"}, timeout=5)
    except Exception:
        pass

    stage_plan = build_scenario_stages(scenario)
    total_steps = len(stage_plan)

    sessions = []
    for i in range(session_count):
        src = SRC_IPS[i % len(SRC_IPS)]
        dst = DST_IPS[i % len(DST_IPS)]
        sessions.append({
            "session_idx": i + 1,
            "src_ip": src,
            "dst_ip": dst,
            "label": f"SSN-{i+1:02d}",
        })

    total_flows_sent = 0
    total_alerts = 0
    benign_false_alarms = 0
    stage_alert_counts: dict[str, int] = {}

    start_time = time.time()
    api_url = api_url.replace("localhost", "127.0.0.1")
    http_session = requests.Session()
    try:
        for step_idx in range(total_steps):
            current_stage = stage_plan[step_idx]

            for session in sessions:
                flow = pool.get_flow(current_stage)
                sport, dport, proto = get_ports_for_stage(current_stage, step_idx)

                # Route IPs based on MITRE kill-chain progression:
                if current_stage == "Reconnaissance":
                    flow_src = "185.220.101.5"      # Frankfurt Adversary Scanner
                    flow_dst = "192.168.0.24"       # Pune Defender NOC
                elif current_stage == "Initial Access":
                    flow_src = "194.26.29.112"      # Amsterdam Brute Force Origin
                    flow_dst = "192.168.0.24"       # Pune Defender NOC
                elif current_stage == "Lateral Movement":
                    flow_src = "192.168.0.24"       # Compromised Host in Pune
                    flow_dst = "10.0.1.45"          # Internal Database Target in Pune
                elif current_stage == "C2":
                    flow_src = "192.168.0.24"       # Compromised Host
                    flow_dst = "45.33.32.156"       # Dallas C2 Controller
                elif current_stage == "Exfiltration":
                    flow_src = "192.168.0.24"       # Data Egress Host
                    flow_dst = "198.51.100.88"      # Zurich / Frankfurt Drop Server
                else:  # Benign nominal traffic
                    flow_src = "192.168.0.24"
                    flow_dst = "104.199.241.202" if (step_idx % 2 == 0) else "34.54.84.110"

                flow["src_ip"] = flow_src
                flow["dst_ip"] = flow_dst
                flow["src_port"] = sport
                flow["dst_port"] = dport
                flow["protocol"] = proto
                flow["timestamp"] = datetime.now(timezone.utc).isoformat()
                flow["source"] = "simulated"
                flow["stage"] = current_stage

                try:
                    resp = http_session.post(f"{api_url}/ingest", json=flow, timeout=8)
                except requests.exceptions.ConnectionError:
                    print(f"ERROR: Cannot connect to {api_url} — is backend running?")
                    sys.exit(1)

                total_flows_sent += 1

                if resp.status_code == 200:
                    res = resp.json()
                    pred = res.get("prediction")
                    alert = res.get("alert")
                    buf_sz = res.get("buffer_size", 0)

                    elapsed = int(time.time() - start_time)
                    ts_str = f"{elapsed // 60:02d}:{elapsed % 60:02d}"

                    log_line = f"[{ts_str}] [{session['label']}: {session['src_ip']} -> {session['dst_ip']}:{dport:<5}] "
                    log_line += f"Stage: {current_stage:<16} | "

                    if pred:
                        prob = pred["infiltration_probability"]
                        pred_stg = pred["predicted_stage"]
                        log_line += f"P(inf)={prob:.4f} | Pred: {pred_stg:<16}"

                        if alert:
                            total_alerts += 1
                            sev = alert["severity"].upper()
                            stage_alert_counts[current_stage] = stage_alert_counts.get(current_stage, 0) + 1
                            if current_stage == "Benign":
                                benign_false_alarms += 1
                                log_line += f" | ⚠️  UNEXPECTED ALERT: [{sev}]"
                            else:
                                log_line += f" | 🚨 ALERT: [{sev}]"
                        else:
                            if prob > 0.35 and current_stage != "Benign":
                                log_line += " | ⚡ EARLY WARNING (Rising Risk)"
                            else:
                                log_line += " | 🟢 Normal"
                    else:
                        log_line += f"Buffering ({buf_sz}/6 flows)"

                    print(log_line, flush=True)

            time.sleep(speed)

    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")

    print(f"\n{'='*75}")
    print("  SIMULATION COMPLETE — METRICS SUMMARY")
    print(f"  Total Telemetry Flows Sent: {total_flows_sent}")
    print(f"  Total Alerts Generated:     {total_alerts}")
    print(f"  False Alarms on Benign:     {benign_false_alarms} (Target: 0)")
    print("  Alerts by Attack Stage:")
    for stg, cnt in stage_alert_counts.items():
        if stg != "Benign":
            print(f"    - {stg:<18}: {cnt} alerts")
    print(f"{'='*75}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Dataset-Grounded Network Attack Traffic Simulator for Project Garud"
    )
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="Backend API URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--speed", type=float, default=0.5, help="Seconds between flow batches (default: 0.5s)")
    parser.add_argument("--sessions", type=int, default=1, help="Number of concurrent sessions (default: 1)")
    parser.add_argument(
        "--scenario",
        default="full_kill_chain",
        choices=["full_kill_chain", "recon_sweep", "brute_force", "lateral_spread", "exfiltration", "benign_baseline"],
        help="Scenario progression preset"
    )
    parser.add_argument("--flows-file", default="real_flows.csv", help="Path to real_flows.csv dataset")
    args = parser.parse_args()

    # Health check
    try:
        resp = requests.get(f"{args.api}/health", timeout=5)
        health = resp.json()
        if not health.get("model_loaded"):
            print("ERROR: Backend reports model is NOT loaded!", flush=True)
            sys.exit(1)
        print(f"Backend connected: model loaded on {health.get('device', 'cpu')} (Mode: {health.get('system_mode', 'live')})")
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Cannot connect to backend at {args.api}. Start backend first!")
        sys.exit(1)

    run_simulator(args.api, args.speed, args.sessions, args.scenario, args.flows_file)


if __name__ == "__main__":
    main()
