"""
Traffic Simulator — generates realistic CIC-IDS-style flow records and
feeds them to the backend /ingest endpoint in real-time.

This is NOT an attack tool. It generates feature vectors (flow statistics),
not actual malicious packets. It simulates how the dashboard would look
during a real attack by walking through the MITRE ATT&CK kill chain:
  Benign → Reconnaissance → Initial Access → Lateral Movement → C2 → Exfiltration

Usage:
  python traffic_simulator.py                          # default: localhost:8000
  python traffic_simulator.py --api http://render-url  # remote backend
  python traffic_simulator.py --speed 0.5              # faster (0.5s between flows)
  python traffic_simulator.py --sessions 5             # 5 concurrent sessions
"""
import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

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
    "10.0.1.5", "10.0.1.12", "10.0.1.23", "10.0.1.45", "10.0.1.78",
    "192.168.1.100", "192.168.1.150", "172.16.0.10", "172.16.0.25",
]
DST_IPS = [
    "10.0.2.1", "10.0.2.5", "10.0.2.20", "10.0.2.50", "10.0.2.100",
    "203.0.113.50", "198.51.100.10", "192.0.2.1",
]

STAGE_PROFILES = {
    "Benign": {
        "flow_duration": (50000, 30000),
        "tot_fwd_pkts": (10, 8),
        "tot_bwd_pkts": (8, 6),
        "fwd_pkt_len_mean": (200, 150),
        "bwd_pkt_len_mean": (180, 120),
        "flow_bytes_s": (5000, 4000),
        "flow_pkts_s": (20, 15),
        "flow_iat_mean": (50000, 40000),
        "flow_iat_std": (30000, 25000),
        "fwd_iat_mean": (60000, 50000),
        "bwd_iat_mean": (70000, 55000),
        "syn_flag_cnt": (1, 0.5),
        "ack_flag_cnt": (5, 3),
        "fin_flag_cnt": (1, 0.5),
        "rst_flag_cnt": (0, 0.2),
        "psh_flag_cnt": (2, 1.5),
        "urg_flag_cnt": (0, 0.1),
        "down_up_ratio": (1.0, 0.3),
        "pkt_size_avg": (400, 200),
        "ttl_variance": (2, 1),
        "tcp_win_size": (65535, 10000),
        "retransmit_cnt": (1, 1),
    },
    "Reconnaissance": {
        "flow_duration": (1000, 500),
        "tot_fwd_pkts": (3, 2),
        "tot_bwd_pkts": (1, 1),
        "fwd_pkt_len_mean": (60, 20),
        "bwd_pkt_len_mean": (40, 15),
        "flow_bytes_s": (2000, 1500),
        "flow_pkts_s": (80, 40),
        "flow_iat_mean": (1000, 800),
        "flow_iat_std": (500, 400),
        "fwd_iat_mean": (800, 600),
        "bwd_iat_mean": (1200, 900),
        "syn_flag_cnt": (8, 3),
        "ack_flag_cnt": (1, 1),
        "fin_flag_cnt": (0, 0.3),
        "rst_flag_cnt": (5, 3),
        "psh_flag_cnt": (0, 0.2),
        "urg_flag_cnt": (0, 0.1),
        "down_up_ratio": (0.3, 0.2),
        "pkt_size_avg": (60, 20),
        "ttl_variance": (5, 3),
        "tcp_win_size": (1024, 500),
        "retransmit_cnt": (0, 0.5),
    },
    "Initial Access": {
        "flow_duration": (30000, 20000),
        "tot_fwd_pkts": (50, 30),
        "tot_bwd_pkts": (20, 15),
        "fwd_pkt_len_mean": (300, 200),
        "bwd_pkt_len_mean": (100, 80),
        "flow_bytes_s": (8000, 5000),
        "flow_pkts_s": (40, 25),
        "flow_iat_mean": (5000, 3000),
        "flow_iat_std": (8000, 6000),
        "fwd_iat_mean": (3000, 2000),
        "bwd_iat_mean": (10000, 8000),
        "syn_flag_cnt": (3, 2),
        "ack_flag_cnt": (15, 10),
        "fin_flag_cnt": (1, 1),
        "rst_flag_cnt": (2, 2),
        "psh_flag_cnt": (8, 4),
        "urg_flag_cnt": (0, 0.2),
        "down_up_ratio": (2.5, 1.5),
        "pkt_size_avg": (350, 200),
        "ttl_variance": (3, 2),
        "tcp_win_size": (32768, 15000),
        "retransmit_cnt": (5, 3),
    },
    "Lateral Movement": {
        "flow_duration": (120000, 80000),
        "tot_fwd_pkts": (30, 20),
        "tot_bwd_pkts": (25, 15),
        "fwd_pkt_len_mean": (500, 300),
        "bwd_pkt_len_mean": (400, 250),
        "flow_bytes_s": (12000, 8000),
        "flow_pkts_s": (15, 10),
        "flow_iat_mean": (40000, 30000),
        "flow_iat_std": (20000, 15000),
        "fwd_iat_mean": (35000, 25000),
        "bwd_iat_mean": (45000, 30000),
        "syn_flag_cnt": (2, 1),
        "ack_flag_cnt": (20, 12),
        "fin_flag_cnt": (1, 1),
        "rst_flag_cnt": (1, 1),
        "psh_flag_cnt": (5, 3),
        "urg_flag_cnt": (0, 0.1),
        "down_up_ratio": (3.0, 1.5),
        "pkt_size_avg": (450, 250),
        "ttl_variance": (4, 2),
        "tcp_win_size": (49152, 15000),
        "retransmit_cnt": (2, 2),
    },
    "C2": {
        "flow_duration": (300000, 200000),
        "tot_fwd_pkts": (8, 5),
        "tot_bwd_pkts": (6, 4),
        "fwd_pkt_len_mean": (150, 100),
        "bwd_pkt_len_mean": (200, 150),
        "flow_bytes_s": (1000, 800),
        "flow_pkts_s": (5, 3),
        "flow_iat_mean": (120000, 80000),
        "flow_iat_std": (5000, 3000),
        "fwd_iat_mean": (100000, 70000),
        "bwd_iat_mean": (130000, 90000),
        "syn_flag_cnt": (1, 0.5),
        "ack_flag_cnt": (12, 6),
        "fin_flag_cnt": (0, 0.3),
        "rst_flag_cnt": (0, 0.2),
        "psh_flag_cnt": (3, 2),
        "urg_flag_cnt": (0, 0.1),
        "down_up_ratio": (1.2, 0.5),
        "pkt_size_avg": (180, 100),
        "ttl_variance": (1, 0.5),
        "tcp_win_size": (16384, 8000),
        "retransmit_cnt": (1, 1),
    },
    "Exfiltration": {
        "flow_duration": (60000, 40000),
        "tot_fwd_pkts": (5, 3),
        "tot_bwd_pkts": (3, 2),
        "fwd_pkt_len_mean": (100, 80),
        "bwd_pkt_len_mean": (1200, 400),
        "flow_bytes_s": (50000, 30000),
        "flow_pkts_s": (10, 5),
        "flow_iat_mean": (30000, 20000),
        "flow_iat_std": (15000, 10000),
        "fwd_iat_mean": (25000, 18000),
        "bwd_iat_mean": (20000, 15000),
        "syn_flag_cnt": (1, 0.5),
        "ack_flag_cnt": (8, 5),
        "fin_flag_cnt": (1, 0.5),
        "rst_flag_cnt": (0, 0.3),
        "psh_flag_cnt": (6, 3),
        "urg_flag_cnt": (1, 0.5),
        "down_up_ratio": (0.2, 0.1),
        "pkt_size_avg": (1100, 400),
        "ttl_variance": (2, 1),
        "tcp_win_size": (65535, 10000),
        "retransmit_cnt": (3, 2),
    },
}


def generate_flow(stage: str) -> dict:
    """Generate a single flow record based on the stage profile."""
    profile = STAGE_PROFILES[stage]
    flow = {}
    for feat in FLOW_FEATURES:
        mean, std = profile[feat]
        value = max(0, np.random.normal(mean, std))
        flow[feat] = round(float(value), 4)
    return flow


def run_attack_scenario(api_url: str, speed: float, session_count: int, scenario: str = "full_kill_chain"):
    """
    Run a multi-session attack scenario:
    - Generates traffic according to selected scenario preset
    - Walks through relevant MITRE ATT&CK stages
    """
    print(f"\n{'='*70}", flush=True)
    print("  PROJECT GARUD — Network Attack Traffic Simulator", flush=True)
    print(f"  Target API: {api_url}", flush=True)
    print(f"  Preset Scenario: {scenario.upper()}", flush=True)
    print(f"  Concurrent Sessions: {session_count}", flush=True)
    print(f"  Cadence Speed: {speed}s between flow batches", flush=True)
    print(f"{'='*70}\n", flush=True)

    sessions = []
    for i in range(session_count):
        src = random.choice(SRC_IPS)
        dst = random.choice(DST_IPS)

        if scenario == "benign_baseline":
            stages = ["Benign"] * random.randint(20, 40)
            label = "BENIGN"
        elif scenario == "recon_sweep":
            stages = (
                ["Benign"] * random.randint(2, 4) +
                ["Reconnaissance"] * random.randint(12, 20)
            )
            label = "RECON"
        elif scenario == "brute_force":
            stages = (
                ["Benign"] * random.randint(2, 3) +
                ["Reconnaissance"] * random.randint(2, 3) +
                ["Initial Access"] * random.randint(12, 22)
            )
            label = "BRUTE"
        elif scenario == "lateral_spread":
            stages = (
                ["Benign"] * random.randint(2, 3) +
                ["Reconnaissance"] * random.randint(2, 3) +
                ["Initial Access"] * random.randint(2, 3) +
                ["Lateral Movement"] * random.randint(10, 18)
            )
            label = "LATERAL"
        elif scenario == "exfiltration":
            stages = (
                ["Benign"] * random.randint(2, 3) +
                ["C2"] * random.randint(2, 3) +
                ["Exfiltration"] * random.randint(12, 20)
            )
            label = "EXFIL"
        else:  # full_kill_chain
            if i < max(1, session_count // 2):
                stages = (
                    ["Benign"] * random.randint(3, 5) +
                    ["Reconnaissance"] * random.randint(3, 5) +
                    ["Initial Access"] * random.randint(2, 4) +
                    ["Lateral Movement"] * random.randint(2, 3) +
                    ["C2"] * random.randint(2, 4) +
                    ["Exfiltration"] * random.randint(2, 3)
                )
                label = "KILLCHAIN"
            else:
                stages = ["Benign"] * random.randint(15, 30)
                label = "BENIGN"

        sessions.append({
            "src_ip": src,
            "dst_ip": dst,
            "stages": stages,
            "current_step": 0,
            "label": label,
        })

    max_steps = max(len(s["stages"]) for s in sessions)
    total_sent = 0
    total_alerts = 0

    try:
        for _step in range(max_steps):
            for session in sessions:
                if session["current_step"] >= len(session["stages"]):
                    continue

                stage = session["stages"][session["current_step"]]
                flow = generate_flow(stage)
                flow["src_ip"] = session["src_ip"]
                flow["dst_ip"] = session["dst_ip"]
                flow["timestamp"] = datetime.now(timezone.utc).isoformat()
                flow["source"] = "simulated"

                try:
                    resp = requests.post(
                        f"{api_url}/ingest",
                        json=flow,
                        timeout=10,
                    )
                    total_sent += 1

                    if resp.status_code == 200:
                        result = resp.json()
                        pred = result.get("prediction")
                        alert = result.get("alert")

                        status = f"[{session['label']:>9}] {session['src_ip']:>15} → {session['dst_ip']:>15} | "
                        status += f"Stage: {stage:<18} | "

                        if pred:
                            prob = pred["infiltration_probability"]
                            pred_stage = pred["predicted_stage"]
                            status += f"P(inf)={prob:.3f} | Pred: {pred_stage}"
                            if alert:
                                total_alerts += 1
                                status += f" | 🚨 ALERT: {alert['severity'].upper()}"
                        else:
                            buf_size = result.get("buffer_size", "?")
                            status += f"Buffering ({buf_size}/{6})"

                        print(status, flush=True)
                    else:
                        print(f"  ERROR: HTTP {resp.status_code} — {resp.text[:100]}", flush=True)

                except requests.exceptions.ConnectionError:
                    print(f"  ERROR: Cannot connect to {api_url} — is the backend running?", flush=True)
                    sys.exit(1)
                except requests.exceptions.Timeout:
                    print("  WARNING: Ingestion request timed out", flush=True)

                session["current_step"] += 1

            time.sleep(speed)

    except KeyboardInterrupt:
        print("\n\nSimulation stopped by operator.", flush=True)

    print(f"\n{'='*70}", flush=True)
    print("  Simulation batch complete", flush=True)
    print(f"  Total telemetry flows sent: {total_sent}", flush=True)
    print(f"  Total alerts triggered: {total_alerts}", flush=True)
    print(f"{'='*70}\n", flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="Traffic simulator for Network Attack Forecasting demo"
    )
    parser.add_argument(
        "--api", default="http://localhost:8000",
        help="Backend API URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--speed", type=float, default=1.0,
        help="Seconds between flow batches (default: 1.0)"
    )
    parser.add_argument(
        "--sessions", type=int, default=4,
        help="Number of concurrent sessions (default: 4)"
    )
    parser.add_argument(
        "--scenario", default="full_kill_chain",
        choices=["full_kill_chain", "recon_sweep", "brute_force", "lateral_spread", "exfiltration", "benign_baseline"],
        help="Attack scenario preset to execute"
    )
    args = parser.parse_args()

    try:
        resp = requests.get(f"{args.api}/health", timeout=5)
        health = resp.json()
        if not health.get("model_loaded"):
            print("WARNING: Backend reports model is NOT loaded!", flush=True)
            print(f"Health: {json.dumps(health, indent=2)}", flush=True)
            sys.exit(1)
        print(f"Backend healthy: model loaded on {health.get('device', 'unknown')}", flush=True)
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Cannot connect to backend at {args.api}", flush=True)
        print("Start the backend first: cd backend && uvicorn app.main:app --reload", flush=True)
        sys.exit(1)

    run_attack_scenario(args.api, args.speed, args.sessions, args.scenario)


if __name__ == "__main__":
    main()
