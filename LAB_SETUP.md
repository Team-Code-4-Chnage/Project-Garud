# Isolated Lab — Real Attack Dataset Collection

**Every command here targets only your own VMs on an isolated host-only network you own.** Never point any
tool at a host, service, or network you do not own or have written authorization to test. The automation in
`lab/` refuses, in code, to run a scenario whose target is outside the configured lab subnet.

## Why

NetForecast forecasts from features extracted from real packets. CIC-IDS2017/2018 has broad attack coverage
but no single multi-stage campaign, so it cannot show attack **progression** (Reconnaissance → Initial Access
→ Lateral Movement → C2 → Exfiltration). A small isolated lab produces that progression, with a ground-truth
timeline, so the network-state and forecasting pipeline can be validated on a real chain. All captures are
labelled lab data and kept separate from the CIC datasets.

The collection host (the machine that runs the VMs and capture) can be separate from the machine that trains
the model: the lab scripts are standard-library only and their only output is `dataset/run_xxx/`, which you
copy to the training machine.

## Lab topology (VirtualBox host-only, no internet route)

```
Host-only network 192.168.56.0/24  (no NAT, no bridged adapter -> no internet)
  attacker   kali-lab          192.168.56.10   (runs the scenario tools over SSH)
  victim     target-victim     192.168.56.20   (e.g. Metasploitable2 / a vulnerable web app)
  peer       target-peer       192.168.56.21   (second victim, for lateral movement / exfil)
  lab host   (this machine)    192.168.56.1     (captures on vboxnet0, runs lab/*.py)
```

1. VirtualBox → Tools → Network → Host-only Networks → Create; set 192.168.56.1/24, DHCP off. **Do not add a
   NAT or bridged adapter to any lab VM.**
2. Import the VMs, attach each to that host-only network, assign the IPs above.
3. Take a snapshot named `clean` on every VM after first boot and configuration.
4. On the lab host install VirtualBox (`VBoxManage`), Wireshark (`dumpcap`), and an SSH client — all on PATH.
5. Set up key-based SSH from the lab host into the attacker VM, and install the scenario tools there
   (`nmap`, `hydra`, `curl`, `smbclient`, `sshpass`, `snmp`, `apache2-utils`; Kali has most preinstalled).
6. **Verify isolation from the attacker VM:** `ping 192.168.56.20` succeeds; `ping 8.8.8.8` fails.

## Automated collection

```bash
cp lab/lab_config.example.json lab/lab_config.json      # then edit VM names, IPs, interface, snapshots
python lab/collect_dataset.py --config lab/lab_config.json --dry-run   # validate config + tools, run nothing
python lab/reset_lab.py       --config lab/lab_config.json             # power off + restore clean snapshots
python lab/collect_dataset.py --config lab/lab_config.json --out dataset
```

Per run the harness (`lab/collect_dataset.py`): restores every VM to its `clean` snapshot and boots it, waits
until each is reachable, starts `dumpcap`, then runs the scenarios in order with a quiet gap between them,
recording each scenario's exact UTC start and stop, stops the capture, writes the run folder, and reverts the
VMs. It stops early and powers the VMs off if capture fails, a VM is unreachable, or two runs fail. It stops
when `runs` valid runs have been collected.

```
dataset/run_001/
  traffic.pcap     raw capture, never modified
  timeline.json    each scenario's id, label, target, UTC start/end, command
  metadata.json    run id, seed, subnet, interface, host, attacker/target IPs, times
```

Then, on either machine (needs scapy):

```bash
python lab/extract_flows.py --dataset dataset
```

This writes `flows.csv` in each run with the 22 model features (from `capture/flow_table.py`, the same
extractor as PCAP upload and live capture, matched to CICFlowMeter in `docs/pcap_parity.md`), plus IPs, ports,
protocol, start time, and the **label taken from the timeline window** the flow's start time falls in (flows
outside every scenario window are `Benign`). Labels come from the timeline, never from inspecting packets.

## Scenarios (edit in `lab_config.json`)

Each is a standard tool run over SSH on the attacker VM against a lab IP; review every command before running.
The default sequence covers reconnaissance, credential testing, web interaction, discovery, lateral movement,
periodic C2-like beaconing, collection, exfiltration of a dummy archive, and a bounded load test, plus benign
web traffic. Adjust targets, durations, and tools to your VMs. Because CIC-IDS2017's flag features are quirks
of its flow tool (see `docs/pcap_parity.md`), the extractor reproduces those quirks so lab flows are directly
comparable to the training data.

## Manual alternative (no automation)

Run the detection pipeline (backend, `capture/live_capture.py` as admin on the host-only adapter, frontend),
then run the same tools by hand from the attacker VM against `192.168.56.x`. Or replay a CIC-IDS2017 pcap:
`python capture/live_capture.py --pcap path/to/capture.pcap --api http://localhost:8000 --speed 0.001`.

## Safety checklist

- VMs are on a host-only network with **no** NAT/bridged adapter; `ping 8.8.8.8` from a VM fails.
- Targets are intentionally vulnerable VMs you created; every command addresses only `192.168.56.x`.
- `collect_dataset.py` refuses any scenario whose target is outside `lab_subnet` or is not a configured VM.
- VMs are reverted to a clean snapshot after every run; the raw pcap is kept unmodified.
- Nothing in `lab/` scans, exploits, beacons to, or transfers data with any host outside the lab.
