import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import requests

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

try:
    from scapy.all import conf, rdpcap, sniff
    from scapy.layers.inet import IP, TCP, UDP
except ImportError:
    try:
        from scapy.all import (  # type: ignore
            IP,
            TCP,
            UDP,
            conf,
            rdpcap,
            sniff,
        )
    except ImportError:
        print("ERROR: scapy not installed. Run: pip install scapy")
        print("On Windows, also install Npcap: https://npcap.com/#download")
        sys.exit(1)


try:
    from .flow_state import FlowState
    from .flow_table import FlowTable, packet_fields
except ImportError:
    from flow_state import FlowState
    from flow_table import FlowTable, packet_fields



class FlowExtractor:
    def __init__(self, api_url: str, flow_timeout: float = 30.0,
                 min_packets: int = 4, export_interval: int = 10):
        self.api_url = api_url
        self.flow_timeout = flow_timeout
        self.min_packets = min_packets
        self.export_interval = export_interval

        self.table = FlowTable()
        self.exported_count = 0
        self.total_packets = 0
        self.alerts_triggered = 0

    @property
    def active_flows(self) -> dict:
        return self.table.active

    def process_packet(self, pkt):
        """Assemble packets into flows with the same rules as PCAP upload and the training data
        (capture/flow_table.py). Flows closed by FIN/RST or the 120 s flow timeout are sent at once;
        flows idle longer than `flow_timeout` seconds are sent by the periodic check (live traffic
        needs an idle cut-off so quiet connections are not held for two minutes)."""
        self.total_packets += 1
        f = packet_fields(pkt)
        if f is None:
            return
        for flow in self.table.add(f):
            self._send(flow)

        now = time.time()
        last_check = getattr(self, "_last_export_check", 0.0)
        if (self.total_packets % 25 == 0) or (now - last_check >= 3.0):
            self._last_export_check = now
            self._export_expired_flows(f["ts"] if f["ts"] > 0 else now)

    def _send(self, flow: FlowState):
        if flow.packet_count >= self.min_packets:
            self._send_to_api(flow)

    def _export_expired_flows(self, current_time: float):
        for flow in self.table.expire(current_time, self.flow_timeout):
            self._send(flow)

    def _send_to_api(self, flow: FlowState):
        features = flow.to_features()
        features["src_ip"] = flow.src_ip
        features["dst_ip"] = flow.dst_ip
        features["src_port"] = flow.src_port
        features["dst_port"] = flow.dst_port
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        features["protocol"] = proto_map.get(flow.protocol, str(flow.protocol))
        # flow start time, as in the training data (the network state groups flows by the minute they start)
        features["timestamp"] = datetime.fromtimestamp(flow.start_time, tz=timezone.utc).isoformat()
        features["source"] = "live_capture"
        features["heartbleed_signature"] = flow.heartbleed_detected

        try:
            resp = requests.post(
                f"{self.api_url}/ingest",
                json=features,
                timeout=10,
            )
            self.exported_count += 1

            if resp.status_code == 200:
                result = resp.json()
                pred = result.get("prediction")
                alert = result.get("alert")

                status = (
                    f"Flow #{self.exported_count:>5} | "
                    f"{flow.src_ip:>15}:{flow.src_port:<5} → "
                    f"{flow.dst_ip:>15}:{flow.dst_port:<5} | "
                    f"{flow.packet_count:>4} pkts | "
                )

                if pred:
                    prob = pred["infiltration_probability"]
                    stage = pred["predicted_stage"]
                    status += f"P={prob:.3f} Stage={stage}"
                    if alert:
                        self.alerts_triggered += 1
                        status += f" | 🚨 {alert['severity'].upper()}: {alert['recommended_action'][:60]}"
                else:
                    buf = result.get("buffer_size", "?")
                    status += f"Buffering ({buf}/6)"

                if flow.heartbleed_detected:
                    self.alerts_triggered += 1
                    status += " | 🚨 HEARTBLEED SIGNATURE (CVE-2014-0160) DETECTED"

                logger.info(status)
            else:
                logger.warning("API returned %d: %s", resp.status_code, resp.text[:100])

        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to API at %s", self.api_url)
        except Exception as e:
            logger.error("Error sending flow: %s", e)

    def export_all_remaining(self):
        logger.info("Exporting %d remaining active flows...", len(self.active_flows))
        for flow in self.table.flush():
            self._send(flow)

    def print_stats(self):
        print(f"\n{'='*60}")
        print("  Capture Statistics")
        print(f"  Total packets processed: {self.total_packets}")
        print(f"  Flows exported:          {self.exported_count}")
        print(f"  Alerts triggered:        {self.alerts_triggered}")
        print(f"  Active flows remaining:  {len(self.active_flows)}")
        print(f"{'='*60}\n")


def get_network_interfaces():
    interfaces = []
    active_ip = None

    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        active_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    try:
        ifaces_dict = getattr(conf, "ifaces", None)
        if ifaces_dict and hasattr(ifaces_dict, "items"):
            for k, iface in ifaces_dict.items():
                name = getattr(iface, "name", str(k))
                desc = getattr(iface, "description", "")
                ip = getattr(iface, "ip", "")
                ip_str = str(ip) if ip else ""

                if ip_str.startswith("127.") or "loopback" in name.lower() or "loopback" in desc.lower():
                    continue

                is_active = (ip_str == active_ip) if active_ip else (bool(ip_str) and not ip_str.startswith("169.254."))

                interfaces.append({
                    "name": name,
                    "description": desc,
                    "ip": ip_str,
                    "is_active": is_active,
                    "scapy_key": k,
                    "iface": iface,
                })
    except Exception:
        pass

    if not interfaces and active_ip:
        interfaces.append({
            "name": "Default Interface",
            "description": f"Active network adapter ({active_ip})",
            "ip": active_ip,
            "is_active": True,
            "scapy_key": active_ip,
            "iface": active_ip,
        })

    return interfaces, active_ip


def list_interfaces():
    interfaces, active_ip = get_network_interfaces()
    print("\nAvailable Network Interfaces:")
    print("=" * 80)
    print(f"{'Name / Alias':<20} | {'IPv4 Address':<16} | {'Status':<10} | {'Description'}")
    print("-" * 80)

    for iface in interfaces:
        status = "ACTIVE" if iface["is_active"] else ("CONNECTED" if iface["ip"] and not iface["ip"].startswith("169.254.") else "DISCONNECTED")
        print(f"{iface['name']:<20} | {iface['ip']:<16} | {status:<10} | {iface['description']}")

    print("=" * 80)
    print("Run with --interface <name> (or --interface auto for active adapter).")
    print("Run as Administrator for live packet capture on Windows.\n")


def resolve_interface(interface_arg: Optional[str] = None) -> dict:
    interfaces, active_ip = get_network_interfaces()

    active_iface = None
    for iface in interfaces:
        if iface["is_active"]:
            active_iface = iface
            break

    if not active_iface and interfaces:
        for iface in interfaces:
            if iface["ip"] and not iface["ip"].startswith("169.254."):
                active_iface = iface
                break

    if not interface_arg or interface_arg.lower() in ("auto", "default"):
        if active_iface:
            logger.info("Auto-selected active interface: %s (%s - %s)",
                        active_iface["name"], active_iface["ip"], active_iface["description"])
            return active_iface
        elif interfaces:
            return interfaces[0]
        else:
            return {"name": "Default", "description": "Default", "ip": active_ip or "0.0.0.0", "scapy_key": "auto"}

    target = interface_arg.strip().lower()

    matched = None
    for iface in interfaces:
        if (target == iface["name"].lower() or
            target == iface["ip"].lower() or
            target in iface["name"].lower() or
            target in iface["description"].lower() or
            target == str(iface.get("scapy_key", "")).lower()):
            matched = iface
            break

    if matched:
        if not matched["ip"] or matched["ip"].startswith("169.254."):
            if active_iface:
                logger.warning(
                    "Requested interface '%s' has no active connection (IP: %s). "
                    "Automatically switching to active connected interface: '%s' (%s)",
                    interface_arg, matched.get("ip", "none"), active_iface["name"], active_iface["ip"]
                )
                return active_iface
        return matched

    if active_iface:
        logger.warning(
            "Interface '%s' not recognized. Falling back to active adapter: '%s' (%s)",
            interface_arg, active_iface["name"], active_iface["ip"]
        )
        return active_iface

    return {"name": interface_arg, "description": interface_arg, "ip": active_ip or "0.0.0.0", "scapy_key": interface_arg}


def _run_traffic_simulator(api_url: str):
    import subprocess
    from pathlib import Path

    sim_script = Path(__file__).resolve().parent.parent / "demo" / "traffic_simulator.py"
    if sim_script.exists():
        logger.info("Starting Traffic Simulator: %s", sim_script)
        cmd = [sys.executable, str(sim_script), "--api", api_url, "--sessions", "4", "--speed", "1.0"]
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass
    else:
        logger.error("Traffic simulator script not found at %s", sim_script)


def _handle_permission_denied(api_url: str, fallback_sim: bool = False):
    print("\n" + "=" * 76)
    print("  [!] LIVE PACKET CAPTURE REQUIRES ADMINISTRATOR PRIVILEGES")
    print("=" * 76)
    print("  Capturing live network packets on Windows requires Administrator rights.")
    print()
    print("  How to fix:")
    print("  1. Launch start_all.ps1 (it automatically requests UAC elevation), OR")
    print("  2. Right-click PowerShell -> 'Run as Administrator', then run:")
    print(f"     python capture\\live_capture.py --interface auto --api {api_url}")
    print()
    print("  Note on Npcap:")
    print("  - Installing Npcap (https://npcap.com/#download) with 'WinPcap API-compatible")
    print("    Mode' enabled provides full Layer-2 packet sniffing.")
    print("  - Without Npcap, Windows native Raw Socket capture is used (needs Admin).")
    print()
    print("  Alternatively, you can run the Traffic Simulator to demo attacks without Admin:")
    print(f"     python demo/traffic_simulator.py --api {api_url}")
    print("=" * 76 + "\n")

    if fallback_sim:
        logger.info("Launching Traffic Simulator as fallback...")
        _run_traffic_simulator(api_url)
    else:
        try:
            if sys.stdin.isatty():
                ans = input("Would you like to launch the Traffic Simulator now? [Y/n]: ").strip().lower()
                if ans in ("", "y", "yes"):
                    _run_traffic_simulator(api_url)
                    return
        except Exception:
            pass
        sys.exit(1)


def _capture_with_raw_socket(bind_ip: str, extractor: FlowExtractor, count: int,
                             api_url: str, fallback_sim: bool = False):
    import socket

    if not bind_ip or bind_ip.startswith(("127.", "169.254.")):
        logger.error("Cannot bind raw socket: Invalid or unassigned IP address '%s'.", bind_ip)
        _handle_permission_denied(api_url, fallback_sim)
        return

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((bind_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        logger.error("Permission denied: Raw socket capture on Windows requires Administrator privileges.")
        _handle_permission_denied(api_url, fallback_sim)
        return
    except OSError as e:
        if getattr(e, "winerror", None) == 10013:
            logger.error("Permission denied (WinError 10013): Run PowerShell as Administrator.")
        else:
            logger.error("Failed to bind raw socket on %s: %s", bind_ip, e)
        _handle_permission_denied(api_url, fallback_sim)
        return

    logger.info("=" * 65)
    logger.info("  LIVE RAW SOCKET CAPTURE ACTIVE")
    logger.info("  Listening on IP address: %s", bind_ip)
    logger.info("  Capturing live IPv4 packets (SIO_RCVALL)...")
    logger.info("  Press Ctrl+C to stop.")
    logger.info("=" * 65)

    pkt_count = 0
    last_heartbeat = time.time()

    try:
        while True:
            raw_data, _ = s.recvfrom(65535)
            now = time.time()
            try:
                pkt = IP(raw_data)
                pkt.time = now
                extractor.process_packet(pkt)
                pkt_count += 1
                if count > 0 and pkt_count >= count:
                    break
            except Exception as e:
                logger.debug("Failed to decode or parse raw IP packet: %s", e)

            if now - last_heartbeat >= 10.0:
                last_heartbeat = now
                logger.info(
                    "Live capture active... (Packets: %d | Active flows: %d | Exported: %d)",
                    extractor.total_packets,
                    len(extractor.active_flows),
                    extractor.exported_count,
                )
    except KeyboardInterrupt:
        logger.info("\nCapture stopped by user.")
    finally:
        if s:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        extractor.export_all_remaining()
        extractor.print_stats()


def capture_live(interface_arg: Optional[str], api_url: str, count: int = 0,
                 timeout_sec: float = 10.0, fallback_sim: bool = False):
    resolved = resolve_interface(interface_arg)
    iface_name = resolved["name"]
    iface_ip = resolved.get("ip", "")
    scapy_iface = resolved.get("scapy_key", iface_name)

    logger.info("Target network interface: %s (%s)", iface_name, iface_ip or "No IPv4")
    logger.info("Sending flows to API:      %s", api_url)

    extractor = FlowExtractor(api_url=api_url, flow_timeout=timeout_sec, min_packets=2)

    has_npcap = False
    try:
        if getattr(conf, "use_pcap", False):
            has_npcap = True
    except Exception:
        pass

    if has_npcap:
        logger.info("Npcap detected. Using Layer-2 capture on %s", scapy_iface)
        logger.info("Press Ctrl+C to stop.\n")
        try:
            sniff(
                iface=scapy_iface,
                prn=extractor.process_packet,
                count=count if count > 0 else 0,
                store=False,
            )
        except PermissionError:
            logger.error("Permission denied. Run as Administrator for live capture.")
            _handle_permission_denied(api_url, fallback_sim)
        except RuntimeError as e:
            logger.warning("Scapy sniff failed (%s). Falling back to Windows native raw socket...", e)
            _capture_with_raw_socket(iface_ip, extractor, count, api_url, fallback_sim)
        except KeyboardInterrupt:
            pass
        finally:
            extractor.export_all_remaining()
            extractor.print_stats()
    else:
        if sys.platform == "win32":
            logger.info("Npcap not detected. Using Windows native Raw Socket capture...")
            _capture_with_raw_socket(iface_ip, extractor, count, api_url, fallback_sim)
        else:
            logger.info("Starting live capture on %s...", scapy_iface)
            try:
                sniff(
                    iface=scapy_iface,
                    prn=extractor.process_packet,
                    count=count if count > 0 else 0,
                    store=False,
                )
            except Exception as e:
                logger.error("Live capture error: %s", e)
                _handle_permission_denied(api_url, fallback_sim)
            finally:
                extractor.export_all_remaining()
                extractor.print_stats()


def process_pcap(pcap_path: str, api_url: str, speed: float = 0.0,
                 timeout_sec: float = 10.0):
    logger.info("Processing pcap: %s", pcap_path)
    logger.info("Sending flows to: %s", api_url)

    extractor = FlowExtractor(api_url=api_url, flow_timeout=timeout_sec, min_packets=2)

    try:
        packets = rdpcap(pcap_path)
        logger.info("Loaded %d packets from pcap", len(packets))

        for i, pkt in enumerate(packets):
            extractor.process_packet(pkt)

            if speed > 0:
                time.sleep(speed)

            if (i + 1) % 1000 == 0:
                logger.info("Processed %d/%d packets...", i + 1, len(packets))

    except FileNotFoundError:
        logger.error("Pcap file not found: %s", pcap_path)
        sys.exit(1)
    except Exception as e:
        logger.error("Error processing pcap: %s", e)
        raise
    finally:
        extractor.export_all_remaining()
        extractor.print_stats()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Network packet capture — flow extraction and model prediction pipeline."
        )
    )
    parser.add_argument("--interface", "-i", default="auto",
                        help="Network interface for live capture (default: 'auto' for active adapter)")
    parser.add_argument("--pcap", "-p", help="Path to pcap/pcapng file to process")
    parser.add_argument("--api", default="http://localhost:8000", help="Backend API URL")
    parser.add_argument("--speed", type=float, default=0.0,
                        help="Delay between packets in pcap replay (0=full speed)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Flow inactivity timeout in seconds (default: 10.0)")
    parser.add_argument("--count", type=int, default=0,
                        help="Max packets to capture (0=unlimited)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("--fallback-simulator", action="store_true",
                        help="Automatically fall back to Traffic Simulator if packet capture cannot start")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    try:
        resp = requests.get(f"{args.api}/health", timeout=5)
        health = resp.json()
        if not health.get("model_loaded"):
            logger.error("Backend model not loaded! Health: %s", json.dumps(health))
            sys.exit(1)
        logger.info("Backend healthy: model=%s, device=%s",
                     "loaded" if health["model_loaded"] else "MISSING",
                     health.get("device", "unknown"))
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to backend at %s", args.api)
        logger.error("Start backend first: cd backend && uvicorn app.main:app --reload")
        sys.exit(1)

    if args.pcap:
        process_pcap(args.pcap, args.api, speed=args.speed, timeout_sec=args.timeout)
    else:
        capture_live(args.interface, args.api, count=args.count, timeout_sec=args.timeout,
                     fallback_sim=args.fallback_simulator)


if __name__ == "__main__":
    main()
