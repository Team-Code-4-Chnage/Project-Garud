"""
Network Identity & Host Discovery Module.
Discovers local machine hostname, active network interfaces, IP addresses,
and classifies source/destination IPs into HOST, LAN_PEER, or NAT_PEER.
"""
import ipaddress
import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _safe_ip_parse(ip_str: Optional[str]) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not ip_str:
        return None
    clean_ip = ip_str.split(":")[0] if ":" in ip_str and not ip_str.count(":") > 1 else ip_str
    try:
        return ipaddress.ip_address(clean_ip)
    except ValueError:
        return None


def get_host_identity() -> dict:
    """
    Query system network configuration to find all local IPs, active interfaces,
    and primary outbound IP.
    """
    hostname = socket.gethostname()
    local_ips = {"127.0.0.1", "::1"}
    interfaces = []
    primary_ip = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        local_ips.add(primary_ip)
        s.close()
    except Exception:
        pass

    try:
        _, _, host_ips = socket.gethostbyname_ex(hostname)
        for ip in host_ips:
            if ip and not ip.startswith("169.254."):
                local_ips.add(ip)
    except Exception:
        pass

    try:
        import psutil
        net_addrs = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()

        for iface_name, addrs in net_addrs.items():
            is_up = net_stats.get(iface_name).isup if iface_name in net_stats else False
            for addr in addrs:
                if addr.family in (socket.AF_INET, getattr(socket, "AF_INET6", -1)):
                    raw_ip = addr.address or ""
                    clean_ip = raw_ip.split("%")[0].strip()
                    if clean_ip:
                        local_ips.add(clean_ip)
                        interfaces.append({
                            "name": iface_name,
                            "ip": clean_ip,
                            "netmask": addr.netmask,
                            "is_up": is_up,
                            "is_primary": (clean_ip == primary_ip),
                        })
    except Exception as e:
        logger.debug("psutil adapter discovery skipped: %s", e)

    if not primary_ip:
        for ip in local_ips:
            if not ip.startswith("127.") and ip != "::1":
                primary_ip = ip
                break
        if not primary_ip:
            primary_ip = "127.0.0.1"

    return {
        "hostname": hostname,
        "primary_ip": primary_ip,
        "local_ips": sorted(list(local_ips)),
        "interfaces": interfaces,
    }


_CACHED_HOST_IDENTITY: Optional[dict] = None


def get_cached_host_identity(refresh: bool = False) -> dict:
    global _CACHED_HOST_IDENTITY
    if _CACHED_HOST_IDENTITY is None or refresh:
        _CACHED_HOST_IDENTITY = get_host_identity()
    return _CACHED_HOST_IDENTITY


def classify_ip_identity(ip_str: Optional[str]) -> str:
    """
    Classify an IP into:
    - "HOST" (This machine / localhost)
    - "LAN_PEER" (Device on local/private network)
    - "NAT_PEER" (External Internet / NAT masked peer)
    """
    if not ip_str:
        return "UNKNOWN"

    host_info = get_cached_host_identity()
    if ip_str in host_info["local_ips"]:
        return "HOST"

    parsed = _safe_ip_parse(ip_str)
    if not parsed:
        return "UNKNOWN"

    if parsed.is_loopback:
        return "HOST"

    is_private = any(parsed in net for net in _PRIVATE_NETS)
    if is_private:
        return "LAN_PEER"

    return "NAT_PEER"
