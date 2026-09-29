"""
Free IP Geolocation Resolver with in-memory caching and deterministic fallback.
Uses ipwho.is (free, no API key required) for public IPs.
Maps private/internal LAN and multicast IPs to the local defender NOC in India.
"""
import ipaddress
import json
import logging
import urllib.request
from typing import Dict, Any

logger = logging.getLogger(__name__)

# In-memory GeoIP cache to avoid duplicate network requests
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

# Dynamic live coordinates for local internal network / NOC (Auto-detected from device egress or HTML5 geolocation)
BASE_NOC_LAT = 0.0
BASE_NOC_LON = 0.0
BASE_NOC_CITY = "Local Host"
BASE_NOC_REGION = ""
BASE_NOC_COUNTRY = "Defender NOC"
BASE_NOC_FLAG = "📍"
_IS_LOCATION_INITIALIZED = False


def update_device_location(
    lat: float,
    lon: float,
    city: str = None,
    region: str = None,
    country: str = None,
    country_code: str = None,
    flag: str = None,
):
    """Dynamically update the device's live location."""
    global BASE_NOC_LAT, BASE_NOC_LON, BASE_NOC_CITY, BASE_NOC_REGION, BASE_NOC_COUNTRY, BASE_NOC_FLAG, _IS_LOCATION_INITIALIZED
    BASE_NOC_LAT = round(float(lat), 4)
    BASE_NOC_LON = round(float(lon), 4)
    if city and city.strip():
        BASE_NOC_CITY = city.strip()
    if region and region.strip():
        BASE_NOC_REGION = region.strip()
    if country and country.strip():
        c_clean = country.strip()
        BASE_NOC_COUNTRY = f"{c_clean} (Defender HQ)" if "(Defender HQ)" not in c_clean else c_clean
    if flag:
        BASE_NOC_FLAG = flag
    elif "india" in BASE_NOC_COUNTRY.lower():
        BASE_NOC_FLAG = "🇮🇳"
    else:
        BASE_NOC_FLAG = "📍"
    _IS_LOCATION_INITIALIZED = True

    # Evict internal IP cache so they re-resolve with exact new coordinates
    keys_to_evict = [k for k, v in _GEO_CACHE.items() if v.get("is_internal")]
    for k in keys_to_evict:
        _GEO_CACHE.pop(k, None)
    logger.info("Updated live device location: %s, %s (%.4f, %.4f)", BASE_NOC_CITY, BASE_NOC_COUNTRY, BASE_NOC_LAT, BASE_NOC_LON)


def get_device_location() -> Dict[str, Any]:
    """Return the current dynamic device location."""
    return {
        "latitude": BASE_NOC_LAT,
        "longitude": BASE_NOC_LON,
        "city": BASE_NOC_CITY,
        "region": BASE_NOC_REGION,
        "country": BASE_NOC_COUNTRY,
        "flag": BASE_NOC_FLAG,
        "is_detected": _IS_LOCATION_INITIALIZED,
    }


# Auto-detect real egress IP on module load
def _detect_local_egress():
    try:
        req = urllib.request.Request("https://ipwho.is/", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("success") and data.get("latitude") and data.get("longitude"):
                update_device_location(
                    lat=float(data["latitude"]),
                    lon=float(data["longitude"]),
                    city=data.get("city") or "Local Host",
                    region=data.get("region") or "",
                    country=data.get("country") or "Local Network",
                    flag=data.get("flag", {}).get("emoji") or "📍",
                )
    except Exception as exc:
        logger.debug("Local egress auto-detect deferred: %s", exc)


_detect_local_egress()

# Known major ASN / Cloud prefix coordinates fallback if offline
KNOWN_PREFIX_COORDS = {
    "1.1.": {"lat": -27.4679, "lon": 153.0281, "city": "Brisbane", "country": "Australia", "country_code": "AU", "org": "Cloudflare DNS", "flag": "🇦🇺"},
    "8.8.": {"lat": 37.4056, "lon": -122.0775, "city": "Mountain View", "country": "United States", "country_code": "US", "org": "Google Public DNS", "flag": "🇺🇸"},
    "57.": {"lat": 1.2897, "lon": 103.8501, "city": "Singapore", "country": "Singapore", "country_code": "SG", "org": "Microsoft Azure", "flag": "🇸🇬"},
    "52.": {"lat": 38.7499, "lon": -77.4619, "city": "Ashburn", "country": "United States", "country_code": "US", "org": "Amazon AWS", "flag": "🇺🇸"},
    "34.": {"lat": 33.7490, "lon": -84.3880, "city": "Atlanta", "country": "United States", "country_code": "US", "org": "Google Cloud", "flag": "🇺🇸"},
    "104.": {"lat": 37.7749, "lon": -122.4194, "city": "San Francisco", "country": "United States", "country_code": "US", "org": "Cloudflare Edge", "flag": "🇺🇸"},
    "140.82.": {"lat": 37.7749, "lon": -122.4194, "city": "San Francisco", "country": "United States", "country_code": "US", "org": "GitHub CDN", "flag": "🇺🇸"},
    "185.220.": {"lat": 50.1109, "lon": 8.6821, "city": "Frankfurt", "country": "Germany", "country_code": "DE", "org": "Tor Exit / Threat Actor", "flag": "🇩🇪"},
    "194.26.": {"lat": 52.3676, "lon": 4.9041, "city": "Amsterdam", "country": "Netherlands", "country_code": "NL", "org": "Adversary Infrastructure", "flag": "🇳🇱"},
    "45.33.": {"lat": 32.7767, "lon": -96.7970, "city": "Dallas", "country": "United States", "country_code": "US", "org": "Adversary C2 Node", "flag": "🇺🇸"},
    "198.51.100.": {"lat": 50.1109, "lon": 8.6821, "city": "Frankfurt", "country": "Germany", "country_code": "DE", "org": "Exfiltration Drop Host", "flag": "🇩🇪"},
    "224.77.": {"lat": 52.3676, "lon": 4.9041, "city": "Amsterdam", "country": "Netherlands", "country_code": "NL", "org": "Adversary C2 Beacon Channel", "flag": "⚠️"},
}


def _is_private_or_special(ip_str: str) -> bool:
    try:
        # Exclude adversary attack targets / C2 beacons from being mapped to local defender NOC
        if ip_str.startswith("224.77."):
            return False
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or (ip.is_multicast and ip_str.startswith(("224.0.0.", "239.")))
            or ip.is_link_local
            or ip_str.startswith("26.")  # Common Radmin VPN / internal subnet
        )
    except Exception:
        return True


def resolve_ip_geo(ip: str) -> Dict[str, Any]:
    """Resolve an IP to geographic coordinates, city, country, and organization."""
    if not ip or ip == "unknown":
        return {
            "ip": ip,
            "is_internal": True,
            "latitude": BASE_NOC_LAT,
            "longitude": BASE_NOC_LON,
            "city": "Unknown",
            "country": BASE_NOC_COUNTRY,
            "country_code": "LOC",
            "org": "Internal Interface",
            "flag": BASE_NOC_FLAG,
        }

    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    # Handle private / internal LAN IPs
    if _is_private_or_special(ip):
        # Slightly jitter internal IPs so multiple LAN hosts don't overlap completely on map
        hash_val = sum(ord(c) for c in ip) % 100
        jitter_lat = (hash_val % 10 - 5) * 0.015
        jitter_lon = (hash_val // 10 - 5) * 0.015

        res = {
            "ip": ip,
            "is_internal": True,
            "latitude": round(BASE_NOC_LAT + jitter_lat, 4),
            "longitude": round(BASE_NOC_LON + jitter_lon, 4),
            "city": f"LAN ({BASE_NOC_CITY})",
            "region": BASE_NOC_REGION,
            "country": BASE_NOC_COUNTRY,
            "country_code": "LOC",
            "org": f"Local Host Interface ({ip})",
            "flag": BASE_NOC_FLAG,
        }
        _GEO_CACHE[ip] = res
        return res

    # Check known cloud/CDN prefix fallback table first
    for prefix, info in KNOWN_PREFIX_COORDS.items():
        if ip.startswith(prefix):
            res = {
                "ip": ip,
                "is_internal": False,
                "latitude": info["lat"],
                "longitude": info["lon"],
                "city": info["city"],
                "region": "",
                "country": info["country"],
                "country_code": info["country_code"],
                "org": info["org"],
                "flag": info["flag"],
            }
            _GEO_CACHE[ip] = res
            return res

    # Query free ipwho.is API
    try:
        url = f"https://ipwho.is/{ip}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ProjectGarud-SIH2026/1.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("success"):
                res = {
                    "ip": ip,
                    "is_internal": False,
                    "latitude": float(data.get("latitude") or 0.0),
                    "longitude": float(data.get("longitude") or 0.0),
                    "city": data.get("city") or "Unknown City",
                    "region": data.get("region") or "",
                    "country": data.get("country") or "External",
                    "country_code": data.get("country_code") or "UN",
                    "org": (
                        data.get("connection", {}).get("isp")
                        or data.get("connection", {}).get("org")
                        or "External Autonomous System"
                    ),
                    "flag": data.get("flag", {}).get("emoji") or "🌐",
                }
                _GEO_CACHE[ip] = res
                return res
    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)

    # Deterministic fallback based on IP bytes if offline
    try:
        parts = [int(p) for p in ip.split(".") if p.isdigit()]
        if len(parts) >= 2:
            lat = round((parts[0] % 120) - 50.0, 4)
            lon = round((parts[1] % 240) - 100.0, 4)
        else:
            lat, lon = 37.0902, -95.7129
    except Exception:
        lat, lon = 37.0902, -95.7129

    res = {
        "ip": ip,
        "is_internal": False,
        "latitude": lat,
        "longitude": lon,
        "city": "External Host",
        "region": "",
        "country": "Remote Origin",
        "country_code": "EXT",
        "org": "External IP",
        "flag": "🌐",
    }
    _GEO_CACHE[ip] = res
    return res


def batch_resolve_geo(ips: list) -> Dict[str, Dict[str, Any]]:
    """Batch resolve a list of unique IPs."""
    result = {}
    for ip in set(ips):
        result[ip] = resolve_ip_geo(ip)
    return result
