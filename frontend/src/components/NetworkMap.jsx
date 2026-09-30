import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import {
  Globe,
  Network,
  Maximize2,
  Minimize2,
  X,
  Search,
  Filter,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Radio,
  ExternalLink,
  RotateCcw,
  SlidersHorizontal,
  Server,
  Cloud,
  Laptop,
  Play,
  Activity,
  CheckCircle2,
  ChevronRight,
  Info,
  Plus,
  Minus,
  ChevronDown,
  ChevronUp,
  Trash2,
} from "lucide-react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { apiFetch, apiPost } from "../api";
import { useTheme } from "../theme";

// System Stage Color Palette
export const STAGE_PALETTE = [
  { id: "all", label: "ALL TRAFFIC", color: "var(--text-primary)" },
  { id: "benign", label: "BENIGN", color: "#34D399", key: "benign" },
  { id: "recon", label: "PHASE 1: RECON", color: "#39DFEB", key: "recon" },
  {
    id: "initial",
    label: "PHASE 2: INITIAL ACCESS",
    color: "#F6B144",
    key: "initial",
  },
  {
    id: "lateral",
    label: "PHASE 3: LATERAL MOVE",
    color: "#E8873A",
    key: "lateral",
  },
  { id: "c2", label: "PHASE 4: C2 CHANNEL", color: "#E5633E", key: "c2" },
  {
    id: "exfil",
    label: "PHASE 5: EXFILTRATION",
    color: "#F64541",
    key: "exfil",
  },
];

export function getStageTheme(stage, risk = 0) {
  const s = String(stage || "").toLowerCase();
  if (
    s.includes("exfil") ||
    s.includes("infilt") ||
    s.includes("heartbleed") ||
    risk >= 0.85
  ) {
    return {
      phase: "05",
      name: "Exfiltration",
      color: "#F64541",
      bg: "rgba(246, 69, 65, 0.16)",
      border: "#F64541",
      rank: 5,
    };
  }
  if (
    s.includes("c2") ||
    s.includes("bot") ||
    s.includes("command") ||
    risk >= 0.7
  ) {
    return {
      phase: "04",
      name: "C2 Channel",
      color: "#E5633E",
      bg: "rgba(229, 99, 62, 0.16)",
      border: "#E5633E",
      rank: 4,
    };
  }
  if (s.includes("lateral") || s.includes("pivot") || risk >= 0.55) {
    return {
      phase: "03",
      name: "Lateral Movement",
      color: "#E8873A",
      bg: "rgba(232, 135, 58, 0.16)",
      border: "#E8873A",
      rank: 3,
    };
  }
  if (
    s.includes("initial") ||
    s.includes("access") ||
    s.includes("brute") ||
    s.includes("dos") ||
    s.includes("web") ||
    risk >= 0.38
  ) {
    return {
      phase: "02",
      name: "Initial Access",
      color: "#F6B144",
      bg: "rgba(246, 177, 68, 0.16)",
      border: "#F6B144",
      rank: 2,
    };
  }
  if (
    s.includes("recon") ||
    s.includes("scan") ||
    s.includes("port") ||
    s.includes("prob") ||
    risk >= 0.2
  ) {
    return {
      phase: "01",
      name: "Reconnaissance",
      color: "#39DFEB",
      bg: "rgba(57, 223, 235, 0.16)",
      border: "#39DFEB",
      rank: 1,
    };
  }
  return {
    phase: "00",
    name: "Benign",
    color: "#34D399",
    bg: "rgba(52, 211, 153, 0.14)",
    border: "#34D399",
    rank: 0,
  };
}

// Dynamic registry of local host interface IPs discovered at runtime
const _detectedLocalIps = new Set(["127.0.0.1", "::1", "localhost", "0.0.0.0"]);

export function registerLocalIps(ips) {
  if (Array.isArray(ips)) {
    ips.forEach((ip) => {
      if (ip && typeof ip === "string")
        _detectedLocalIps.add(ip.trim().toLowerCase());
    });
  }
}

// Helper to determine if an IP is a local host, private LAN, loopback, or local interface
export function isLocalHostOrLAN(ip) {
  if (!ip || typeof ip !== "string") return false;
  const clean = ip.trim().toLowerCase();
  if (_detectedLocalIps.has(clean)) return true;
  if (
    clean.startsWith("10.") ||
    clean.startsWith("192.168.") ||
    clean.startsWith("127.") ||
    clean === "localhost" ||
    clean === "::1" ||
    clean.startsWith("fe80:") ||
    clean.startsWith("fc00:") ||
    clean.startsWith("fd00:") ||
    clean.startsWith("169.254.")
  ) {
    return true;
  }
  if (clean.startsWith("172.")) {
    const parts = clean.split(".");
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

// Keep isInternalIP as alias for backwards compatibility
export function isInternalIP(ip) {
  return isLocalHostOrLAN(ip);
}

// Filter out link-local broadcast and discovery noise
function isMulticastOrBroadcast(ip) {
  if (!ip || typeof ip !== "string") return false;
  return (
    ip.startsWith("224.") ||
    ip.startsWith("239.") ||
    ip === "255.255.255.255" ||
    ip.endsWith(".255") ||
    ip.startsWith("ff02::") ||
    ip.startsWith("ff00::")
  );
}

// Clean formatting of long IPv6 addresses
function formatShortIP(ip) {
  if (!ip) return "";
  if (ip.includes(":")) {
    const parts = ip.split(":");
    if (parts.length > 3) {
      return `${parts[0]}:${parts[1]}..${parts[parts.length - 1]}`;
    }
  }
  return ip;
}

// Geodesic Parabolic Arc Generator:
// Connects real coordinates with a smooth crest peaking at midpoint.
// Guarantees exact connection at both endpoints with zero flatlines,
// zero antimeridian breaks, and zero spikes on local nodes.
function createSmoothCyberArc(p1, p2, steps = 30) {
  const [lat1, lon1] = p1;
  const [lat2, lon2] = p2;

  const dLat = lat2 - lat1;
  const dLon = lon2 - lon1;
  const dist = Math.sqrt(dLat * dLat + dLon * dLon);

  // If endpoints are nearly coincident (same city or local LAN)
  if (dist < 0.15) {
    return [
      [lat1, lon1],
      [lat2, lon2],
    ];
  }

  // Arch height scales gracefully based on distance:
  // Local/regional (< 4 deg): virtually flat (dist * 0.03)
  // Medium range (4-15 deg): gentle arch (dist * 0.06)
  // Intercontinental (> 15 deg): prominent cyber arch max 18 degrees latitude
  let archHeight = 0;
  if (dist > 15.0) {
    archHeight = Math.min(dist * 0.09, 18.0);
  } else if (dist > 4.0) {
    archHeight = Math.min(dist * 0.06, 3.5);
  } else {
    archHeight = dist * 0.02;
  }

  const points = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    // Pure parabolic elevation: 4 * t * (1 - t) is 0 at ends, 1.0 at t=0.5
    const elevation = 4 * t * (1 - t) * archHeight;
    const lat = lat1 + t * dLat + elevation;
    const lon = lon1 + t * dLon;
    points.push([lat, lon]);
  }
  return points;
}

// SVG Icon Helpers matching media_1790688008635.png
export function RouterSwitchIcon({ size = 15, color = "currentColor" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="9" />
      <path d="M8 10h8M8 14h8M8 10l2.5-2.5M16 14l-2.5 2.5" />
    </svg>
  );
}

export function ThreatServerIcon({ size = 15, color = "currentColor" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="4" y="5" width="16" height="14" rx="2" />
      <line x1="4" y1="12" x2="20" y2="12" />
      <line x1="8" y1="8.5" x2="8.01" y2="8.5" strokeWidth="2.6" />
      <line x1="12" y1="8.5" x2="16" y2="8.5" />
      <line x1="8" y1="15.5" x2="8.01" y2="15.5" strokeWidth="2.6" />
      <line x1="12" y1="15.5" x2="16" y2="15.5" />
    </svg>
  );
}

export function DatabaseStorageIcon({ size = 15, color = "currentColor" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <ellipse cx="12" cy="6" rx="8" ry="3" />
      <path d="M4 6v6c0 1.66 3.58 3 8 3s8-1.34 8-3V6" />
      <path d="M4 12v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6" />
    </svg>
  );
}

export function GlobeWebIcon({ size = 15, color = "currentColor" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="2.0"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="9" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <path d="M12 3a13 13 0 0 1 4.5 9 13 13 0 0 1-4.5 9 13 13 0 0 1-4.5-9 13 13 0 0 1 4.5-9z" />
    </svg>
  );
}

export function MonitorLanIcon({ size = 15, color = "currentColor" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <line x1="8" y1="19" x2="16" y2="19" />
      <line x1="12" y1="16" x2="12" y2="19" />
    </svg>
  );
}

// Geometric Line Intersections for exact arrow endpoints
function getCircleLinePoints(
  x1,
  y1,
  x2,
  y2,
  r1 = 15,
  r2 = 15,
  arrowPadding = 5,
) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const dist = Math.hypot(dx, dy);
  if (dist === 0) return { sx: x1, sy: y1, ex: x2, ey: y2 };

  const sx = x1 + (dx / dist) * r1;
  const sy = y1 + (dy / dist) * r1;
  const ex = x2 - (dx / dist) * (r2 + arrowPadding);
  const ey = y2 - (dy / dist) * (r2 + arrowPadding);

  return { sx, sy, ex, ey };
}

// Map Marker Icon matching the circular badge design with concentric radar rings
function createClusterMarkerIcon(cluster, isDark) {
  const isInternal = cluster.is_internal;
  const risk = cluster.max_risk || 0;
  const isThreat =
    cluster.has_threat ||
    risk >= 0.35 ||
    (cluster.max_stage && cluster.max_stage !== "Benign");
  const stageTheme = getStageTheme(cluster.max_stage, risk);
  const color = isThreat ? "#EF4444" : isInternal ? "#10B981" : "#3B82F6";
  const boxSize = 38;
  const ringColor = isThreat
    ? "rgba(239, 68, 68, 0.45)"
    : isInternal
      ? "rgba(16, 185, 129, 0.45)"
      : "rgba(59, 130, 246, 0.35)";

  let innerIconSvg = "";
  if (isInternal) {
    innerIconSvg = `
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="9"/>
        <path d="M8 10h8M8 14h8M8 10l2.5-2.5M16 14l-2.5 2.5"/>
      </svg>
    `;
  } else if (isThreat) {
    innerIconSvg = `
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="4" y="5" width="16" height="14" rx="2"/>
        <line x1="4" y1="12" x2="20" y2="12"/>
        <line x1="8" y1="8.5" x2="8.01" y2="8.5" stroke-width="2.6"/>
        <line x1="12" y1="8.5" x2="16" y2="8.5"/>
        <line x1="8" y1="15.5" x2="8.01" y2="15.5" stroke-width="2.6"/>
        <line x1="12" y1="15.5" x2="16" y2="15.5"/>
      </svg>
    `;
  } else if (
    (cluster.org && cluster.org.toLowerCase().includes("cloud")) ||
    (cluster.org && cluster.org.toLowerCase().includes("amazon")) ||
    (cluster.org && cluster.org.toLowerCase().includes("microsoft")) ||
    (cluster.org && cluster.org.toLowerCase().includes("google"))
  ) {
    innerIconSvg = `
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <ellipse cx="12" cy="6" rx="8" ry="3"/>
        <path d="M4 6v6c0 1.66 3.58 3 8 3s8-1.34 8-3V6"/>
        <path d="M4 12v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>
      </svg>
    `;
  } else {
    innerIconSvg = `
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.0" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="9"/>
        <line x1="3" y1="12" x2="21" y2="12"/>
        <path d="M12 3a13 13 0 0 1 4.5 9 13 13 0 0 1-4.5 9 13 13 0 0 1-4.5-9 13 13 0 0 1 4.5-9z"/>
      </svg>
    `;
  }

  return L.divIcon({
    className: "garud-geo-marker",
    html: `
      <div style="position: relative; width: ${boxSize}px; height: ${boxSize}px; display: flex; align-items: center; justify-content: center;">
        <div style="
          position: absolute;
          width: 36px;
          height: 36px;
          border-radius: 50%;
          border: 1.2px solid ${color};
          opacity: ${isThreat ? "0.75" : "0.35"};
          ${isThreat ? "animation: pulse-ring 2s infinite ease-out;" : ""}
        "></div>
        <div style="
          position: absolute;
          width: 27px;
          height: 27px;
          border-radius: 50%;
          border: 1px solid ${ringColor};
        "></div>
        <div style="
          width: 20px;
          height: 20px;
          border-radius: 50%;
          background: ${isDark ? "#0A1620" : "#FFFFFF"};
          border: 2px solid ${color};
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 0 ${isThreat ? "10px" : "6px"} ${color};
          cursor: pointer;
          z-index: 2;
        ">
          ${innerIconSvg}
        </div>
        ${
          cluster.total_ips > 1
            ? `<div style="
                position: absolute;
                top: -3px;
                right: -3px;
                background: ${isThreat ? "#EF4444" : isDark ? "#1E293B" : "#F3F4F6"};
                color: ${isThreat ? "#FFFFFF" : isDark ? "#94A3B8" : "#334155"};
                border: 1px solid ${color};
                border-radius: 8px;
                font-family: var(--font-mono, monospace);
                font-size: 8px;
                font-weight: 700;
                padding: 0 3px;
                line-height: 10px;
                pointer-events: none;
                z-index: 3;
              ">${cluster.total_ips}</div>`
            : ""
        }
      </div>
    `,
    iconSize: [boxSize, boxSize],
    iconAnchor: [boxSize / 2, boxSize / 2],
  });
}

export default function NetworkMap({
  liveFlows = [],
  onSelectSession,
  height = 320,
}) {
  const { isDark } = useTheme();
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState("geo"); // 'geo' | 'logical'
  const [stageFilter, setStageFilter] = useState("all");
  const [densityMode, setDensityMode] = useState("all"); // 'all' | 'threats' | 'focused'
  const [hideBroadcast, setHideBroadcast] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEntity, setSelectedEntity] = useState(null); // cluster or flow
  const [hoveredNodeId, setHoveredNodeId] = useState(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [systemMode, setSystemMode] = useState("live");
  const [simulating, setSimulating] = useState(false);
  const [focusedFlow, setFocusedFlow] = useState(null);
  const [showThreatRadar, setShowThreatRadar] = useState(false);
  const [isRadarMinimized, setIsRadarMinimized] = useState(false);
  const [hostIdentity, setHostIdentity] = useState(null);
  const [deviceLocation, setDeviceLocation] = useState({
    latitude: 0,
    longitude: 0,
    city: "Local Host",
    region: "",
    country: "Defender HQ",
    flag: "📍",
    is_detected: false,
  });

  // Topology Interactive Zoom & Pan States
  const [topoZoom, setTopoZoom] = useState(1);
  const [topoPan, setTopoPan] = useState({ x: 0, y: 0 });
  const [isPanningTopo, setIsPanningTopo] = useState(false);
  const panStartRef = useRef({
    startX: 0,
    startY: 0,
    panX: 0,
    panY: 0,
    hasMoved: false,
  });
  const topoContainerRef = useRef(null);

  const containerRef = useRef(null);
  const mapContainerRef = useRef(null);
  const leafletMapRef = useRef(null);
  const markersLayerRef = useRef(null);
  const linesLayerRef = useRef(null);
  const hasInitialFittedRef = useRef(false);

  // Client-side GeoIP cache for dynamic live flow resolution
  const [geoCache, setGeoCache] = useState({});
  const pendingGeoIpsRef = useRef(new Set());

  const fetchMissingGeo = useCallback(async (ip) => {
    if (!ip || isLocalHostOrLAN(ip) || pendingGeoIpsRef.current.has(ip)) return;
    pendingGeoIpsRef.current.add(ip);
    try {
      const geo = await apiFetch(`/graph/geoip/${encodeURIComponent(ip)}`);
      if (
        geo &&
        typeof geo.latitude === "number" &&
        typeof geo.longitude === "number"
      ) {
        setGeoCache((prev) => ({ ...prev, [ip]: geo }));
      }
    } catch {
      // Non-fatal fallback
    }
  }, []);

  // Fetch host machine identity (real hostname, primary IP, active adapters, auto-detected egress location)
  useEffect(() => {
    apiFetch("/system/host-identity")
      .then((h) => {
        if (h?.hostname) {
          setHostIdentity(h);
          if (Array.isArray(h.local_ips)) {
            registerLocalIps(h.local_ips);
          }
          if (h.primary_ip) {
            registerLocalIps([h.primary_ip]);
          }
          if (
            h.location &&
            (h.location.latitude || h.location.longitude || h.location.city)
          ) {
            setDeviceLocation((prev) => ({
              ...prev,
              ...h.location,
              is_detected: h.location.is_detected ?? true,
            }));
          }
        }
      })
      .catch(() => {});
  }, []);

  // HTML5 Live Browser Geolocation auto-sync to backend
  useEffect(() => {
    if (typeof window !== "undefined" && "geolocation" in navigator) {
      navigator.geolocation.getCurrentPosition(
        async (pos) => {
          const lat = parseFloat(pos.coords.latitude.toFixed(4));
          const lon = parseFloat(pos.coords.longitude.toFixed(4));
          try {
            let city = "";
            let country = "";
            let flag = "";
            try {
              const res = await fetch(
                `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=en`,
              );
              if (res.ok) {
                const geo = await res.json();
                city = geo.city || geo.locality || "";
                country = geo.countryName || "";
              }
            } catch {}

            const updated = await apiPost("/system/device-location", {
              latitude: lat,
              longitude: lon,
              city: city || undefined,
              country: country || undefined,
              flag: flag || undefined,
            });
            if (updated?.location) {
              setDeviceLocation(updated.location);
            }
          } catch (e) {
            console.debug("Device location sync error:", e);
          }
        },
        (err) => {
          console.debug(
            "Browser geolocation fallback to egress IP:",
            err?.message,
          );
        },
        { timeout: 7000, maximumAge: 60000 },
      );
    }
  }, []);

  // Load topology enriched with real GeoIP data & apps
  const loadTopology = async () => {
    try {
      const data = await apiFetch(
        "/graph/topology_geo?min_risk=0.0&limit=150&active_only=true&max_age_seconds=75",
      );
      if (data?.nodes) {
        setGraphData({
          nodes: data.nodes || [],
          edges: data.edges || [],
          highRiskNodes: data.high_risk_nodes || [],
        });
        setLoading(false);
      }
    } catch {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTopology();
    const interval = setInterval(loadTopology, 4000);
    return () => clearInterval(interval);
  }, []);

  // Poll system mode
  useEffect(() => {
    apiFetch("/system/mode")
      .then((m) => {
        if (m?.mode) setSystemMode(m.mode);
        if (typeof m?.simulator_running === "boolean")
          setSimulating(m.simulator_running);
      })
      .catch(() => {});
  }, []);

  // Handle Trigger Simulation from map toolbar
  const handleTriggerSimulation = async (scenario = "full_kill_chain") => {
    try {
      setSimulating(true);
      await apiPost("/system/simulator/start", {
        scenario,
        sessions: 4,
        speed: 0.8,
        auto_switch_mode: true,
      });
      setSystemMode("simulated");
      setTimeout(loadTopology, 1000);
    } catch (e) {
      console.error("Failed to start simulator:", e);
      setSimulating(false);
    }
  };

  const handleStopSimulation = async () => {
    try {
      await apiPost("/system/mode", { mode: "live" });
      setSystemMode("live");
      setSimulating(false);
      setTimeout(loadTopology, 1000);
    } catch (e) {
      console.error("Failed to switch to live mode:", e);
    }
  };

  // Clear GeoIP cache on server and client to force fresh live geolocations
  const [clearingCache, setClearingCache] = useState(false);
  const handleClearMapCache = async () => {
    try {
      setClearingCache(true);
      await apiPost("/graph/geoip/clear_cache");
      setGeoCache({});
      setGraphData({ nodes: [], edges: [], highRiskNodes: [] });
      if (pendingGeoIpsRef.current) pendingGeoIpsRef.current.clear();
      await loadTopology();
    } catch (e) {
      console.error("Failed to clear GeoIP cache:", e);
    } finally {
      setTimeout(() => setClearingCache(false), 500);
    }
  };

  // Seamlessly merge REST topology with real-time liveFlows from WebSocket
  const combinedGraph = useMemo(() => {
    const nodesMap = new Map();
    (graphData.nodes || []).forEach((n) => nodesMap.set(n.id, { ...n }));

    const edges = [...(graphData.edges || [])];
    const seenSessionKeys = new Set(
      edges.map((e) => e.session_key || `${e.source}->${e.target}`),
    );

    const nowMs = Date.now();
    (liveFlows || []).forEach((flow) => {
      // In live mode, ignore any stale simulated flows
      if (systemMode === "live" && flow.source === "simulated") return;

      // Discard stale flows older than 90 seconds from the live map
      const flowTs = flow.timestamp
        ? new Date(flow.timestamp).getTime()
        : flow._ts
          ? new Date(flow._ts).getTime()
          : nowMs;
      if (nowMs - flowTs > 90000) return;

      const src = flow.src_ip;
      const dst = flow.dst_ip;
      if (!src || !dst) return;
      const key = flow.session_key || `${src}->${dst}@${flow.dst_port || 80}`;
      if (seenSessionKeys.has(key)) return;
      seenSessionKeys.add(key);

      const prob =
        flow.predicted_probability ??
        flow.latest_risk_score ??
        flow.infiltration_prob ??
        0;
      const stage = flow.predicted_stage || "Benign";
      const app = flow.app_name || flow.process_name || "Network Flow";

      // Register source and destination nodes if new
      [src, dst].forEach((ip) => {
        if (!nodesMap.has(ip)) {
          const isInt =
            (hostIdentity?.local_ips && hostIdentity.local_ips.includes(ip)) ||
            isLocalHostOrLAN(ip);

          // Real GeoIP from flow metadata or client cache
          const flowGeo =
            (ip === src ? flow.src_geo : flow.dst_geo) || geoCache[ip];
          const hasGeo =
            flowGeo &&
            typeof flowGeo.latitude === "number" &&
            typeof flowGeo.longitude === "number";

          if (!isInt && !hasGeo && !pendingGeoIpsRef.current.has(ip)) {
            fetchMissingGeo(ip);
          }

          nodesMap.set(ip, {
            id: ip,
            role: ip === src ? "source" : "destination",
            max_risk: prob,
            session_count: 1,
            max_stage: stage,
            apps: app && app.toLowerCase() !== "unknown" ? [app] : [],
            is_internal: isInt,
            latitude: isInt
              ? deviceLocation.latitude || 18.5
              : hasGeo
                ? flowGeo.latitude
                : null,
            longitude: isInt
              ? deviceLocation.longitude || 73.8
              : hasGeo
                ? flowGeo.longitude
                : null,
            city: isInt
              ? deviceLocation.city
                ? `LAN (${deviceLocation.city})`
                : "Local Host"
              : hasGeo && flowGeo.city
                ? flowGeo.city
                : flow.dst_identity || "External Host",
            country: isInt
              ? deviceLocation.country || "Local Network (Defender HQ)"
              : hasGeo && flowGeo.country
                ? flowGeo.country
                : "Remote",
            org: isInt
              ? "Defender Local Interface"
              : hasGeo && flowGeo.org
                ? flowGeo.org
                : flow.dst_identity ||
                  flow.src_identity ||
                  app ||
                  "External Transit",
            flag: isInt
              ? deviceLocation.flag || "📍"
              : hasGeo && flowGeo.flag
                ? flowGeo.flag
                : "🌐",
          });
        } else {
          const n = nodesMap.get(ip);
          if (prob > (n.max_risk || 0)) n.max_risk = prob;
          if (stage !== "Benign") n.max_stage = stage;
          if (
            app &&
            app.toLowerCase() !== "unknown" &&
            (!n.apps || !n.apps.includes(app))
          ) {
            n.apps = [...(n.apps || []), app];
          }
          if (!n.is_internal && (n.latitude == null || n.longitude == null)) {
            const flowGeo =
              (ip === src ? flow.src_geo : flow.dst_geo) || geoCache[ip];
            if (
              flowGeo &&
              typeof flowGeo.latitude === "number" &&
              typeof flowGeo.longitude === "number"
            ) {
              n.latitude = flowGeo.latitude;
              n.longitude = flowGeo.longitude;
              if (flowGeo.city) n.city = flowGeo.city;
              if (flowGeo.country) n.country = flowGeo.country;
              if (flowGeo.org) n.org = flowGeo.org;
              if (flowGeo.flag) n.flag = flowGeo.flag;
            }
          }
        }
      });

      const srcNode = nodesMap.get(src);
      const dstNode = nodesMap.get(dst);

      const srcLat =
        srcNode?.latitude ??
        (srcNode?.is_internal ? deviceLocation.latitude : null);
      const srcLon =
        srcNode?.longitude ??
        (srcNode?.is_internal ? deviceLocation.longitude : null);
      const dstLat =
        dstNode?.latitude ??
        (dstNode?.is_internal ? deviceLocation.latitude : null);
      const dstLon =
        dstNode?.longitude ??
        (dstNode?.is_internal ? deviceLocation.longitude : null);

      edges.push({
        source: src,
        target: dst,
        session_key: key,
        stage,
        probability: prob,
        flow_count: flow.flow_count || 1,
        app_name: app,
        protocol: flow.protocol || "TCP",
        src_lat: srcLat,
        src_lon: srcLon,
        dst_lat: dstLat,
        dst_lon: dstLon,
        src_city:
          srcNode?.city ||
          (srcNode?.is_internal ? deviceLocation.city : "Host"),
        dst_city: dstNode?.city || "Remote",
        src_country:
          srcNode?.country ||
          (srcNode?.is_internal ? deviceLocation.country : "Local Network"),
        dst_country: dstNode?.country || "Global",
        src_flag:
          srcNode?.flag || (srcNode?.is_internal ? deviceLocation.flag : "🌐"),
        dst_flag: dstNode?.flag || "🌐",
      });
    });

    return {
      nodes: Array.from(nodesMap.values()),
      edges,
    };
  }, [
    graphData.nodes,
    graphData.edges,
    liveFlows,
    hostIdentity,
    deviceLocation,
    geoCache,
    fetchMissingGeo,
  ]);

  // Filtered nodes based on densityMode, hideBroadcast, stageFilter, and search
  const visibleNodes = useMemo(() => {
    let list = combinedGraph.nodes || [];

    // Filter out broadcast/multicast noise unless searched, NEVER filter active threats!
    if (hideBroadcast && !searchQuery.trim()) {
      list = list.filter((n) => {
        const isThreat =
          (n.max_risk || 0) >= 0.25 ||
          (n.max_stage && n.max_stage !== "Benign");
        if (isThreat) return true;
        return !isMulticastOrBroadcast(n.id);
      });
    }

    // Stage Filter
    if (stageFilter !== "all") {
      list = list.filter((n) => {
        const theme = getStageTheme(n.max_stage, n.max_risk);
        return (
          theme.phase === stageFilter ||
          theme.name.toLowerCase().includes(stageFilter)
        );
      });
    }

    // Density Limiting
    if (densityMode === "threats") {
      list = list.filter(
        (n) =>
          (n.max_risk || 0) >= 0.25 ||
          (n.max_stage && n.max_stage !== "Benign"),
      );
    } else if (densityMode === "focused" && !searchQuery.trim()) {
      const internal = list.filter((n) => isInternalIP(n.id) || n.is_internal);
      const threats = list.filter(
        (n) =>
          !isInternalIP(n.id) &&
          !n.is_internal &&
          ((n.max_risk || 0) >= 0.25 ||
            (n.max_stage && n.max_stage !== "Benign")),
      );
      const others = list.filter(
        (n) =>
          !isInternalIP(n.id) &&
          !n.is_internal &&
          (n.max_risk || 0) < 0.25 &&
          (!n.max_stage || n.max_stage === "Benign"),
      );

      const budget = 80;
      const combined = [...internal, ...threats];
      for (const ext of others) {
        if (combined.length >= budget) break;
        combined.push(ext);
      }
      list = combined;
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (n) =>
          n.id.toLowerCase().includes(q) ||
          (n.city && n.city.toLowerCase().includes(q)) ||
          (n.country && n.country.toLowerCase().includes(q)) ||
          (n.org && n.org.toLowerCase().includes(q)) ||
          (Array.isArray(n.apps) &&
            n.apps.some((a) => a.toLowerCase().includes(q))),
      );
    }

    return list;
  }, [
    combinedGraph.nodes,
    densityMode,
    hideBroadcast,
    stageFilter,
    searchQuery,
  ]);

  // Filtered edges
  const visibleEdges = useMemo(() => {
    const nodeSet = new Set(visibleNodes.map((n) => n.id));
    return (combinedGraph.edges || []).filter((e) => {
      // Discard self loops on the world map
      if (e.source === e.target) return false;
      const matchesNodes = nodeSet.has(e.source) && nodeSet.has(e.target);
      if (!matchesNodes) return false;
      if (stageFilter === "all") return true;
      const theme = getStageTheme(e.stage, e.probability);
      return (
        theme.phase === stageFilter ||
        theme.name.toLowerCase().includes(stageFilter)
      );
    });
  }, [combinedGraph.edges, visibleNodes, stageFilter]);

  // Datacenter / Geographic Location Clusters
  // Solves the multi-IP datacenter edgecase: if 10 IPs exist at 1 datacenter and 1 is an attack,
  // the cluster inherits the MAXIMUM attack stage and risk, ensuring threats are never hidden.
  const locationClusters = useMemo(() => {
    const clusterMap = new Map();

    visibleNodes.forEach((node) => {
      if (node.latitude == null || node.longitude == null) return;
      // Key rounded to ~0.02 degrees (~2km radius) to group colocated datacenter hosts
      const key = `${node.latitude.toFixed(2)}_${node.longitude.toFixed(2)}`;

      if (!clusterMap.has(key)) {
        clusterMap.set(key, {
          key,
          latitude: node.latitude,
          longitude: node.longitude,
          city: node.city || "Unknown",
          region: node.region || "",
          country: node.country || "Local",
          country_code: node.country_code || "",
          flag: node.flag || "🌐",
          org: node.org || "Network Datacenter",
          is_internal:
            (hostIdentity?.local_ips &&
              hostIdentity.local_ips.includes(node.id)) ||
            node.is_internal ||
            isLocalHostOrLAN(node.id),
          nodes: [],
          all_apps: new Set(),
          max_risk: 0,
          max_stage: "Benign",
          has_threat: false,
          threat_count: 0,
          total_ips: 0,
        });
      }

      const cluster = clusterMap.get(key);
      cluster.nodes.push(node);
      cluster.total_ips = cluster.nodes.length;

      // Collect all applications observed across all IPs at this datacenter
      if (Array.isArray(node.apps)) {
        node.apps.forEach((a) => {
          if (a && a.toLowerCase() !== "unknown") cluster.all_apps.add(a);
        });
      }

      const risk = node.max_risk || 0;
      const isThreat =
        risk >= 0.35 || (node.max_stage && node.max_stage !== "Benign");

      if (risk > cluster.max_risk) {
        cluster.max_risk = risk;
      }

      const theme = getStageTheme(node.max_stage, risk);
      const currentClusterTheme = getStageTheme(
        cluster.max_stage,
        cluster.max_risk,
      );
      if (theme.rank > currentClusterTheme.rank) {
        cluster.max_stage = node.max_stage;
      }

      if (isThreat) {
        cluster.has_threat = true;
        cluster.threat_count += 1;
      }
    });

    return Array.from(clusterMap.values());
  }, [visibleNodes, hostIdentity]);

  // Stage counts for stage palette badges
  const stageCounts = useMemo(() => {
    const counts = {
      all: combinedGraph.edges?.length || 0,
      benign: 0,
      recon: 0,
      initial: 0,
      lateral: 0,
      c2: 0,
      exfil: 0,
    };
    (combinedGraph.edges || []).forEach((e) => {
      if (e.source === e.target) return;
      const theme = getStageTheme(e.stage, e.probability);
      if (theme.phase === "00") counts.benign++;
      else if (theme.phase === "01") counts.recon++;
      else if (theme.phase === "02") counts.initial++;
      else if (theme.phase === "03") counts.lateral++;
      else if (theme.phase === "04") counts.c2++;
      else if (theme.phase === "05") counts.exfil++;
    });
    return counts;
  }, [combinedGraph.edges]);

  // Peak risk score across visible traffic
  const peakRisk = useMemo(() => {
    let max = 0;
    visibleEdges.forEach((e) => {
      if ((e.probability || 0) > max) max = e.probability;
    });
    return max;
  }, [visibleEdges]);

  // Active adversary flows prioritized by risk
  const threatFlows = useMemo(() => {
    return [...visibleEdges]
      .filter(
        (e) =>
          (e.probability || 0) >= 0.25 || (e.stage && e.stage !== "Benign"),
      )
      .sort((a, b) => (b.probability || 0) - (a.probability || 0));
  }, [visibleEdges]);

  // Initialize Leaflet with ESRI World Dark Gray Canvas and Smooth Zoom Configuration
  useEffect(() => {
    if (viewMode !== "geo") return;
    if (!mapContainerRef.current) return;

    if (!leafletMapRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [25.0, 15.0],
        zoom: 1.5,
        minZoom: 1.0,
        maxZoom: 16,
        zoomControl: false,
        attributionControl: false,
        // Smooth Zoom Enhancements
        zoomAnimation: true,
        zoomAnimationThreshold: 8,
        fadeAnimation: true,
        markerZoomAnimation: true,
        zoomSnap: 0.25, // Fractional zoom for ultra-smooth zoom levels
        zoomDelta: 0.5, // Smooth 0.5 step per scroll increment
        wheelPxPerZoomLevel: 120, // Inertia scroll distance
        wheelDebounceTime: 40,
      });

      const baseTileUrl = isDark
        ? "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
        : "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}";

      L.tileLayer(baseTileUrl, {
        maxZoom: 16,
        subdomains: ["server", "services"],
      }).addTo(map);

      if (isDark) {
        L.tileLayer(
          "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
          { maxZoom: 16, opacity: 0.65 },
        ).addTo(map);
      }

      L.control.zoom({ position: "bottomleft" }).addTo(map);

      markersLayerRef.current = L.layerGroup().addTo(map);
      linesLayerRef.current = L.layerGroup().addTo(map);

      leafletMapRef.current = map;
    } else {
      leafletMapRef.current.invalidateSize();
    }
  }, [viewMode, isDark]);

  // Update Geo Markers & Cyber Arcs
  useEffect(() => {
    if (viewMode !== "geo" || !leafletMapRef.current) return;

    const map = leafletMapRef.current;
    const markersLayer = markersLayerRef.current;
    const linesLayer = linesLayerRef.current;

    if (!markersLayer || !linesLayer) return;

    markersLayer.clearLayers();
    linesLayer.clearLayers();

    const bounds = [];

    // 1. Draw smooth cyber arcs with dual-pass laser rendering
    visibleEdges.forEach((edge) => {
      if (
        edge.src_lat != null &&
        edge.src_lon != null &&
        edge.dst_lat != null &&
        edge.dst_lon != null
      ) {
        const p1 = [edge.src_lat, edge.src_lon];
        const p2 = [edge.dst_lat, edge.dst_lon];
        bounds.push(p1, p2);

        const isThreat =
          (edge.probability || 0) >= 0.35 ||
          (edge.stage && edge.stage !== "Benign");
        const stageTheme = getStageTheme(edge.stage, edge.probability);
        const lineColor = stageTheme.color;
        const isHovered =
          focusedFlow && focusedFlow.session_key === edge.session_key;

        // Generate smooth parabolic cyber arc (touching endpoints exactly with zero spikes)
        const arcPoints = createSmoothCyberArc(p1, p2, 30);

        // Pass 1: Outer glowing neon halo
        const haloLine = L.polyline(arcPoints, {
          color: lineColor,
          weight: isHovered ? 7.0 : isThreat ? 5.0 : 3.2,
          opacity: isHovered ? 0.65 : isThreat ? 0.35 : 0.16,
          interactive: false,
        });
        linesLayer.addLayer(haloLine);

        // Pass 2: Sharp foreground laser core with flowing animation
        const coreLine = L.polyline(arcPoints, {
          color: lineColor,
          weight: isHovered ? 3.4 : isThreat ? 2.6 : 1.6,
          opacity: isHovered ? 1.0 : isThreat ? 0.95 : 0.75,
          className: isThreat ? "leaflet-threat-line" : "leaflet-active-line",
        });

        coreLine.on("click", () => {
          setSelectedEntity({ type: "flow", data: edge });
          setFocusedFlow(edge);
        });

        coreLine.on("mouseover", () => {
          setFocusedFlow(edge);
        });

        coreLine.on("mouseout", () => {
          setFocusedFlow(null);
        });

        coreLine.bindTooltip(
          `
          <div style="font-family: var(--font-mono); font-size: 11px; padding: 2px;">
            <div style="font-weight: 700; color: var(--text-primary); margin-bottom: 2px;">
              ${edge.src_flag || "🌐"} ${edge.src_city || deviceLocation.city || "Local Host"} &rarr; ${edge.dst_flag || "🌐"} ${edge.dst_city || "Remote"}
            </div>
            <div>
              <span style="color: ${lineColor}; font-weight: 700;">PHASE ${stageTheme.phase}: ${stageTheme.name}</span> &bull; 
              <span style="color: ${isThreat ? "var(--danger)" : "var(--success)"}; font-weight: 700;">Risk: ${(edge.probability * 100).toFixed(1)}%</span>
            </div>
            <div style="color: var(--text-muted); font-size: 9.5px; margin-top: 2px;">
              ${formatShortIP(edge.source)} &rarr; ${formatShortIP(edge.target)} &bull; ${edge.app_name || "Flow"}
            </div>
          </div>
        `,
          { sticky: true },
        );

        linesLayer.addLayer(coreLine);
      }
    });

    // 2. Plot real geographic datacenter / location cluster markers
    locationClusters.forEach((cluster) => {
      const lat = cluster.latitude;
      const lon = cluster.longitude;
      if (lat == null || lon == null) return;

      bounds.push([lat, lon]);
      const icon = createClusterMarkerIcon(cluster, isDark);
      const marker = L.marker([lat, lon], { icon });

      const stageTheme = getStageTheme(cluster.max_stage, cluster.max_risk);
      const appsList = Array.from(cluster.all_apps);
      const appsDisplay =
        appsList.length > 0 ? appsList.slice(0, 3).join(", ") : "Active Flows";

      // Sleek hover tooltip (without permanent box cluttering the map)
      marker.bindTooltip(
        cluster.is_internal
          ? `🛡️ DEFENDER NOC: ${(cluster.city || deviceLocation.city || "LOCAL HOST").toUpperCase()}, ${(cluster.country || deviceLocation.country || "DEFENDER HQ").toUpperCase()} (${cluster.total_ips} Active Interfaces)`
          : `${cluster.flag} ${cluster.city}, ${cluster.country} &bull; ${cluster.total_ips} IP${cluster.total_ips > 1 ? "s" : ""} &bull; ${appsDisplay} [${stageTheme.name} ${(cluster.max_risk * 100).toFixed(0)}%]`,
        { direction: "top", offset: [0, -12], opacity: 0.94 },
      );

      marker.on("click", () => {
        setSelectedEntity({ type: "cluster", data: cluster });
      });

      markersLayer.addLayer(marker);
    });

    // Auto-fit whole world on initial load so all nodes are visible in small view
    if (!hasInitialFittedRef.current && bounds.length > 0) {
      hasInitialFittedRef.current = true;
      try {
        map.fitBounds(bounds, {
          padding: [25, 25],
          maxZoom: 1.75,
          animate: false,
        });
      } catch {
        map.setView([25.0, 15.0], 1.5);
      }
    }
  }, [locationClusters, visibleEdges, isDark, focusedFlow, deviceLocation]);

  // Recenter Map
  const handleRecenter = () => {
    if (!leafletMapRef.current) return;
    const bounds = locationClusters
      .filter((c) => c.latitude != null && c.longitude != null)
      .map((c) => [c.latitude, c.longitude]);
    if (bounds.length > 0) {
      leafletMapRef.current.fitBounds(bounds, {
        padding: [25, 25],
        maxZoom: 1.75,
      });
    } else {
      leafletMapRef.current.setView([25.0, 15.0], 1.5);
    }
  };

  // Toggle fullscreen
  const toggleFullscreen = () => {
    setIsFullscreen((prev) => {
      const next = !prev;
      if (next) {
        setShowThreatRadar(true);
      }
      setTimeout(() => {
        if (leafletMapRef.current) leafletMapRef.current.invalidateSize();
        if (viewMode === "logical") fitAllTopology();
      }, 250);
      return next;
    });
  };

  // Dynamic Blueprint Network Topology Model (100% Real Live Network Data)
  const logicalLayout = useMemo(() => {
    const width = 1040;
    const canvasHeight = 440;

    const rawNodes = combinedGraph.nodes || [];
    const rawEdges = combinedGraph.edges || [];

    const nodeMap = new Map();
    rawNodes.forEach((n) => nodeMap.set(n.id, n));

    // 1. Identify Local Host / LAN Nodes
    const internalNodes = rawNodes.filter(
      (n) =>
        (hostIdentity?.local_ips && hostIdentity.local_ips.includes(n.id)) ||
        isLocalHostOrLAN(n.id) ||
        n.is_internal,
    );

    // Compute LAN flows and identify primary LAN host
    let primaryLanIp =
      hostIdentity?.primary_ip || internalNodes[0]?.id || "Local Machine";
    const lanHostname = hostIdentity?.hostname || "Local Machine";
    const lanAppsSet = new Set();
    let lanFlowCount = 0;
    let lanMaxRisk = 0;
    let lanMaxStage = "Benign";

    if (internalNodes.length > 0) {
      let mostActive =
        internalNodes.find((n) => n.id === primaryLanIp) ||
        internalNodes.find(
          (n) => n.id.startsWith("192.168.") || n.id.startsWith("10."),
        ) ||
        internalNodes[0];

      internalNodes.forEach((n) => {
        (n.apps || []).forEach((a) => {
          if (a && a.toLowerCase() !== "unknown") lanAppsSet.add(a);
        });
        if ((n.max_risk || 0) > lanMaxRisk) lanMaxRisk = n.max_risk;
        if (n.max_stage && n.max_stage !== "Benign") lanMaxStage = n.max_stage;
      });
      if (mostActive) primaryLanIp = mostActive.id;
    }

    // Collect flow count for LAN
    rawEdges.forEach((e) => {
      const srcIsLocal =
        (hostIdentity?.local_ips &&
          hostIdentity.local_ips.includes(e.source)) ||
        isLocalHostOrLAN(e.source);
      const dstIsLocal =
        (hostIdentity?.local_ips &&
          hostIdentity.local_ips.includes(e.target)) ||
        isLocalHostOrLAN(e.target);
      if (srcIsLocal || dstIsLocal) {
        lanFlowCount += e.flow_count || 1;
        if (e.app_name && e.app_name.toLowerCase() !== "unknown") {
          lanAppsSet.add(e.app_name);
        }
      }
    });

    const lanAppsList = Array.from(lanAppsSet);

    // Derive gateway IP from LAN subnet dynamically
    let gatewayIp = "LAN Gateway";
    if (primaryLanIp && primaryLanIp.includes(".")) {
      const parts = primaryLanIp.split(".");
      if (parts.length === 4) {
        gatewayIp = `${parts[0]}.${parts[1]}.${parts[2]}.1`;
      }
    }

    // 2. Identify Active Threat(s) across ANY active node or edge
    const threatCandidates = [];
    rawNodes.forEach((n) => {
      if (
        (n.max_risk || 0) >= 0.25 ||
        (n.max_stage && n.max_stage !== "Benign")
      ) {
        threatCandidates.push({
          id: n.id,
          risk: n.max_risk || 0,
          stage: n.max_stage || "Initial Access",
          city: n.city,
          country: n.country,
          flag: n.flag,
          org: n.org,
          apps: n.apps,
          rawNode: n,
        });
      }
    });

    rawEdges.forEach((e) => {
      const prob = e.probability || 0;
      if (prob >= 0.25 || (e.stage && e.stage !== "Benign")) {
        // Evaluate both endpoints of a threat edge
        [e.source, e.target].forEach((ip) => {
          if (ip && !threatCandidates.some((t) => t.id === ip)) {
            threatCandidates.push({
              id: ip,
              risk: prob,
              stage: e.stage || "Initial Access",
              city: ip === e.source ? e.src_city : e.dst_city,
              country: ip === e.source ? e.src_country : e.dst_country,
              flag: ip === e.source ? e.src_flag : e.dst_flag,
              org:
                ip === e.source
                  ? "Adversary Infrastructure"
                  : "Target Endpoint",
              apps: [e.app_name || "Exploit Flow"],
              rawEdge: e,
            });
          }
        });
      }
    });

    threatCandidates.sort((a, b) => b.risk - a.risk);
    const activeThreat = threatCandidates[0] || null;

    // 3. Group REAL External Traffic into Legitimate Services
    const serviceClusters = new Map();

    rawEdges.forEach((e) => {
      const srcIsLocal =
        (hostIdentity?.local_ips &&
          hostIdentity.local_ips.includes(e.source)) ||
        isLocalHostOrLAN(e.source);
      const dstIsLocal =
        (hostIdentity?.local_ips &&
          hostIdentity.local_ips.includes(e.target)) ||
        isLocalHostOrLAN(e.target);

      if (srcIsLocal && dstIsLocal) {
        return; // Pure inter-host/LAN traffic
      }

      const remoteIp = srcIsLocal ? e.target : e.source;
      if (
        activeThreat &&
        (e.source === activeThreat.id || e.target === activeThreat.id)
      ) {
        return; // Isolated into the dedicated Threat slot
      }

      const node = nodeMap.get(remoteIp);
      const orgStr = String(node?.org || e.dst_city || remoteIp).toLowerCase();
      const appStr = String(e.app_name || "").toLowerCase();

      let serviceKey = "telecom";
      let displayName = "ISP & Telecom";
      let iconType = "database";
      let color = "#3B82F6";

      if (
        orgStr.includes("discord") ||
        appStr.includes("discord") ||
        orgStr.includes("cloudflare") ||
        remoteIp.startsWith("162.159.") ||
        remoteIp.startsWith("104.")
      ) {
        serviceKey = "cloudflare";
        displayName = "Discord & Cloudflare";
        iconType = "globe";
        color = "#0284C7";
      } else if (
        orgStr.includes("microsoft") ||
        appStr.includes("edge") ||
        appStr.includes("windows") ||
        orgStr.includes("azure") ||
        remoteIp.startsWith("20.") ||
        remoteIp.startsWith("2620:")
      ) {
        serviceKey = "microsoft";
        displayName = "Microsoft & Azure";
        iconType = "database";
        color = "#3B82F6";
      } else if (
        orgStr.includes("spotify") ||
        appStr.includes("spotify") ||
        appStr.includes("spotifylauncher")
      ) {
        serviceKey = "spotify";
        displayName = "Spotify Audio";
        iconType = "cloud";
        color = "#1DB954";
      } else if (
        orgStr.includes("google") ||
        appStr.includes("chrome") ||
        appStr.includes("agy") ||
        remoteIp.startsWith("8.8.") ||
        remoteIp.startsWith("142.250.")
      ) {
        serviceKey = "google";
        displayName = "Google Cloud";
        iconType = "database";
        color = "#3B82F6";
      } else if (
        orgStr.includes("akamai") ||
        orgStr.includes("github") ||
        orgStr.includes("fastly") ||
        remoteIp.startsWith("2600:1417")
      ) {
        serviceKey = "akamai";
        displayName = "Akamai & GitHub";
        iconType = "globe";
        color = "#0284C7";
      } else if (
        orgStr.includes("amazon") ||
        orgStr.includes("aws") ||
        remoteIp.startsWith("52.") ||
        remoteIp.startsWith("54.") ||
        remoteIp.startsWith("34.")
      ) {
        serviceKey = "aws";
        displayName = "AWS Infrastructure";
        iconType = "database";
        color = "#3B82F6";
      } else if (
        orgStr.includes("meta") ||
        appStr.includes("whatsapp") ||
        orgStr.includes("facebook") ||
        remoteIp.startsWith("157.240.")
      ) {
        serviceKey = "meta";
        displayName = "Meta & Messaging";
        iconType = "globe";
        color = "#0284C7";
      } else {
        const customName =
          node?.org &&
          node.org !== "External Autonomous System" &&
          node.org !== "External IP" &&
          node.org !== "Remote Origin"
            ? node.org.slice(0, 18)
            : node?.city
              ? `${node.city} Transit`
              : e.app_name && e.app_name !== "Network Flow"
                ? e.app_name
                : "External Service";
        serviceKey = `service_${customName.replace(/\s+/g, "_").toLowerCase()}`;
        displayName = customName;
        iconType = "globe";
        color = "#3B82F6";
      }

      if (!serviceClusters.has(serviceKey)) {
        serviceClusters.set(serviceKey, {
          key: serviceKey,
          displayName,
          iconType,
          color,
          flowCount: 0,
          ips: new Set(),
          apps: new Set(),
          maxRisk: 0,
          maxStage: "Benign",
          nodes: [],
          edges: [],
        });
      }

      const cluster = serviceClusters.get(serviceKey);
      cluster.flowCount += e.flow_count || 1;
      cluster.ips.add(remoteIp);
      if (e.app_name && e.app_name.toLowerCase() !== "unknown") {
        cluster.apps.add(e.app_name);
      }
      cluster.edges.push(e);
      if (node && !cluster.nodes.some((x) => x.id === node.id)) {
        cluster.nodes.push(node);
      }
      if ((e.probability || 0) > cluster.maxRisk)
        cluster.maxRisk = e.probability;
      if (e.stage && e.stage !== "Benign") cluster.maxStage = e.stage;
    });

    const sortedServices = Array.from(serviceClusters.values()).sort(
      (a, b) => b.flowCount - a.flowCount,
    );

    const topoNodes = [];
    const topoEdges = [];

    // Node 1: Host Machine / LAN (140, 220)
    const lanNodeId = "corporate_lan";
    const lanLabel =
      lanHostname && lanHostname !== "Local Machine"
        ? `${lanHostname} (${formatShortIP(primaryLanIp)})`
        : `Host: ${formatShortIP(primaryLanIp)}`;
    const lanSubtext = `${lanFlowCount} flows • ${lanAppsList.length > 0 ? lanAppsList.slice(0, 2).join(", ") : "Active"}`;

    topoNodes.push({
      id: lanNodeId,
      type: "lan",
      label: lanLabel,
      subtext: lanSubtext,
      iconType: "lan",
      x: 140,
      y: 220,
      color: lanMaxRisk >= 0.25 ? "#EF4444" : "#F97316",
      isThreat: lanMaxRisk >= 0.25,
      isGateway: false,
      raw: {
        id: primaryLanIp || "Local Machine",
        hostname: lanHostname,
        name: `${lanHostname} (${primaryLanIp})`,
        city: internalNodes[0]?.city || deviceLocation.city || "Local Host",
        country:
          internalNodes[0]?.country || deviceLocation.country || "Defender HQ",
        org: internalNodes[0]?.org || "Protected Network Interface",
        interfaces: hostIdentity?.interfaces || [],
        apps: lanAppsList.length > 0 ? lanAppsList : ["System Host Services"],
        flows: lanFlowCount,
        total_ips: internalNodes.length || 1,
        max_risk: lanMaxRisk,
        max_stage: lanMaxStage,
        nodes: internalNodes,
      },
    });

    // Node 2: Gateway (320, 220)
    const gwNodeId = "gateway";
    topoNodes.push({
      id: gwNodeId,
      type: "gateway",
      label: `Gateway (${gatewayIp})`,
      subtext: "Core Router",
      iconType: "gateway",
      x: 320,
      y: 220,
      color: "#10B981",
      isThreat: false,
      isGateway: true,
      raw: {
        id: gatewayIp,
        name: "Core Network Gateway",
        status: "Defended Core Router",
        city: `${deviceLocation.city || "Local"} Gateway`,
        country: deviceLocation.country || "Local Network",
        flows: rawEdges.length,
        total_ips: 1,
      },
    });

    // Connect LAN to Gateway
    topoEdges.push({
      source: lanNodeId,
      target: gwNodeId,
      isThreat: false,
      raw: rawEdges.find(
        (e) => isInternalIP(e.source) || isInternalIP(e.target),
      ) || {
        source: primaryLanIp,
        target: gatewayIp,
        app_name: "Internal LAN Routing",
        protocol: "IP",
        probability: 0,
        stage: "Benign",
      },
    });

    // Slot mappings (matching visual coordinates from reference blueprint)
    const externalSlotPositions = [
      { x: 500, y: 100 },
      { x: 500, y: 220 },
      { x: 500, y: 340 },
      { x: 700, y: 100 },
      { x: 700, y: 340 },
      { x: 890, y: 100 },
      { x: 890, y: 340 },
    ];

    sortedServices
      .slice(0, externalSlotPositions.length)
      .forEach((service, idx) => {
        const pos = externalSlotPositions[idx];
        const sNodeId = `service_${service.key}`;
        const appsArr = Array.from(service.apps);
        const ipsArr = Array.from(service.ips);

        topoNodes.push({
          id: sNodeId,
          type: "service",
          label: `${service.displayName} (${service.flowCount})`,
          subtext: `${ipsArr.length} IP${ipsArr.length > 1 ? "s" : ""} • ${appsArr[0] || "Active"}`,
          iconType: service.iconType,
          x: pos.x,
          y: pos.y,
          color: service.color,
          isThreat: false,
          isGateway: false,
          raw: {
            id: ipsArr[0] || service.key,
            name: service.displayName,
            org: service.displayName,
            city: service.nodes[0]?.city || "External Cloud",
            country: service.nodes[0]?.country || "Global",
            apps: appsArr.length > 0 ? appsArr : ["Cloud Services"],
            flows: service.flowCount,
            total_ips: ipsArr.length,
            ips: ipsArr,
            max_risk: service.maxRisk,
            max_stage: service.maxStage,
            nodes: service.nodes,
          },
        });

        topoEdges.push({
          source: gwNodeId,
          target: sNodeId,
          isThreat: false,
          raw: service.edges[0] || {
            source: gatewayIp,
            target: ipsArr[0] || service.key,
            app_name: appsArr[0] || service.displayName,
            protocol: "TCP",
            probability: service.maxRisk,
            stage: service.maxStage,
          },
        });
      });

    // Threat Slot at [700, 220]
    if (activeThreat) {
      const threatNodeId = "threat_node";
      const threatApps =
        Array.isArray(activeThreat.apps) && activeThreat.apps.length > 0
          ? activeThreat.apps
          : ["Adversary Penetration Flow"];

      topoNodes.push({
        id: threatNodeId,
        type: "threat",
        label: `Threat: ${formatShortIP(activeThreat.id)}`,
        subtext: `${activeThreat.stage} (${(activeThreat.risk * 100).toFixed(0)}%)`,
        iconType: "threat",
        x: 700,
        y: 220,
        color: "#EF4444",
        isThreat: true,
        isGateway: false,
        risk: activeThreat.risk,
        raw: {
          id: activeThreat.id,
          name: `Adversary Endpoint (${activeThreat.id})`,
          city: activeThreat.city || "Remote Adversary",
          country: activeThreat.country || "External Origin",
          org: activeThreat.org || "Threat Actor Infrastructure",
          apps: threatApps,
          max_risk: activeThreat.risk,
          max_stage: activeThreat.stage,
          flows:
            activeThreat.rawEdge?.flow_count ||
            activeThreat.rawNode?.session_count ||
            1,
          total_ips: 1,
          nodes: activeThreat.rawNode ? [activeThreat.rawNode] : [],
        },
      });

      topoEdges.push({
        source: gwNodeId,
        target: threatNodeId,
        isThreat: true,
        risk: activeThreat.risk,
        stage: activeThreat.stage,
        raw: activeThreat.rawEdge || {
          source: gatewayIp,
          target: activeThreat.id,
          app_name: threatApps[0],
          protocol: "TCP",
          probability: activeThreat.risk,
          stage: activeThreat.stage,
        },
      });
    } else {
      const cleanNodeId = "clean_defense";
      topoNodes.push({
        id: cleanNodeId,
        type: "service",
        label: "Defense Nominal",
        subtext: "0 Active Threats",
        iconType: "gateway",
        x: 700,
        y: 220,
        color: "#10B981",
        isThreat: false,
        isGateway: false,
        raw: {
          id: "0.0.0.0/0",
          name: "Nominal Defense State",
          status: "Network Monitored & Defended",
          city: `${deviceLocation.city || "Local"} NOC`,
          country: deviceLocation.country || "Local Network",
          flows: 0,
          total_ips: 0,
          apps: ["Intrusion Prevention Engine"],
          max_risk: 0,
          max_stage: "Benign",
        },
      });

      topoEdges.push({
        source: gwNodeId,
        target: cleanNodeId,
        isThreat: false,
        raw: {
          source: gatewayIp,
          target: "Clean Baseline",
          app_name: "Active Posture Monitor",
          protocol: "ICMP",
          probability: 0,
          stage: "Benign",
        },
      });
    }

    const nodeCoords = new Map(topoNodes.map((n) => [n.id, n]));
    return {
      nodeCoords,
      topoNodes,
      topoEdges,
      nodes: topoNodes,
      edges: topoEdges,
      width,
      canvasHeight,
    };
  }, [combinedGraph.nodes, combinedGraph.edges, hostIdentity, deviceLocation]);

  // Auto-fit entire topology so all 3 columns and all nodes are visible without cutoffs
  const fitAllTopology = useCallback(() => {
    if (!topoContainerRef.current) return;
    const { clientWidth, clientHeight } = topoContainerRef.current;
    if (clientWidth <= 0 || clientHeight <= 0) return;

    const layoutWidth = logicalLayout.width || 1040;
    const layoutHeight = logicalLayout.canvasHeight || 440;

    const paddingX = 30;
    const paddingY = 30;

    const scaleX = (clientWidth - paddingX) / layoutWidth;
    const scaleY = (clientHeight - paddingY) / layoutHeight;
    const initialScale = Math.min(scaleX, scaleY);
    const clampedScale = Math.max(0.35, Math.min(initialScale, 1.15));

    const scaledWidth = layoutWidth * clampedScale;
    const scaledHeight = layoutHeight * clampedScale;
    const panX = Math.round((clientWidth - scaledWidth) / 2);
    const panY = Math.max(6, Math.round((clientHeight - scaledHeight) / 2));

    setTopoZoom(Number(clampedScale.toFixed(3)));
    setTopoPan({ x: panX, y: panY });
  }, [logicalLayout.width, logicalLayout.canvasHeight]);

  // Effect to automatically fit topology on viewMode change, data change, or fullscreen
  useEffect(() => {
    if (viewMode === "logical") {
      const timer = setTimeout(fitAllTopology, 60);
      return () => clearTimeout(timer);
    }
  }, [viewMode, fitAllTopology, isFullscreen]);

  // Window resize listener to keep topology fitted
  useEffect(() => {
    const handleResize = () => {
      if (viewMode === "logical") fitAllTopology();
    };
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [viewMode, fitAllTopology]);

  // Smooth wheel zoom for Topology
  const handleTopoWheel = (e) => {
    e.preventDefault();
    if (!topoContainerRef.current) return;

    const rect = topoContainerRef.current.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
    const nextZoom = Math.max(0.3, Math.min(2.5, topoZoom * zoomFactor));

    const ratio = nextZoom / topoZoom;
    const nextPanX = mouseX - (mouseX - topoPan.x) * ratio;
    const nextPanY = mouseY - (mouseY - topoPan.y) * ratio;

    setTopoZoom(Number(nextZoom.toFixed(3)));
    setTopoPan({ x: Math.round(nextPanX), y: Math.round(nextPanY) });
  };

  // Mouse pan handling for Topology
  const handleTopoMouseDown = (e) => {
    if (e.button !== 0) return;
    if (e.target.closest("button")) return;
    setIsPanningTopo(true);
    panStartRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      panX: topoPan.x,
      panY: topoPan.y,
      hasMoved: false,
    };
  };

  const handleTopoMouseMove = (e) => {
    if (!isPanningTopo) return;
    const dx = e.clientX - panStartRef.current.startX;
    const dy = e.clientY - panStartRef.current.startY;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
      panStartRef.current.hasMoved = true;
    }
    setTopoPan({
      x: panStartRef.current.panX + dx,
      y: panStartRef.current.panY + dy,
    });
  };

  const handleTopoMouseUp = () => {
    setIsPanningTopo(false);
  };

  // Zoom button handlers
  const handleTopoZoomIn = () => {
    if (!topoContainerRef.current) return;
    const { clientWidth, clientHeight } = topoContainerRef.current;
    const centerX = clientWidth / 2;
    const centerY = clientHeight / 2;
    const nextZoom = Math.min(2.5, topoZoom * 1.25);
    const ratio = nextZoom / topoZoom;
    setTopoZoom(Number(nextZoom.toFixed(3)));
    setTopoPan({
      x: Math.round(centerX - (centerX - topoPan.x) * ratio),
      y: Math.round(centerY - (centerY - topoPan.y) * ratio),
    });
  };

  const handleTopoZoomOut = () => {
    if (!topoContainerRef.current) return;
    const { clientWidth, clientHeight } = topoContainerRef.current;
    const centerX = clientWidth / 2;
    const centerY = clientHeight / 2;
    const nextZoom = Math.max(0.3, topoZoom * 0.8);
    const ratio = nextZoom / topoZoom;
    setTopoZoom(Number(nextZoom.toFixed(3)));
    setTopoPan({
      x: Math.round(centerX - (centerX - topoPan.x) * ratio),
      y: Math.round(centerY - (centerY - topoPan.y) * ratio),
    });
  };

  // Connected nodes & edges set when hovering over a node
  const activeConnectionSet = useMemo(() => {
    if (!hoveredNodeId) return null;
    const connectedNodeIds = new Set([hoveredNodeId]);
    const connectedEdgeIndices = new Set();
    const edgesList = logicalLayout.topoEdges || logicalLayout.edges || [];

    edgesList.forEach((e, idx) => {
      if (e.source === hoveredNodeId || e.target === hoveredNodeId) {
        connectedNodeIds.add(e.source);
        connectedNodeIds.add(e.target);
        connectedEdgeIndices.add(idx);
      }
    });

    return { nodeIds: connectedNodeIds, edgeIndices: connectedEdgeIndices };
  }, [hoveredNodeId, logicalLayout.topoEdges, logicalLayout.edges]);

  return (
    <div
      ref={containerRef}
      className={`garud-map-wrapper ${isFullscreen ? "fullscreen" : ""}`}
      style={{
        height: isFullscreen ? "100vh" : `${height}px`,
        position: isFullscreen ? "fixed" : "relative",
        inset: isFullscreen ? "0" : "auto",
        zIndex: isFullscreen ? 9999 : 1,
        background: "var(--bg-surface)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Primary Header Controls Bar */}
      <div
        className="garud-map-header-bar"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "6px 12px",
          background: "var(--bg-raised)",
          borderBottom: "1px solid var(--border)",
          fontFamily: "var(--font-mono)",
          fontSize: "0.72rem",
          gap: 10,
          flexWrap: "wrap",
        }}
      >
        {/* Left: View Mode Switcher */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              display: "inline-flex",
              background: "var(--bg-inset)",
              borderRadius: "var(--radius-sm)",
              padding: 2,
            }}
          >
            <button
              onClick={() => setViewMode("geo")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "3px 8px",
                border: "none",
                borderRadius: "var(--radius-sm)",
                background:
                  viewMode === "geo" ? "var(--bg-raised)" : "transparent",
                color:
                  viewMode === "geo" ? "var(--accent)" : "var(--text-muted)",
                cursor: "pointer",
                fontWeight: viewMode === "geo" ? 700 : 500,
                fontSize: "0.68rem",
              }}
            >
              <Globe size={12} /> WORLD MAP
            </button>
            <button
              onClick={() => setViewMode("logical")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "3px 8px",
                border: "none",
                borderRadius: "var(--radius-sm)",
                background:
                  viewMode === "logical" ? "var(--bg-raised)" : "transparent",
                color:
                  viewMode === "logical"
                    ? "var(--accent)"
                    : "var(--text-muted)",
                cursor: "pointer",
                fontWeight: viewMode === "logical" ? 700 : 500,
                fontSize: "0.68rem",
              }}
            >
              <Network size={12} /> TOPOLOGY
            </button>
          </div>
        </div>

        {/* Center: Search Box */}
        <div
          style={{
            position: "relative",
            minWidth: 170,
            maxWidth: 240,
            flex: 1,
          }}
        >
          <Search
            size={11}
            style={{
              position: "absolute",
              left: 7,
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--text-muted)",
            }}
          />
          <input
            type="text"
            placeholder="Search IP, App, City, Org..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              padding: "3px 7px 3px 24px",
              background: "var(--bg-inset)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              fontSize: "0.70rem",
              color: "var(--text-primary)",
              fontFamily: "var(--font-mono)",
              outline: "none",
            }}
          />
        </div>

        {/* Right: Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {viewMode === "geo" && (
            <button
              onClick={() => setShowThreatRadar((prev) => !prev)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                padding: "2px 7px",
                background: showThreatRadar
                  ? "rgba(57, 223, 235, 0.16)"
                  : "transparent",
                border: `1px solid ${
                  showThreatRadar ? "#39DFEB" : "var(--border)"
                }`,
                borderRadius: "var(--radius-sm)",
                color: showThreatRadar ? "#39DFEB" : "var(--text-secondary)",
                cursor: "pointer",
                fontSize: "0.68rem",
                fontWeight: showThreatRadar ? 700 : 500,
                transition: "all 0.15s ease",
              }}
              title="Toggle Global Threat Radar Overlay"
            >
              <Radio
                size={10}
                className={showThreatRadar ? "pulse-fast" : ""}
              />{" "}
              THREAT RADAR
            </button>
          )}

          {viewMode === "geo" && (
            <button
              onClick={handleRecenter}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                padding: "2px 6px",
                background: "transparent",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: "var(--text-secondary)",
                cursor: "pointer",
                fontSize: "0.68rem",
              }}
              title="Recenter Map View"
            >
              <RotateCcw size={10} /> RECENTER
            </button>
          )}

          {viewMode === "logical" && (
            <button
              onClick={fitAllTopology}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                padding: "2px 6px",
                background: "transparent",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: "var(--text-secondary)",
                cursor: "pointer",
                fontSize: "0.68rem",
              }}
              title="Fit Entire Topology to Screen"
            >
              <RotateCcw size={10} /> FIT ALL
            </button>
          )}

          <button
            onClick={handleClearMapCache}
            disabled={clearingCache}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              padding: "2px 6px",
              background: "transparent",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: clearingCache
                ? "var(--text-muted)"
                : "var(--text-secondary)",
              cursor: clearingCache ? "not-allowed" : "pointer",
              fontSize: "0.68rem",
            }}
            title="Flush GeoIP cache from disk and memory to force fresh live lookups"
          >
            <Trash2 size={10} /> {clearingCache ? "CLEARING..." : "FLUSH CACHE"}
          </button>

          <button
            onClick={toggleFullscreen}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              padding: "2px 6px",
              background: "transparent",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: "var(--text-secondary)",
              cursor: "pointer",
              fontSize: "0.68rem",
            }}
            title={
              isFullscreen ? "Exit Fullscreen (ESC)" : "Fullscreen Radar Map"
            }
          >
            {isFullscreen ? <Minimize2 size={11} /> : <Maximize2 size={11} />}
            {isFullscreen ? "EXIT" : "EXPAND"}
          </button>

          <span
            style={{
              color: "var(--success)",
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              fontSize: "0.68rem",
            }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: "var(--success)",
              }}
            />
            {locationClusters.length} SITES &bull; {visibleNodes.length} IPS
            &bull; {visibleEdges.length} FLOWS
          </span>
        </div>
      </div>

      {/* Stage Palette Filter Bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "5px 12px",
          background: isDark ? "rgba(0,0,0,0.28)" : "rgba(0,0,0,0.04)",
          borderBottom: "1px solid var(--border)",
          fontFamily: "var(--font-mono)",
          fontSize: "0.68rem",
          overflowX: "auto",
          userSelect: "none",
        }}
      >
        <span
          style={{
            color: "var(--text-muted)",
            fontWeight: 700,
            marginRight: 2,
            whiteSpace: "nowrap",
          }}
        >
          STAGE PALETTE:
        </span>
        {STAGE_PALETTE.map((stg) => {
          const isSelected =
            stageFilter === stg.id ||
            (stg.id !== "all" && stageFilter === stg.key);
          const count =
            stg.id === "all" ? stageCounts.all : stageCounts[stg.key] || 0;
          return (
            <button
              key={stg.id}
              onClick={() =>
                setStageFilter(isSelected && stg.id !== "all" ? "all" : stg.id)
              }
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "2px 7px",
                borderRadius: "var(--radius-sm, 3px)",
                background: isSelected
                  ? `${stg.color === "var(--text-primary)" ? "var(--bg-raised)" : stg.color}25`
                  : "transparent",
                border: `1px solid ${
                  isSelected
                    ? stg.color === "var(--text-primary)"
                      ? "var(--border-strong)"
                      : stg.color
                    : "transparent"
                }`,
                color: isSelected
                  ? stg.color === "var(--text-primary)"
                    ? "var(--text-primary)"
                    : stg.color
                  : "var(--text-secondary)",
                cursor: "pointer",
                fontWeight: isSelected ? 700 : 500,
                whiteSpace: "nowrap",
                fontSize: "0.66rem",
                transition: "all 0.15s ease",
              }}
            >
              {stg.id !== "all" && (
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: stg.color,
                    boxShadow: isSelected ? `0 0 5px ${stg.color}` : "none",
                  }}
                />
              )}
              {stg.label}
              {count > 0 && (
                <span
                  style={{
                    fontSize: "0.60rem",
                    padding: "1px 4px",
                    borderRadius: 3,
                    background: isSelected
                      ? "rgba(0,0,0,0.3)"
                      : "var(--bg-surface)",
                    opacity: 0.85,
                  }}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Main Map & Graph Canvas Area */}
      <div style={{ flex: 1, position: "relative", minHeight: 0 }}>
        {/* VIEW 1: ESRI WORLD DARK GRAY LEAFLET MAP */}
        <div
          ref={mapContainerRef}
          style={{
            width: "100%",
            height: "100%",
            display: viewMode === "geo" ? "block" : "none",
          }}
        />

        {/* Sleek Floating GLOBAL THREAT RADAR (HUD Overlay) */}
        {viewMode === "geo" && showThreatRadar && (
          <div
            style={{
              position: "absolute",
              top: 14,
              left: 14,
              width: isRadarMinimized ? "auto" : 340,
              background: isDark
                ? "rgba(10, 20, 26, 0.88)"
                : "rgba(255, 255, 255, 0.94)",
              backdropFilter: "blur(16px)",
              WebkitBackdropFilter: "blur(16px)",
              border: `1px solid ${
                isDark ? "rgba(57, 223, 235, 0.35)" : "rgba(0, 0, 0, 0.15)"
              }`,
              borderRadius: "var(--radius-md, 8px)",
              boxShadow: isDark
                ? "0 12px 36px rgba(0, 0, 0, 0.75), 0 0 16px rgba(57, 223, 235, 0.12)"
                : "0 12px 30px rgba(0, 0, 0, 0.15)",
              zIndex: 999,
              fontFamily: "var(--font-mono)",
              fontSize: "0.72rem",
              pointerEvents: "auto",
              transition: "all 0.2s cubic-bezier(0.16, 1, 0.3, 1)",
              overflow: "hidden",
            }}
          >
            {/* Radar Header Bar */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "8px 12px",
                background: isDark
                  ? "rgba(14, 28, 36, 0.95)"
                  : "rgba(240, 244, 248, 0.95)",
                borderBottom: isRadarMinimized
                  ? "none"
                  : `1px solid ${
                      isDark ? "rgba(57, 223, 235, 0.2)" : "var(--border)"
                    }`,
                gap: 10,
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  cursor: "pointer",
                }}
                onClick={() => setIsRadarMinimized((prev) => !prev)}
              >
                <div
                  style={{
                    position: "relative",
                    width: 10,
                    height: 10,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <span
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: peakRisk >= 0.35 ? "#F64541" : "#39DFEB",
                      boxShadow: `0 0 8px ${
                        peakRisk >= 0.35 ? "#F64541" : "#39DFEB"
                      }`,
                    }}
                  />
                  <span
                    style={{
                      position: "absolute",
                      inset: -2,
                      borderRadius: "50%",
                      border: `1px solid ${
                        peakRisk >= 0.35 ? "#F64541" : "#39DFEB"
                      }`,
                      animation:
                        "ping 1.6s cubic-bezier(0, 0, 0.2, 1) infinite",
                      opacity: 0.75,
                    }}
                  />
                </div>
                <div style={{ display: "flex", flexDirection: "column" }}>
                  <span
                    style={{
                      color: "var(--text-primary)",
                      fontWeight: 800,
                      fontSize: "0.74rem",
                      letterSpacing: "0.04em",
                    }}
                  >
                    GLOBAL THREAT RADAR
                  </span>
                  {isRadarMinimized && (
                    <span
                      style={{
                        fontSize: "0.62rem",
                        color: peakRisk >= 0.35 ? "#F64541" : "#34D399",
                      }}
                    >
                      {threatFlows.length} THREATS &bull; PEAK{" "}
                      {(peakRisk * 100).toFixed(0)}%
                    </span>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <button
                  onClick={() => setIsRadarMinimized((prev) => !prev)}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "var(--text-muted)",
                    cursor: "pointer",
                    padding: 2,
                    display: "flex",
                    alignItems: "center",
                  }}
                  title={isRadarMinimized ? "Expand Radar" : "Minimize Radar"}
                >
                  {isRadarMinimized ? (
                    <ChevronDown size={14} />
                  ) : (
                    <Minus size={14} />
                  )}
                </button>
                <button
                  onClick={() => setShowThreatRadar(false)}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "var(--text-muted)",
                    cursor: "pointer",
                    padding: 2,
                    display: "flex",
                    alignItems: "center",
                  }}
                  title="Close Radar"
                >
                  <X size={14} />
                </button>
              </div>
            </div>

            {/* Radar Body Content (Visible when not minimized) */}
            {!isRadarMinimized && (
              <div style={{ padding: "10px 12px" }}>
                {/* 3 Telemetry Metrics Chips */}
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr 1fr",
                    gap: 6,
                    marginBottom: 10,
                  }}
                >
                  <div
                    style={{
                      background: isDark
                        ? "rgba(0,0,0,0.3)"
                        : "rgba(0,0,0,0.04)",
                      padding: "6px 8px",
                      borderRadius: 4,
                      border: "1px solid var(--border)",
                      textAlign: "center",
                    }}
                  >
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.60rem",
                        textTransform: "uppercase",
                      }}
                    >
                      DEFENDED NOC
                    </div>
                    <div
                      style={{
                        color: "#5294E2",
                        fontWeight: 700,
                        fontSize: "0.72rem",
                        marginTop: 2,
                        textTransform: "uppercase",
                      }}
                    >
                      {(deviceLocation.city || "LOCAL HOST").toUpperCase()}{" "}
                      {deviceLocation.flag || "📍"}
                    </div>
                  </div>

                  <div
                    style={{
                      background: isDark
                        ? "rgba(0,0,0,0.3)"
                        : "rgba(0,0,0,0.04)",
                      padding: "6px 8px",
                      borderRadius: 4,
                      border: "1px solid var(--border)",
                      textAlign: "center",
                    }}
                  >
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.60rem",
                        textTransform: "uppercase",
                      }}
                    >
                      THREAT STATUS
                    </div>
                    <div
                      style={{
                        color:
                          peakRisk >= 0.7
                            ? "#F64541"
                            : peakRisk >= 0.35
                              ? "#F6B144"
                              : "#34D399",
                        fontWeight: 700,
                        fontSize: "0.72rem",
                        marginTop: 2,
                      }}
                    >
                      {peakRisk >= 0.7
                        ? "CRITICAL"
                        : peakRisk >= 0.35
                          ? "ELEVATED"
                          : "SECURE"}
                    </div>
                  </div>

                  <div
                    style={{
                      background: isDark
                        ? "rgba(0,0,0,0.3)"
                        : "rgba(0,0,0,0.04)",
                      padding: "6px 8px",
                      borderRadius: 4,
                      border: "1px solid var(--border)",
                      textAlign: "center",
                    }}
                  >
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.60rem",
                        textTransform: "uppercase",
                      }}
                    >
                      PEAK RISK
                    </div>
                    <div
                      style={{
                        color: peakRisk >= 0.35 ? "#F64541" : "#34D399",
                        fontWeight: 800,
                        fontSize: "0.72rem",
                        marginTop: 2,
                      }}
                    >
                      {(peakRisk * 100).toFixed(0)}%
                    </div>
                  </div>
                </div>

                {/* Adversary Intercept Stream */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 6,
                    paddingBottom: 4,
                    borderBottom: "1px solid var(--border)",
                  }}
                >
                  <span
                    style={{
                      color: "var(--text-secondary)",
                      fontSize: "0.64rem",
                      fontWeight: 700,
                      letterSpacing: "0.03em",
                    }}
                  >
                    LIVE INTERCEPT STREAM
                  </span>
                  <span
                    style={{ color: "var(--text-muted)", fontSize: "0.62rem" }}
                  >
                    {threatFlows.length} Active Vectors
                  </span>
                </div>

                <div
                  className="garud-hud-scroll"
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 6,
                    maxHeight: 160,
                    overflowY: "auto",
                    paddingRight: 2,
                  }}
                >
                  {threatFlows.length === 0 ? (
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.68rem",
                        padding: "12px 6px",
                        textAlign: "center",
                      }}
                    >
                      No active adversary flows detected. Network posture clean.
                    </div>
                  ) : (
                    threatFlows.slice(0, 6).map((e, i) => {
                      const stageTheme = getStageTheme(e.stage, e.probability);
                      const isHovered =
                        focusedFlow &&
                        focusedFlow.session_key === e.session_key;
                      return (
                        <div
                          key={`radar-flow-${i}`}
                          onClick={() => {
                            setSelectedEntity({ type: "flow", data: e });
                            setFocusedFlow(e);
                          }}
                          onMouseEnter={() => setFocusedFlow(e)}
                          onMouseLeave={() => setFocusedFlow(null)}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            padding: "6px 8px",
                            background: isHovered
                              ? "var(--bg-hover)"
                              : isDark
                                ? "rgba(14, 25, 33, 0.75)"
                                : "rgba(0, 0, 0, 0.03)",
                            borderRadius: 4,
                            borderLeft: `3px solid ${stageTheme.color}`,
                            border: `1px solid ${
                              isHovered ? stageTheme.color : "transparent"
                            }`,
                            borderLeftWidth: 3,
                            cursor: "pointer",
                            transition: "all 0.15s ease",
                          }}
                        >
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <div
                              style={{
                                color: "var(--text-primary)",
                                fontWeight: 700,
                                fontSize: "0.68rem",
                                whiteSpace: "nowrap",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                              }}
                            >
                              {e.src_flag || "🌐"} {e.src_city || "Adversary"}{" "}
                              &rarr; {e.dst_flag || "🌐"}{" "}
                              {e.dst_city ||
                                deviceLocation.city ||
                                "Local Host"}
                            </div>
                            <div
                              style={{
                                color: "var(--text-muted)",
                                fontSize: "0.62rem",
                                marginTop: 1,
                              }}
                            >
                              <span
                                style={{
                                  color: stageTheme.color,
                                  fontWeight: 600,
                                }}
                              >
                                {stageTheme.name}
                              </span>{" "}
                              &bull; {e.app_name || "Flow"}
                            </div>
                          </div>
                          <div style={{ textAlign: "right", marginLeft: 8 }}>
                            <span
                              style={{
                                color: stageTheme.color,
                                fontWeight: 800,
                                fontSize: "0.72rem",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {(e.probability * 100).toFixed(0)}%
                            </span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Footer Status */}
                <div
                  style={{
                    marginTop: 8,
                    paddingTop: 6,
                    borderTop: "1px solid var(--border)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    fontSize: "0.60rem",
                    color: "var(--text-muted)",
                  }}
                >
                  <span
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 4,
                    }}
                  >
                    <span
                      style={{
                        width: 5,
                        height: 5,
                        borderRadius: "50%",
                        background: "var(--success)",
                      }}
                    />
                    TELEMETRY: SYNCHRONIZED
                  </span>
                  <span>CLICK FLOW TO INSPECT</span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* VIEW 2: LOGICAL TOPOLOGY GRAPH (Interactive Smooth Zoom & Pan, Fit-All) */}
        {viewMode === "logical" && (
          <div
            ref={topoContainerRef}
            onWheel={handleTopoWheel}
            onMouseDown={handleTopoMouseDown}
            onMouseMove={handleTopoMouseMove}
            onMouseUp={handleTopoMouseUp}
            onMouseLeave={handleTopoMouseUp}
            style={{
              width: "100%",
              height: "100%",
              overflow: "hidden",
              position: "relative",
              cursor: isPanningTopo ? "grabbing" : "grab",
              userSelect: "none",
              background: isDark ? "#0C141D" : "#F6F4EB",
            }}
          >
            {/* Floating Zoom & Fit Controls */}
            <div
              style={{
                position: "absolute",
                bottom: 14,
                left: 14,
                display: "flex",
                alignItems: "center",
                gap: 4,
                background: isDark
                  ? "rgba(10, 22, 28, 0.88)"
                  : "rgba(255, 255, 255, 0.92)",
                backdropFilter: "blur(12px)",
                border: "1px solid var(--border-strong)",
                borderRadius: "var(--radius-sm)",
                padding: "3px 6px",
                zIndex: 20,
                fontFamily: "var(--font-mono)",
                fontSize: "0.68rem",
                boxShadow: "0 4px 14px rgba(0,0,0,0.35)",
                userSelect: "none",
              }}
            >
              <button
                onClick={handleTopoZoomIn}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 22,
                  height: 22,
                  background: "transparent",
                  border: "1px solid var(--border)",
                  borderRadius: 3,
                  color: "var(--text-primary)",
                  cursor: "pointer",
                }}
                title="Zoom In (+)"
              >
                <Plus size={12} />
              </button>
              <button
                onClick={handleTopoZoomOut}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 22,
                  height: 22,
                  background: "transparent",
                  border: "1px solid var(--border)",
                  borderRadius: 3,
                  color: "var(--text-primary)",
                  cursor: "pointer",
                }}
                title="Zoom Out (-)"
              >
                <Minus size={12} />
              </button>
              <span
                style={{
                  color: "var(--text-muted)",
                  padding: "0 6px",
                  fontSize: "0.65rem",
                  fontWeight: 700,
                  minWidth: 44,
                  textAlign: "center",
                }}
              >
                {Math.round(topoZoom * 100)}%
              </span>
              <button
                onClick={fitAllTopology}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                  padding: "2px 7px",
                  background: "var(--bg-raised)",
                  border: "1px solid var(--border)",
                  borderRadius: 3,
                  color: "var(--text-primary)",
                  cursor: "pointer",
                  fontWeight: 600,
                  fontSize: "0.65rem",
                }}
                title="Fit Entire Topology to Screen"
              >
                <RotateCcw size={10} /> FIT ALL
              </button>
            </div>

            {/* Navigation Hint Pill */}
            <div
              style={{
                position: "absolute",
                bottom: 14,
                right: 14,
                fontSize: "0.62rem",
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
                background: isDark
                  ? "rgba(10, 20, 26, 0.75)"
                  : "rgba(255, 255, 255, 0.8)",
                padding: "3px 8px",
                borderRadius: 3,
                border: "1px solid var(--border)",
                pointerEvents: "none",
                zIndex: 20,
              }}
            >
              SCROLL TO ZOOM &bull; DRAG TO PAN
            </div>

            {/* Hardware-accelerated Transformation Wrapper */}
            <div
              style={{
                width: `${logicalLayout.width}px`,
                height: `${logicalLayout.canvasHeight}px`,
                transform: `translate(${topoPan.x}px, ${topoPan.y}px) scale(${topoZoom})`,
                transformOrigin: "0 0",
                transition: isPanningTopo ? "none" : "transform 0.08s ease-out",
                willChange: "transform",
                pointerEvents: "auto",
              }}
            >
              <svg
                viewBox={`0 0 ${logicalLayout.width} ${logicalLayout.canvasHeight}`}
                style={{
                  width: `${logicalLayout.width}px`,
                  height: `${logicalLayout.canvasHeight}px`,
                  display: "block",
                }}
              >
                {/* SVG Definitions: Dotted Grid Pattern and Directed Arrow Markers */}
                <defs>
                  <pattern
                    id="topo-dot-grid"
                    width="24"
                    height="24"
                    patternUnits="userSpaceOnUse"
                  >
                    <circle
                      cx="12"
                      cy="12"
                      r="1.15"
                      fill={
                        isDark
                          ? "rgba(255, 255, 255, 0.13)"
                          : "rgba(0, 0, 0, 0.16)"
                      }
                    />
                  </pattern>

                  {/* Normal Benign Arrowhead */}
                  <marker
                    id="arrow-benign"
                    markerWidth="8"
                    markerHeight="8"
                    refX="7"
                    refY="4"
                    orient="auto"
                  >
                    <polygon
                      points="0 1, 8 4, 0 7"
                      fill={isDark ? "#6B7280" : "#9CA3AF"}
                    />
                  </marker>

                  {/* Threat / Adversary Arrowhead */}
                  <marker
                    id="arrow-threat"
                    markerWidth="9"
                    markerHeight="9"
                    refX="8"
                    refY="4.5"
                    orient="auto"
                  >
                    <polygon points="0 1.5, 9 4.5, 0 7.5" fill="#EF4444" />
                  </marker>
                </defs>

                {/* 1. Blueprint Dotted Grid Background */}
                <rect
                  width={logicalLayout.width}
                  height={logicalLayout.canvasHeight}
                  fill="url(#topo-dot-grid)"
                />

                {/* 2. Soft Organic Zone Hull Blobs matching screenshot */}
                {/* Left Zone Blob (LAN & Gateway) */}
                <path
                  d="M 80 180 Q 200 130 360 180 Q 400 240 340 280 Q 200 290 90 260 Z"
                  fill={
                    isDark
                      ? "rgba(255, 255, 255, 0.025)"
                      : "rgba(180, 170, 150, 0.16)"
                  }
                />
                {/* Middle Zone Blob (ISP, Google, Azure) */}
                <path
                  d="M 430 70 Q 560 50 740 120 Q 770 240 680 370 Q 460 380 430 250 Z"
                  fill={
                    isDark
                      ? "rgba(255, 255, 255, 0.02)"
                      : "rgba(180, 170, 150, 0.12)"
                  }
                />
                {/* Right Zone Blob (Edge Services & Threat) */}
                <path
                  d="M 720 150 Q 860 110 970 140 Q 990 260 910 380 Q 740 370 720 250 Z"
                  fill={
                    isDark
                      ? "rgba(255, 255, 255, 0.025)"
                      : "rgba(180, 170, 150, 0.14)"
                  }
                />

                {/* 3. Subtle Zone Column Headers at Top */}
                <text
                  x="140"
                  y="34"
                  fill={isDark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.28)"}
                  fontSize="11"
                  fontFamily="var(--font-mono, monospace)"
                  letterSpacing="0.08em"
                  fontWeight="700"
                >
                  INTERNAL / LAN
                </text>
                <text
                  x="470"
                  y="34"
                  fill={isDark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.28)"}
                  fontSize="11"
                  fontFamily="var(--font-mono, monospace)"
                  letterSpacing="0.08em"
                  fontWeight="700"
                >
                  DMZ / PUBLIC SERVICES
                </text>
                <text
                  x="780"
                  y="34"
                  fill={isDark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.28)"}
                  fontSize="11"
                  fontFamily="var(--font-mono, monospace)"
                  letterSpacing="0.08em"
                  fontWeight="700"
                >
                  EXTERNAL / INTERNET
                </text>

                {/* 4. Directed Flow Arrows with Circle Intersections */}
                {logicalLayout.topoEdges.map((edge, idx) => {
                  const src = logicalLayout.nodeCoords.get(edge.source);
                  const dst = logicalLayout.nodeCoords.get(edge.target);
                  if (!src || !dst) return null;

                  const isThreat = edge.isThreat;
                  const pts = getCircleLinePoints(
                    src.x,
                    src.y,
                    dst.x,
                    dst.y,
                    16,
                    16,
                    isThreat ? 5 : 4,
                  );

                  const isEdgeActive =
                    !activeConnectionSet ||
                    activeConnectionSet.edgeIndices.has(idx);

                  return (
                    <g
                      key={`topo-edge-${idx}`}
                      onClick={() => {
                        if (!panStartRef.current.hasMoved && edge.raw) {
                          setSelectedEntity({ type: "flow", data: edge.raw });
                        }
                      }}
                      style={{ cursor: "pointer" }}
                    >
                      <line
                        x1={pts.sx}
                        y1={pts.sy}
                        x2={pts.ex}
                        y2={pts.ey}
                        stroke={
                          isThreat
                            ? "#EF4444"
                            : isEdgeActive && activeConnectionSet
                              ? "var(--accent)"
                              : isDark
                                ? "#4B5563"
                                : "#9CA3AF"
                        }
                        strokeWidth={
                          isThreat
                            ? 2.8
                            : isEdgeActive && activeConnectionSet
                              ? 2.4
                              : 1.8
                        }
                        opacity={
                          isThreat
                            ? 0.95
                            : isEdgeActive
                              ? activeConnectionSet
                                ? 1.0
                                : 0.65
                              : 0.18
                        }
                        markerEnd={
                          isThreat ? "url(#arrow-threat)" : "url(#arrow-benign)"
                        }
                        style={{
                          filter: isThreat
                            ? "drop-shadow(0 0 4px rgba(239, 68, 68, 0.6))"
                            : isEdgeActive && activeConnectionSet
                              ? "drop-shadow(0 0 4px var(--accent))"
                              : "none",
                          transition: "all 0.15s ease",
                        }}
                      />
                    </g>
                  );
                })}

                {/* 5. Concentric Circular Radar Nodes matching Reference Screenshot */}
                {logicalLayout.topoNodes.map((node) => {
                  const isThreat = node.isThreat;
                  const isGateway = node.isGateway;
                  const isHovered = hoveredNodeId === node.id;
                  const isNodeActive =
                    !activeConnectionSet ||
                    activeConnectionSet.nodeIds.has(node.id);

                  return (
                    <g
                      key={`topo-node-${node.id}`}
                      transform={`translate(${node.x}, ${node.y})`}
                      opacity={isNodeActive ? 1.0 : 0.3}
                      onClick={() => {
                        if (!panStartRef.current.hasMoved) {
                          setSelectedEntity({ type: "node", data: node.raw });
                        }
                      }}
                      onMouseEnter={() => setHoveredNodeId(node.id)}
                      onMouseLeave={() => setHoveredNodeId(null)}
                      style={{
                        cursor: "pointer",
                        transition: "opacity 0.15s ease",
                      }}
                    >
                      {/* Concentric Sonar Pulse Rings */}
                      {isThreat ? (
                        <>
                          <circle
                            r="30"
                            fill="none"
                            stroke="#EF4444"
                            strokeWidth="1"
                            opacity="0.28"
                            className="pulse-fast"
                          />
                          <circle
                            r="23"
                            fill="none"
                            stroke="#EF4444"
                            strokeWidth="1.2"
                            opacity="0.45"
                          />
                          <circle
                            r="18"
                            fill="none"
                            stroke="#EF4444"
                            strokeWidth="1.5"
                            opacity="0.65"
                          />
                        </>
                      ) : isGateway ? (
                        <>
                          <circle
                            r="28"
                            fill="none"
                            stroke="#10B981"
                            strokeWidth="1"
                            opacity="0.28"
                          />
                          <circle
                            r="22"
                            fill="none"
                            stroke="#10B981"
                            strokeWidth="1.2"
                            opacity="0.45"
                          />
                        </>
                      ) : (
                        <circle
                          r="23"
                          fill="none"
                          stroke={node.color}
                          strokeWidth="1"
                          opacity={isHovered ? "0.6" : "0.32"}
                        />
                      )}

                      {/* Central Badge Circle */}
                      <circle
                        r="15"
                        fill={isDark ? "#0E1822" : "#FFFFFF"}
                        stroke={node.color}
                        strokeWidth="2.4"
                        style={{
                          filter: isThreat
                            ? "drop-shadow(0 0 6px rgba(239, 68, 68, 0.55))"
                            : isHovered
                              ? `drop-shadow(0 0 6px ${node.color})`
                              : "none",
                          transition: "filter 0.15s ease",
                        }}
                      />

                      {/* Icon inside Circle */}
                      <g transform="translate(-7.5, -7.5)">
                        {node.iconType === "gateway" && (
                          <RouterSwitchIcon size={15} color={node.color} />
                        )}
                        {node.iconType === "threat" && (
                          <ThreatServerIcon size={15} color={node.color} />
                        )}
                        {node.iconType === "lan" && (
                          <MonitorLanIcon size={15} color={node.color} />
                        )}
                        {node.iconType === "database" && (
                          <DatabaseStorageIcon size={15} color={node.color} />
                        )}
                        {node.iconType === "globe" && (
                          <GlobeWebIcon size={15} color={node.color} />
                        )}
                      </g>

                      {/* Label Text Centered Directly Underneath */}
                      <text
                        y="28"
                        textAnchor="middle"
                        fill={isDark ? "var(--text-primary)" : "#1F2937"}
                        fontSize="10.5"
                        fontFamily="var(--font-mono, monospace)"
                        fontWeight="600"
                        letterSpacing="-0.01em"
                      >
                        {node.label}
                      </text>
                      {node.subtext && (
                        <text
                          y="40"
                          textAnchor="middle"
                          fill={
                            node.isThreat
                              ? "#EF4444"
                              : isDark
                                ? "rgba(255,255,255,0.45)"
                                : "rgba(0,0,0,0.5)"
                          }
                          fontSize="9"
                          fontFamily="var(--font-mono, monospace)"
                          fontWeight={node.isThreat ? "700" : "500"}
                          letterSpacing="0.02em"
                        >
                          {node.subtext}
                        </text>
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>
          </div>
        )}

        {/* Selected Entity Forensics Drawer (Handles Datacenter Clusters, Multi-IP and App lists) */}
        {selectedEntity && (
          <div
            style={{
              position: "absolute",
              right: 14,
              top: 14,
              width: 320,
              maxHeight: "calc(100% - 28px)",
              overflowY: "auto",
              background: "var(--bg-raised)",
              border: "1px solid var(--border-strong)",
              borderRadius: "var(--radius-md)",
              padding: 14,
              boxShadow: "0 10px 30px rgba(0, 0, 0, 0.6)",
              zIndex: 1000,
              fontFamily: "var(--font-mono)",
              fontSize: "0.72rem",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                borderBottom: "1px solid var(--border)",
                paddingBottom: 6,
                marginBottom: 10,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                {selectedEntity.type === "cluster" ? (
                  selectedEntity.data.is_internal ? (
                    <Shield size={15} color="#5294E2" />
                  ) : (
                    <Globe size={15} color="var(--accent)" />
                  )
                ) : selectedEntity.type === "node" ? (
                  <Laptop size={15} color="var(--accent)" />
                ) : (
                  <Radio size={15} color="var(--danger)" />
                )}
                <strong
                  style={{ color: "var(--text-primary)", fontSize: "0.76rem" }}
                >
                  {selectedEntity.type === "cluster"
                    ? "DATACENTER FORENSICS"
                    : selectedEntity.type === "node"
                      ? "HOST TELEMETRY"
                      : "CONNECTION TELEMETRY"}
                </strong>
              </div>
              <button
                onClick={() => setSelectedEntity(null)}
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--text-muted)",
                  cursor: "pointer",
                }}
              >
                <X size={15} />
              </button>
            </div>

            {/* CASE 1: DATACENTER CLUSTER (Handles 10 IPs with 1 attack edgecase) */}
            {selectedEntity.type === "cluster" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    LOCATION & SITE
                  </div>
                  <div
                    style={{
                      color: "var(--text-primary)",
                      fontWeight: 700,
                      fontSize: "0.80rem",
                    }}
                  >
                    {selectedEntity.data.flag} {selectedEntity.data.city},{" "}
                    {selectedEntity.data.country}
                  </div>
                  <div
                    style={{
                      color: "var(--text-secondary)",
                      fontSize: "0.66rem",
                    }}
                  >
                    {selectedEntity.data.org}
                  </div>
                </div>

                <div
                  style={{
                    display: "flex",
                    gap: 8,
                    background: "var(--bg-inset)",
                    padding: "6px 8px",
                    borderRadius: 4,
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.62rem",
                      }}
                    >
                      TOTAL MONITORED IPS
                    </div>
                    <div
                      style={{ color: "var(--text-primary)", fontWeight: 700 }}
                    >
                      {selectedEntity.data.total_ips} Active Host
                      {selectedEntity.data.total_ips > 1 ? "s" : ""}
                    </div>
                  </div>
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.62rem",
                      }}
                    >
                      HIGHEST THREAT
                    </div>
                    <div
                      style={{
                        color: getStageTheme(
                          selectedEntity.data.max_stage,
                          selectedEntity.data.max_risk,
                        ).color,
                        fontWeight: 700,
                      }}
                    >
                      {selectedEntity.data.max_stage} (
                      {(selectedEntity.data.max_risk * 100).toFixed(0)}%)
                    </div>
                  </div>
                </div>

                {/* Individual IP list at this datacenter showing exact process/app names */}
                <div style={{ marginTop: 4 }}>
                  <div
                    style={{
                      color: "var(--text-muted)",
                      fontSize: "0.64rem",
                      marginBottom: 4,
                      fontWeight: 700,
                    }}
                  >
                    ACTIVE HOSTS & APPLICATIONS (
                    {selectedEntity.data.nodes.length})
                  </div>
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 6,
                      maxHeight: 220,
                      overflowY: "auto",
                    }}
                  >
                    {selectedEntity.data.nodes.map((node, nIdx) => {
                      const nTheme = getStageTheme(
                        node.max_stage,
                        node.max_risk,
                      );
                      const isThreat =
                        (node.max_risk || 0) >= 0.35 ||
                        (node.max_stage && node.max_stage !== "Benign");
                      const apps =
                        Array.isArray(node.apps) && node.apps.length > 0
                          ? node.apps.join(", ")
                          : "System Process";

                      return (
                        <div
                          key={`cluster-node-${nIdx}`}
                          style={{
                            background: "var(--bg-inset)",
                            borderLeft: `3px solid ${nTheme.color}`,
                            padding: "6px 8px",
                            borderRadius: 3,
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                            }}
                          >
                            <strong
                              style={{
                                color: isThreat
                                  ? nTheme.color
                                  : "var(--text-primary)",
                                fontSize: "0.72rem",
                              }}
                            >
                              {node.id}
                            </strong>
                            <span
                              style={{
                                color: nTheme.color,
                                fontWeight: 700,
                                fontSize: "0.66rem",
                              }}
                            >
                              {nTheme.phase !== "00"
                                ? `PHASE ${nTheme.phase}`
                                : "NOMINAL"}{" "}
                              ({(node.max_risk * 100).toFixed(0)}%)
                            </span>
                          </div>
                          <div
                            style={{
                              color: "var(--text-secondary)",
                              fontSize: "0.64rem",
                              marginTop: 2,
                            }}
                          >
                            App:{" "}
                            <span
                              style={{
                                color: "var(--text-primary)",
                                fontWeight: 600,
                              }}
                            >
                              {apps}
                            </span>
                          </div>
                          {isThreat && (
                            <div
                              style={{
                                color: "var(--danger)",
                                fontSize: "0.62rem",
                                marginTop: 2,
                                fontWeight: 700,
                              }}
                            >
                              ⚠️ ACTIVE ATTACK PROGRESSION DETECTED
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* CASE 2: SINGLE NODE TELEMETRY */}
            {selectedEntity.type === "node" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    {selectedEntity.data.hostname
                      ? "HOST IDENTITY"
                      : "IP ADDRESS"}
                  </div>
                  <div
                    style={{ color: "var(--text-primary)", fontWeight: 700 }}
                  >
                    {selectedEntity.data.hostname
                      ? `${selectedEntity.data.hostname} (${selectedEntity.data.id})`
                      : selectedEntity.data.id}
                  </div>
                </div>

                {Array.isArray(selectedEntity.data.interfaces) &&
                  selectedEntity.data.interfaces.length > 0 && (
                    <div style={{ marginTop: 2 }}>
                      <div
                        style={{
                          color: "var(--text-muted)",
                          fontSize: "0.62rem",
                          marginBottom: 3,
                          fontWeight: 700,
                        }}
                      >
                        ACTIVE ADAPTERS & INTERFACES
                      </div>
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 3,
                          maxHeight: 90,
                          overflowY: "auto",
                        }}
                      >
                        {selectedEntity.data.interfaces
                          .filter(
                            (i) =>
                              i.is_up &&
                              i.ip &&
                              !i.ip.startsWith("fe80:") &&
                              !i.ip.startsWith("169.254."),
                          )
                          .slice(0, 5)
                          .map((iface, iIdx) => (
                            <div
                              key={iIdx}
                              style={{
                                background: "var(--bg-inset)",
                                padding: "2px 6px",
                                borderRadius: 3,
                                fontSize: "0.62rem",
                                display: "flex",
                                justifyContent: "space-between",
                              }}
                            >
                              <span
                                style={{
                                  fontWeight: 600,
                                  color: "var(--accent)",
                                }}
                              >
                                {iface.name}:
                              </span>
                              <span style={{ color: "var(--text-primary)" }}>
                                {iface.ip} {iface.is_primary ? "★" : ""}
                              </span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    LOCATION & COUNTRY
                  </div>
                  <div style={{ color: "var(--text-primary)" }}>
                    {selectedEntity.data.flag ||
                      (selectedEntity.data.is_internal
                        ? deviceLocation.flag
                        : "🌐")}{" "}
                    {selectedEntity.data.city ||
                      (selectedEntity.data.is_internal
                        ? deviceLocation.city
                        : "Local Host")}
                    ,{" "}
                    {selectedEntity.data.country ||
                      (selectedEntity.data.is_internal
                        ? deviceLocation.country
                        : "Local Network")}
                  </div>
                </div>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    ORGANIZATION / ASN
                  </div>
                  <div style={{ color: "var(--text-secondary)" }}>
                    {selectedEntity.data.org || "Defender Infrastructure"}
                  </div>
                </div>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    ASSOCIATED PROCESS / APP
                  </div>
                  <div
                    style={{ color: "var(--text-primary)", fontWeight: 600 }}
                  >
                    {Array.isArray(selectedEntity.data.apps) &&
                    selectedEntity.data.apps.length > 0
                      ? selectedEntity.data.apps.join(", ")
                      : "System / Network"}
                  </div>
                </div>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    MAX KILL-CHAIN PHASE
                  </div>
                  <div
                    style={{
                      color: getStageTheme(
                        selectedEntity.data.max_stage,
                        selectedEntity.data.max_risk,
                      ).color,
                      fontWeight: 700,
                    }}
                  >
                    {selectedEntity.data.max_stage || "Benign"} (
                    {(selectedEntity.data.max_risk * 100 || 0).toFixed(1)}%
                    Infiltration Risk)
                  </div>
                </div>

                {selectedEntity.data.total_ips > 1 &&
                  Array.isArray(selectedEntity.data.ips) && (
                    <div
                      style={{
                        marginTop: 6,
                        paddingTop: 6,
                        borderTop: "1px solid var(--border)",
                      }}
                    >
                      <div
                        style={{
                          color: "var(--text-muted)",
                          fontSize: "0.62rem",
                          marginBottom: 4,
                          fontWeight: 700,
                        }}
                      >
                        MEMBER HOST IPS ({selectedEntity.data.total_ips})
                      </div>
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: 4,
                          maxHeight: 90,
                          overflowY: "auto",
                        }}
                      >
                        {selectedEntity.data.ips.map((ip, idx) => (
                          <span
                            key={idx}
                            style={{
                              background: "var(--bg-inset)",
                              border: "1px solid var(--border)",
                              padding: "2px 5px",
                              borderRadius: 3,
                              fontSize: "0.62rem",
                              color: "var(--text-primary)",
                            }}
                          >
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
              </div>
            )}

            {/* CASE 3: CONNECTION FLOW TELEMETRY */}
            {selectedEntity.type === "flow" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    TRAFFIC TRAJECTORY
                  </div>
                  <div
                    style={{
                      color: "var(--text-primary)",
                      fontWeight: 700,
                      fontSize: "0.68rem",
                    }}
                  >
                    {selectedEntity.data.source} &rarr;{" "}
                    {selectedEntity.data.target}
                  </div>
                  <div
                    style={{
                      color: "var(--text-secondary)",
                      fontSize: "0.64rem",
                    }}
                  >
                    {selectedEntity.data.src_city ||
                      (isLocalHostOrLAN(selectedEntity.data.source)
                        ? deviceLocation.city
                        : "Local Host")}{" "}
                    &rarr; {selectedEntity.data.dst_city || "Remote"}
                  </div>
                </div>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    PROCESS / PROTOCOL
                  </div>
                  <div
                    style={{ color: "var(--text-primary)", fontWeight: 600 }}
                  >
                    {selectedEntity.data.app_name || "Flow"} (
                    {selectedEntity.data.protocol || "TCP"}
                    {selectedEntity.data.dst_port
                      ? `:${selectedEntity.data.dst_port}`
                      : ""}
                    )
                  </div>
                </div>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    MITRE ATT&CK STAGE
                  </div>
                  <div
                    style={{
                      color: getStageTheme(
                        selectedEntity.data.stage,
                        selectedEntity.data.probability,
                      ).color,
                      fontWeight: 700,
                    }}
                  >
                    {selectedEntity.data.stage || "Benign"}
                  </div>
                </div>
                <div>
                  <div
                    style={{ color: "var(--text-muted)", fontSize: "0.64rem" }}
                  >
                    INFILTRATION PROBABILITY
                  </div>
                  <div
                    style={{
                      color:
                        (selectedEntity.data.probability || 0) >= 0.35
                          ? "var(--danger)"
                          : "var(--success)",
                      fontWeight: 700,
                    }}
                  >
                    {((selectedEntity.data.probability || 0) * 100).toFixed(1)}%
                  </div>
                </div>
                {onSelectSession && selectedEntity.data.session_key && (
                  <button
                    onClick={() =>
                      onSelectSession(selectedEntity.data.session_key)
                    }
                    style={{
                      marginTop: 8,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: 4,
                      padding: "5px 10px",
                      background: "var(--accent)",
                      border: "none",
                      borderRadius: "var(--radius-sm)",
                      color: "#FFFFFF",
                      cursor: "pointer",
                      fontWeight: 700,
                      fontSize: "0.68rem",
                    }}
                  >
                    INSPECT FORECAST & EXPLAIN <ExternalLink size={11} />
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
