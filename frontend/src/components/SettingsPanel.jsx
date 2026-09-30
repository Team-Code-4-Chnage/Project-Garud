import { useState, useEffect, useRef } from "react";
import {
  Wifi,
  FlaskConical,
  Play,
  Square,
  Trash2,
  Cpu,
  CheckCircle2,
  Layers,
  Terminal,
  Sliders,
  RefreshCw,
  Palette,
  Shield,
  Info,
  Sun,
  Moon,
} from "lucide-react";
import { apiFetch, apiPost } from "../api";
import { formatFeatureName } from "../utils";
import { useTheme } from "../theme";

const SCENARIOS = [
  {
    id: "full_kill_chain",
    name: "Full MITRE Kill-Chain",
    badge: "RECOMMENDED",
    badgeColor: "var(--c-gold)",
    desc: "Sequential 5-stage attack progressing from Benign → Recon → Initial Access → Lateral Movement → C2 → Exfiltration.",
    target: "End-to-End Prediction Verification",
  },
  {
    id: "recon_sweep",
    name: "Stealth Reconnaissance Sweep",
    badge: "RECON",
    badgeColor: "#5294E2",
    desc: "High SYN flag ratio, low packet length, fast port sweeps across multiple target hosts and ports.",
    target: "Port Scanner & Sweep Detection",
  },
  {
    id: "brute_force",
    name: "Perimeter Brute Force & Exploit",
    badge: "INITIAL ACCESS",
    badgeColor: "#D6B36A",
    desc: "Intense authentication bursts, repeated connection resets (RST flags), and payload probe attempts.",
    target: "Initial Exploitation & Ingress Alarm",
  },
  {
    id: "lateral_spread",
    name: "Internal Lateral Movement",
    badge: "LATERAL MOVE",
    badgeColor: "#DE934B",
    desc: "Internal subnet traversal between peer LAN IP addresses mimicking SMB, RPC, and RDP pivoting.",
    target: "Internal Network Spread & Pivot",
  },
  {
    id: "exfiltration",
    name: "C2 Command & Data Exfiltration",
    badge: "EXFILTRATION",
    badgeColor: "#C94A45",
    desc: "Large backward byte transfers, elevated PSH flag flushes, and periodic beaconing to external drop servers.",
    target: "Data Staging & High-Volume Egress",
  },
  {
    id: "benign_baseline",
    name: "Nominal Business Baseline",
    badge: "BENIGN",
    badgeColor: "#58A668",
    desc: "Peaceful normal enterprise traffic flows (HTTPS, DNS queries, NTP time sync, internal API polling).",
    target: "False Positive Validation & Baseline",
  },
];

const FEATURE_DEFINITIONS = [
  {
    key: "flow_duration",
    unit: "microseconds",
    desc: "Total duration of the bidirectional network flow session.",
  },
  {
    key: "tot_fwd_pkts",
    unit: "packets",
    desc: "Total number of packets transmitted in forward (client → server) direction.",
  },
  {
    key: "tot_bwd_pkts",
    unit: "packets",
    desc: "Total number of packets transmitted in backward (server → client) direction.",
  },
  {
    key: "fwd_pkt_len_mean",
    unit: "bytes",
    desc: "Mean byte length of packets transmitted in the forward direction.",
  },
  {
    key: "bwd_pkt_len_mean",
    unit: "bytes",
    desc: "Mean byte length of packets transmitted in the backward direction.",
  },
  {
    key: "flow_bytes_s",
    unit: "bytes/s",
    desc: "Rate of data transfer across the flow session.",
  },
  {
    key: "flow_pkts_s",
    unit: "pkts/s",
    desc: "Packet transmission rate across the bidirectional flow.",
  },
  {
    key: "flow_iat_mean",
    unit: "microseconds",
    desc: "Mean inter-arrival time between consecutive packets in the flow.",
  },
  {
    key: "flow_iat_std",
    unit: "microseconds",
    desc: "Standard deviation of packet inter-arrival times (traffic jitter).",
  },
  {
    key: "fwd_iat_mean",
    unit: "microseconds",
    desc: "Mean inter-arrival time between forward packets.",
  },
  {
    key: "bwd_iat_mean",
    unit: "microseconds",
    desc: "Mean inter-arrival time between backward packets.",
  },
  {
    key: "syn_flag_cnt",
    unit: "count",
    desc: "Packets with SYN flag set (connection establishment / port scans).",
  },
  {
    key: "ack_flag_cnt",
    unit: "count",
    desc: "Packets with ACK flag set (established data stream acknowledgment).",
  },
  {
    key: "fin_flag_cnt",
    unit: "count",
    desc: "Packets with FIN flag set (orderly socket connection termination).",
  },
  {
    key: "rst_flag_cnt",
    unit: "count",
    desc: "Packets with RST flag set (abrupt connection teardown or scan rejection).",
  },
  {
    key: "psh_flag_cnt",
    unit: "count",
    desc: "Packets with PSH flag set (immediate application buffer flush).",
  },
  {
    key: "urg_flag_cnt",
    unit: "count",
    desc: "Packets with URG flag set (urgent out-of-band data pointer).",
  },
  {
    key: "down_up_ratio",
    unit: "ratio",
    desc: "Ratio of download packets to upload packets across the flow.",
  },
  {
    key: "pkt_size_avg",
    unit: "bytes",
    desc: "Average packet byte size across the entire bidirectional flow.",
  },
  {
    key: "ttl_variance",
    unit: "variance",
    desc: "Variance in IP Time-To-Live (indicates routing anomalies or evasion).",
  },
  {
    key: "tcp_win_size",
    unit: "bytes",
    desc: "Initial TCP receive window size advertised during handshake.",
  },
  {
    key: "retransmit_cnt",
    unit: "count",
    desc: "Retransmitted packet count caused by packet drops or resets.",
  },
];

export default function SettingsPanel({
  health,
  systemMode,
  onToggleMode,
  simulatorRunning,
  onStartSimulator,
  onStopSimulator,
  onPurgeSimulated,
  captureRunning,
  onStartLiveCapture,
  onStopLiveCapture,
}) {
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState("appearance");
  const [density, setDensity] = useState(() => {
    try {
      return localStorage.getItem("garud-density") || "comfortable";
    } catch {
      return "comfortable";
    }
  });
  const [reducedMotion, setReducedMotion] = useState(() => {
    try {
      return localStorage.getItem("garud-motion") === "true";
    } catch {
      return false;
    }
  });
  const [riskThreshold, setRiskThreshold] = useState(0.40);

  const handleDensityChange = (d) => {
    setDensity(d);
    try {
      localStorage.setItem("garud-density", d);
      document.documentElement.setAttribute("data-density", d);
    } catch {}
  };

  const handleMotionChange = (m) => {
    setReducedMotion(m);
    try {
      localStorage.setItem("garud-motion", String(m));
      document.documentElement.setAttribute("data-motion", m ? "reduced" : "normal");
    } catch {}
  };

  const [scenario, setScenario] = useState("full_kill_chain");
  const [speed, setSpeed] = useState(1.0);
  const [sessions, setSessions] = useState(4);
  const [simulatorLogs, setSimulatorLogs] = useState("");
  const [isRunning, setIsRunning] = useState(simulatorRunning);
  const [isStarting, setIsStarting] = useState(false);
  const [stats, setStats] = useState(null);
  const logContainerRef = useRef(null);

  // Live packet capture states
  const [isCaptureRunning, setIsCaptureRunning] = useState(captureRunning);
  const [isCaptureStarting, setIsCaptureStarting] = useState(false);
  const [captureStatus, setCaptureStatus] = useState(null);

  // Poll simulator status & live logs
  useEffect(() => {
    let mounted = true;
    const fetchStatus = async () => {
      try {
        const res = await apiFetch("/system/simulator/status");
        if (!mounted) return;
        setIsRunning(Boolean(res.running));
        if (res.logs) {
          setSimulatorLogs(res.logs);
        }
      } catch {}
    };

    fetchStatus();
    const iv = setInterval(fetchStatus, isRunning ? 2000 : 5000);
    return () => {
      mounted = false;
      clearInterval(iv);
    };
  }, [isRunning]);

  // Sync simulatorRunning prop
  useEffect(() => {
    let active = true;
    Promise.resolve().then(() => {
      if (active) setIsRunning(simulatorRunning);
    });
    return () => {
      active = false;
    };
  }, [simulatorRunning]);

  // Poll live capture status & logs
  useEffect(() => {
    let mounted = true;
    const fetchCaptureStatus = async () => {
      try {
        const res = await apiFetch("/system/capture/status");
        if (!mounted) return;
        setIsCaptureRunning(Boolean(res.running));
        setCaptureStatus(res);
      } catch {}
    };

    fetchCaptureStatus();
    const iv = setInterval(fetchCaptureStatus, isCaptureRunning ? 2000 : 5000);
    return () => {
      mounted = false;
      clearInterval(iv);
    };
  }, [isCaptureRunning]);

  // Sync captureRunning prop
  useEffect(() => {
    let active = true;
    Promise.resolve().then(() => {
      if (active) setIsCaptureRunning(captureRunning);
    });
    return () => {
      active = false;
    };
  }, [captureRunning]);

  // Fetch db stats
  useEffect(() => {
    apiFetch("/dashboard/stats")
      .then(setStats)
      .catch(() => {});
  }, [simulatorRunning, captureRunning]);

  // Auto scroll terminal to bottom on update
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [simulatorLogs]);


  const handleLaunch = async () => {
    setIsStarting(true);
    try {
      if (onStartSimulator) {
        await onStartSimulator({
          scenario,
          speed: Number(speed),
          sessions: Number(sessions),
          auto_switch_mode: true,
        });
      } else {
        await apiPost("/system/simulator/start", {
          scenario,
          speed: Number(speed),
          sessions: Number(sessions),
          auto_switch_mode: true,
        });
      }
      setIsRunning(true);
      if (onToggleMode && systemMode !== "simulated") {
        onToggleMode("simulated");
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    try {
      if (onStopSimulator) {
        await onStopSimulator();
      } else {
        await apiPost("/system/simulator/stop", {});
      }
      setIsRunning(false);
    } catch (e) {
      console.error(e);
    }
  };

  const handleLaunchCapture = async () => {
    setIsCaptureStarting(true);
    try {
      if (onStartLiveCapture) {
        await onStartLiveCapture({
          mode: "auto",
          auto_switch_mode: true,
        });
      } else {
        await apiPost("/system/capture/start", {
          mode: "auto",
          auto_switch_mode: true,
        });
      }
      setIsCaptureRunning(true);
      if (onToggleMode && systemMode !== "live") {
        onToggleMode("live");
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsCaptureStarting(false);
    }
  };

  const handleStopCapture = async () => {
    try {
      if (onStopLiveCapture) {
        await onStopLiveCapture();
      } else {
        await apiPost("/system/capture/stop", {});
      }
      setIsCaptureRunning(false);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="settings-grid">
      {/* Navigation Header Tabs */}
      <div
        className="panel"
        style={{
          gridColumn: "1 / -1",
          background: "var(--bg-surface)",
          border: "1px solid var(--border-dark)",
          padding: "8px 16px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Sliders size={18} color="var(--c-gold)" />
          <div>
            <strong
              style={{ fontSize: "0.95rem", color: "var(--text-primary)" }}
            >
              System Configuration & Cyber Simulation Lab
            </strong>
            <span
              style={{
                display: "block",
                fontSize: "0.72rem",
                color: "var(--text-muted)",
              }}
            >
              Control real-time network capture, synthetic MITRE scenarios, and
              ML world model settings
            </span>
          </div>
        </div>

        <div className="tab-group" style={{ margin: 0, flexWrap: "wrap" }}>
          <button
            className={`tab-btn ${activeTab === "appearance" ? "active" : ""}`}
            onClick={() => setActiveTab("appearance")}
            style={{ fontSize: "0.72rem", padding: "4px 12px" }}
          >
            <Palette size={12} style={{ marginRight: 6 }} />
            Appearance & Theme
          </button>
          <button
            className={`tab-btn ${activeTab === "detection" ? "active" : ""}`}
            onClick={() => setActiveTab("detection")}
            style={{ fontSize: "0.72rem", padding: "4px 12px" }}
          >
            <Shield size={12} style={{ marginRight: 6 }} />
            Detection & Threshold
          </button>
          <button
            className={`tab-btn ${activeTab === "lab" ? "active" : ""}`}
            onClick={() => setActiveTab("lab")}
            style={{ fontSize: "0.72rem", padding: "4px 12px" }}
          >
            <FlaskConical size={12} style={{ marginRight: 6 }} />
            Simulation Lab & Mode
          </button>
          <button
            className={`tab-btn ${activeTab === "architecture" ? "active" : ""}`}
            onClick={() => setActiveTab("architecture")}
            style={{ fontSize: "0.72rem", padding: "4px 12px" }}
          >
            <Cpu size={12} style={{ marginRight: 6 }} />
            Model & Telemetry DB
          </button>
          <button
            className={`tab-btn ${activeTab === "features" ? "active" : ""}`}
            onClick={() => setActiveTab("features")}
            style={{ fontSize: "0.72rem", padding: "4px 12px" }}
          >
            <Layers size={12} style={{ marginRight: 6 }} />
            Feature Dictionary (22)
          </button>
          <button
            className={`tab-btn ${activeTab === "about" ? "active" : ""}`}
            onClick={() => setActiveTab("about")}
            style={{ fontSize: "0.72rem", padding: "4px 12px" }}
          >
            <Info size={12} style={{ marginRight: 6 }} />
            About Garud
          </button>
        </div>
      </div>

      {/* TAB: Appearance & Theme (Only Place Where Theme is Switched) */}
      {activeTab === "appearance" && (
        <div style={{ gridColumn: "1 / -1", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
          {/* Card 1: Theme Selection */}
          <div className="panel" style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
              <Palette size={16} color="var(--accent)" />
              <strong style={{ fontSize: "0.9rem", color: "var(--text-primary)" }}>
                Interface Theme
              </strong>
            </div>
            <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: 16, lineHeight: 1.4 }}>
              Select between the Dark technical operations console and the Light warm technical paper control-room interface. Theme is strictly managed here and persisted in local storage.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {/* Dark Theme Button */}
              <button
                type="button"
                onClick={() => setTheme("dark")}
                style={{
                  background: "#010B0C",
                  border: theme === "dark" ? "2px solid #F6B144" : "1px solid rgba(231,240,244,0.18)",
                  borderRadius: 6,
                  padding: "16px 12px",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 8,
                  cursor: "pointer",
                  color: "#E7F0F4",
                  boxShadow: theme === "dark" ? "0 0 12px rgba(246,177,68,0.25)" : "none",
                  transition: "all 150ms ease",
                }}
              >
                <Moon size={22} color={theme === "dark" ? "#F6B144" : "#9AA6AA"} />
                <span style={{ fontFamily: "var(--font-heading)", fontSize: "0.95rem", fontWeight: 700, letterSpacing: "0.05em" }}>
                  DARK THEME
                </span>
                <span style={{ fontSize: "0.7rem", color: "#9AA6AA", textAlign: "center" }}>
                  Near-black technical palette &bull; High-contrast SOC console
                </span>
                {theme === "dark" && (
                  <span style={{ fontSize: "0.65rem", fontWeight: 700, color: "#F6B144", marginTop: 4 }}>
                    ACTIVE THEME
                  </span>
                )}
              </button>

              {/* Light Theme Button */}
              <button
                type="button"
                onClick={() => setTheme("light")}
                style={{
                  background: "#FAF7F1",
                  border: theme === "light" ? "2px solid #FDB23A" : "1px solid #CFC6B3",
                  borderRadius: 6,
                  padding: "16px 12px",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 8,
                  cursor: "pointer",
                  color: "#252A2D",
                  boxShadow: theme === "light" ? "0 0 12px rgba(253,178,58,0.25)" : "none",
                  transition: "all 150ms ease",
                }}
              >
                <Sun size={22} color={theme === "light" ? "#FDB23A" : "#666B6E"} />
                <span style={{ fontFamily: "var(--font-heading)", fontSize: "0.95rem", fontWeight: 700, letterSpacing: "0.05em" }}>
                  LIGHT THEME
                </span>
                <span style={{ fontSize: "0.7rem", color: "#666B6E", textAlign: "center" }}>
                  Warm technical paper &bull; Defense room document aesthetic
                </span>
                {theme === "light" && (
                  <span style={{ fontSize: "0.65rem", fontWeight: 700, color: "#9A6100", marginTop: 4 }}>
                    ACTIVE THEME
                  </span>
                )}
              </button>
            </div>
          </div>

          {/* Card 2: Density & Motion Controls */}
          <div className="panel" style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
              <Sliders size={16} color="var(--accent)" />
              <strong style={{ fontSize: "0.9rem", color: "var(--text-primary)" }}>
                Display Density & Motion
              </strong>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", marginBottom: 6 }}>
                INTERFACE DENSITY
              </label>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  className={`garud-btn ${density === "comfortable" ? "garud-btn-primary" : ""}`}
                  onClick={() => handleDensityChange("comfortable")}
                  style={{ flex: 1, justifyContent: "center" }}
                >
                  Comfortable
                </button>
                <button
                  type="button"
                  className={`garud-btn ${density === "compact" ? "garud-btn-primary" : ""}`}
                  onClick={() => handleDensityChange("compact")}
                  style={{ flex: 1, justifyContent: "center" }}
                >
                  Compact
                </button>
              </div>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)", marginBottom: 6 }}>
                ACCESSIBILITY MOTION
              </label>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  className={`garud-btn ${!reducedMotion ? "garud-btn-primary" : ""}`}
                  onClick={() => handleMotionChange(false)}
                  style={{ flex: 1, justifyContent: "center" }}
                >
                  Full Motion (Default)
                </button>
                <button
                  type="button"
                  className={`garud-btn ${reducedMotion ? "garud-btn-primary" : ""}`}
                  onClick={() => handleMotionChange(true)}
                  style={{ flex: 1, justifyContent: "center" }}
                >
                  Reduced Motion
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB: Detection & Global Risk Threshold */}
      {activeTab === "detection" && (
        <div style={{ gridColumn: "1 / -1", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
          {/* Card 1: Global Risk Calibration */}
          <div className="panel" style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
              <Shield size={16} color="var(--accent)" />
              <strong style={{ fontSize: "0.9rem", color: "var(--text-primary)" }}>
                Global Detection & Risk Calibration
              </strong>
            </div>
            <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: 16 }}>
              Set the baseline risk threshold above which network flows trigger sustained MITRE kill-chain progression alerts.
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-secondary)" }}>
                    GLOBAL RISK THRESHOLD
                  </span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", fontWeight: 700, color: "var(--accent)" }}>
                    {riskThreshold.toFixed(2)}
                  </span>
                </div>
                <input
                  type="range"
                  min="0.10"
                  max="0.90"
                  step="0.05"
                  value={riskThreshold}
                  onChange={(e) => setRiskThreshold(parseFloat(e.target.value))}
                  style={{ width: "100%", accentColor: "var(--accent)" }}
                />
                <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", display: "block", marginTop: 4 }}>
                  Recommended: 0.40. Lower values increase sensitivity; higher values minimize false alarms.
                </span>

                <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                  <button
                    type="button"
                    className={`garud-btn garud-btn-sm ${riskThreshold === 0.30 ? "garud-btn-primary" : ""}`}
                    onClick={() => setRiskThreshold(0.30)}
                    style={{ flex: 1, justifyContent: "center", fontSize: 10 }}
                  >
                    High Sensitivity (0.30)
                  </button>
                  <button
                    type="button"
                    className={`garud-btn garud-btn-sm ${riskThreshold === 0.40 ? "garud-btn-primary" : ""}`}
                    onClick={() => setRiskThreshold(0.40)}
                    style={{ flex: 1, justifyContent: "center", fontSize: 10 }}
                  >
                    Balanced SOC (0.40)
                  </button>
                  <button
                    type="button"
                    className={`garud-btn garud-btn-sm ${riskThreshold === 0.55 ? "garud-btn-primary" : ""}`}
                    onClick={() => setRiskThreshold(0.55)}
                    style={{ flex: 1, justifyContent: "center", fontSize: 10 }}
                  >
                    Low Noise (0.55)
                  </button>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 8 }}>
                <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "8px 10px" }}>
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>CONSECUTIVE WINDOWS (N)</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.95rem", fontWeight: 700, marginTop: 2 }}>
                    2 Steps (Sustained)
                  </div>
                </div>
                <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "8px 10px" }}>
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>TEMPORAL HORIZON (H)</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.95rem", fontWeight: 700, marginTop: 2 }}>
                    6 Rollout Minutes
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Card 2: MITRE Infiltration & Alert Trigger Rules */}
          <div className="panel" style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
              <Sliders size={16} color="var(--accent)" />
              <strong style={{ fontSize: "0.9rem", color: "var(--text-primary)" }}>
                Attack Progression & Alert Trigger Rules
              </strong>
            </div>
            <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: 14 }}>
              Automated correlation rules tuned to differentiate normal multi-cloud traffic from adversarial attack patterns.
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "10px 12px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-primary)" }}>Reconnaissance & Scan Suppressor</span>
                  <span style={{ fontSize: "0.7rem", color: "var(--success)", fontWeight: 700 }}>ACTIVE</span>
                </div>
                <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", lineHeight: 1.4 }}>
                  Suppresses single isolated probe flows; requires multiple SYN bursts or multi-port sweeps before raising high-priority alert.
                </span>
              </div>

              <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "10px 12px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-primary)" }}>Lateral Movement & Pivot Correlator</span>
                  <span style={{ fontSize: "0.7rem", color: "var(--success)", fontWeight: 700 }}>ACTIVE</span>
                </div>
                <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", lineHeight: 1.4 }}>
                  Detects internal peer-to-peer subnet hops (SMB 445, RPC 135, RDP 3389) linking ingress nodes to protected internal workstations.
                </span>
              </div>

              <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "10px 12px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-primary)" }}>Exfiltration & High Egress Bandwidth</span>
                  <span style={{ fontSize: "0.7rem", color: "var(--danger)", fontWeight: 700 }}>CRITICAL</span>
                </div>
                <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", lineHeight: 1.4 }}>
                  Immediately flags abnormal backward packet byte spikes and elevated PSH flag flushes directed at external endpoints.
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB: About Project Garud */}
      {activeTab === "about" && (
        <div className="panel" style={{ gridColumn: "1 / -1", background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <Info size={16} color="var(--accent)" />
            <strong style={{ fontSize: "0.9rem", color: "var(--text-primary)" }}>
              About Project Garud &mdash; AI Network Attack Forecasting
            </strong>
          </div>
          <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", lineHeight: 1.6, maxWidth: 700 }}>
            <p>
              <strong>Project Garud</strong> is an advanced Defensive Network World Model built for the Smart India Hackathon (SIH) 2026 under Problem Statement <strong>PS26153</strong>.
            </p>
            <p>
              Unlike legacy Intrusion Detection Systems (IDS) that only identify attacks after compromise, Garud forecasts multi-step attack progression across 5 MITRE ATT&CK kill-chain stages up to 6 minutes into the future.
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginTop: 16 }}>
              <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "10px" }}>
                <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>ORGANIZATION</div>
                <strong style={{ color: "var(--text-primary)" }}>SIH 2026 &bull; PS26153</strong>
              </div>
              <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "10px" }}>
                <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>TEAM</div>
                <strong style={{ color: "var(--text-primary)" }}>Team Code 4 Change</strong>
              </div>
              <div style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "10px" }}>
                <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>MODEL ARCHITECTURE</div>
                <strong style={{ color: "var(--text-primary)" }}>LSTM World Model (22 Feat)</strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 1: Simulation Lab & Source Controls */}
      {activeTab === "lab" && (
        <>
          {/* Master Telemetry Mode Selector */}
          <div
            className="panel"
            style={{
              gridColumn: "1 / -1",
              border:
                systemMode === "live"
                  ? "1px solid var(--severity-low)"
                  : "1px solid var(--c-gold)",
              background:
                systemMode === "live"
                  ? "rgba(88, 166, 104, 0.04)"
                  : "rgba(214, 179, 106, 0.04)",
            }}
          >
            <div className="panel-header">
              <span className="panel-title">
                Active Operating Telemetry Mode
              </span>
              <span className="panel-meta">
                Currently running in:{" "}
                <strong
                  style={{
                    color:
                      systemMode === "live"
                        ? "var(--severity-low)"
                        : "var(--c-gold)",
                    textTransform: "uppercase",
                  }}
                >
                  {systemMode} Mode
                </strong>
              </span>
            </div>

            <div className="panel-body">
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                  gap: "var(--sp-4)",
                }}
              >
                {/* Live Real-Time Card */}
                <div
                  onClick={() => onToggleMode?.("live")}
                  style={{
                    padding: "14px 16px",
                    borderRadius: "var(--radius-sm)",
                    border:
                      systemMode === "live"
                        ? "2px solid var(--severity-low)"
                        : "1px solid var(--border-dark)",
                    background:
                      systemMode === "live"
                        ? "var(--success-soft)"
                        : "var(--bg-raised)",
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 6,
                    }}
                  >
                    <div
                      style={{ display: "flex", alignItems: "center", gap: 8 }}
                    >
                      <Wifi size={16} color="var(--severity-low)" />
                      <strong
                        style={{
                          fontSize: "0.92rem",
                          color: "var(--severity-low)",
                          textTransform: "uppercase",
                        }}
                      >
                        Live Real-Time Capture
                      </strong>
                    </div>
                    {systemMode === "live" && (
                      <span
                        style={{
                          fontSize: "0.68rem",
                          fontWeight: 800,
                          color: "var(--severity-low)",
                          background: "rgba(88, 166, 104, 0.2)",
                          padding: "2px 8px",
                          borderRadius: 4,
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 4,
                        }}
                      >
                        <CheckCircle2 size={10} /> Active
                      </span>
                    )}
                  </div>
                  <p
                    style={{
                      fontSize: "0.78rem",
                      color: "var(--text-secondary)",
                      margin: 0,
                      lineHeight: 1.4,
                    }}
                  >
                    Operational defense mode. Real packets intercepted from host
                    network adapters by <code>live_capture.py</code> are
                    inspected by the LSTM model. Synthetic simulation traffic is
                    strictly rejected.
                  </p>

                  {systemMode === "live" && (
                    <div
                      style={{
                        marginTop: 10,
                        paddingTop: 8,
                        borderTop: "1px solid rgba(88, 166, 104, 0.2)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: 8,
                      }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span
                        style={{
                          fontSize: "0.72rem",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          color: isCaptureRunning
                            ? "var(--severity-low)"
                            : "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        <span
                          style={{
                            width: 6,
                            height: 6,
                            borderRadius: "50%",
                            background: isCaptureRunning
                              ? "var(--severity-low)"
                              : "var(--text-muted)",
                            boxShadow: isCaptureRunning
                              ? "0 0 6px var(--severity-low)"
                              : "none",
                          }}
                        />
                        {isCaptureRunning
                          ? `Host Sniffer Active (PID ${captureStatus?.pid || ""})`
                          : "Sniffer Idle"}
                      </span>

                      {isCaptureRunning ? (
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={handleStopCapture}
                          style={{ fontSize: "0.7rem", padding: "2px 8px" }}
                        >
                          <Square size={10} fill="currentColor" /> Stop Sniffer
                        </button>
                      ) : (
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={handleLaunchCapture}
                          disabled={isCaptureStarting}
                          style={{ fontSize: "0.7rem", padding: "2px 10px" }}
                        >
                          {isCaptureStarting ? (
                            <RefreshCw size={10} className="spin" />
                          ) : (
                            <Play size={10} fill="currentColor" />
                          )}
                          Start Sniffer
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {/* Simulation Research Lab Card */}
                <div
                  onClick={() => onToggleMode?.("simulated")}
                  style={{
                    padding: "14px 16px",
                    borderRadius: "var(--radius-sm)",
                    border:
                      systemMode === "simulated"
                        ? "2px solid var(--c-gold)"
                        : "1px solid var(--border-dark)",
                    background:
                      systemMode === "simulated"
                        ? "var(--accent-soft)"
                        : "var(--bg-raised)",
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 6,
                    }}
                  >
                    <div
                      style={{ display: "flex", alignItems: "center", gap: 8 }}
                    >
                      <FlaskConical size={16} color="var(--c-gold)" />
                      <strong
                        style={{
                          fontSize: "0.92rem",
                          color: "var(--c-gold)",
                          textTransform: "uppercase",
                        }}
                      >
                        Simulation Research Lab
                      </strong>
                    </div>
                    {systemMode === "simulated" && (
                      <span
                        style={{
                          fontSize: "0.68rem",
                          fontWeight: 800,
                          color: "var(--c-gold)",
                          background: "rgba(214, 179, 106, 0.2)",
                          padding: "2px 8px",
                          borderRadius: 4,
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 4,
                        }}
                      >
                        <CheckCircle2 size={10} /> Active
                      </span>
                    )}
                  </div>
                  <p
                    style={{
                      fontSize: "0.78rem",
                      color: "var(--text-secondary)",
                      margin: 0,
                      lineHeight: 1.4,
                    }}
                  >
                    Research, stress testing, and demonstration mode. Inject
                    multi-stage MITRE ATT&CK scenarios to evaluate live
                    detection, attribution, and 4-minute future horizon
                    forecasting.
                  </p>
                </div>
              </div>
            </div>
          </div>


          {/* Interactive Simulation Lab Console */}
          <div className="panel" style={{ gridColumn: "1 / -1" }}>
            <div
              className="panel-header"
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: "var(--sp-2)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <FlaskConical size={16} color="var(--c-gold)" />
                <span className="panel-title">
                  Cyber Attack Simulation Suite
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "3px 10px",
                    borderRadius: "var(--radius-sm)",
                    background: isRunning
                      ? "var(--success-soft)"
                      : "var(--bg-raised)",
                    border: `1px solid ${isRunning ? "var(--success)" : "var(--border)"}`,
                    color: isRunning
                      ? "var(--severity-low)"
                      : "var(--text-muted)",
                    fontSize: "0.75rem",
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: isRunning
                        ? "var(--severity-low)"
                        : "var(--text-muted)",
                      boxShadow: isRunning
                        ? "0 0 6px var(--severity-low)"
                        : "none",
                    }}
                  />
                  {isRunning ? "Simulator Process Running" : "Simulator Idle"}
                </span>

                {isRunning ? (
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={handleStop}
                    style={{ fontSize: "0.72rem", padding: "4px 12px" }}
                  >
                    <Square size={11} fill="currentColor" /> STOP SIMULATOR
                  </button>
                ) : (
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={handleLaunch}
                    disabled={isStarting}
                    style={{ fontSize: "0.72rem", padding: "4px 14px" }}
                  >
                    {isStarting ? (
                      <RefreshCw size={11} className="spin" />
                    ) : (
                      <Play size={11} fill="currentColor" />
                    )}
                    LAUNCH ATTACK SCENARIO
                  </button>
                )}

                <button
                  className="btn btn-sm btn-outline"
                  onClick={onPurgeSimulated}
                  style={{
                    color: "var(--c-red)",
                    fontSize: "0.72rem",
                    padding: "4px 10px",
                  }}
                  title="Purge all simulated records from SQLite database"
                >
                  <Trash2 size={11} /> PURGE SIMULATED
                </button>
              </div>
            </div>

            <div className="panel-body">
              {/* Scenario Picker Cards */}
              <div style={{ marginBottom: "16px" }}>
                <span
                  style={{
                    fontSize: "0.72rem",
                    color: "var(--text-muted)",
                    fontWeight: 700,
                    letterSpacing: "0.06em",
                    display: "block",
                    marginBottom: 8,
                  }}
                >
                  SELECT ATTACK SCENARIO PROFILE:
                </span>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                    gap: "10px",
                  }}
                >
                  {SCENARIOS.map((sc) => {
                    const isSelected = scenario === sc.id;
                    return (
                      <div
                        key={sc.id}
                        onClick={() => setScenario(sc.id)}
                        style={{
                          background: isSelected
                            ? "var(--accent-soft)"
                            : "var(--bg-raised)",
                          border: `1px solid ${isSelected ? "var(--c-gold)" : "var(--border-dark)"}`,
                          borderRadius: "var(--radius-sm)",
                          padding: "10px 14px",
                          cursor: "pointer",
                          transition: "all 0.15s ease",
                          position: "relative",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: 4,
                          }}
                        >
                          <strong
                            style={{
                              fontSize: "0.85rem",
                              color: isSelected
                                ? "var(--c-gold)"
                                : "var(--text-primary)",
                            }}
                          >
                            {sc.name}
                          </strong>
                          <span
                            style={{
                              fontSize: "0.62rem",
                              fontWeight: 800,
                              color: sc.badgeColor,
                              border: `1px solid ${sc.badgeColor}40`,
                              background: `${sc.badgeColor}15`,
                              padding: "1px 6px",
                              borderRadius: 3,
                            }}
                          >
                            {sc.badge}
                          </span>
                        </div>
                        <p
                          style={{
                            fontSize: "0.72rem",
                            color: "var(--text-muted)",
                            margin: 0,
                            lineHeight: 1.35,
                          }}
                        >
                          {sc.desc}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Execution Controls: Pace & Scale */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
                  gap: 14,
                  padding: "12px 14px",
                  background: "var(--bg-raised)",
                  borderRadius: "var(--radius-sm)",
                  border: "1px solid var(--border)",
                  marginBottom: 16,
                }}
              >
                <div>
                  <label
                    style={{
                      fontSize: "0.72rem",
                      color: "var(--text-muted)",
                      fontWeight: 700,
                      display: "block",
                      marginBottom: 6,
                    }}
                  >
                    INJECTION CADENCE (SPEED):
                  </label>
                  <div style={{ display: "flex", gap: 8 }}>
                    {[
                      { val: 0.5, label: "0.5s (Rapid Demo)" },
                      { val: 1.0, label: "1.0s (Normal Flow)" },
                      { val: 2.0, label: "2.0s (Deliberate)" },
                    ].map((s) => (
                      <button
                        key={s.val}
                        className={`btn btn-sm ${speed === s.val ? "btn-primary" : "btn-outline"}`}
                        onClick={() => setSpeed(s.val)}
                        style={{
                          fontSize: "0.7rem",
                          padding: "3px 10px",
                          flex: 1,
                        }}
                      >
                        {s.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label
                    style={{
                      fontSize: "0.72rem",
                      color: "var(--text-muted)",
                      fontWeight: 700,
                      display: "block",
                      marginBottom: 6,
                    }}
                  >
                    CONCURRENT SESSIONS:
                  </label>
                  <div style={{ display: "flex", gap: 8 }}>
                    {[
                      { val: 2, label: "2 Sessions" },
                      { val: 4, label: "4 Sessions" },
                      { val: 8, label: "8 Sessions" },
                    ].map((c) => (
                      <button
                        key={c.val}
                        className={`btn btn-sm ${sessions === c.val ? "btn-primary" : "btn-outline"}`}
                        onClick={() => setSessions(c.val)}
                        style={{
                          fontSize: "0.7rem",
                          padding: "3px 10px",
                          flex: 1,
                        }}
                      >
                        {c.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Integrated Real-Time Simulator Output Terminal */}
              <div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 6,
                  }}
                >
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 6 }}
                  >
                    <Terminal size={14} color="var(--c-gold)" />
                    <span
                      style={{
                        fontSize: "0.74rem",
                        fontWeight: 700,
                        color: "var(--text-primary)",
                      }}
                    >
                      Live Simulator Output Stream
                    </span>
                  </div>
                  <span
                    className="mono"
                    style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}
                  >
                    {isRunning
                      ? "Receiving output from demo/traffic_simulator.py"
                      : "Subprocess idle — click Launch to stream"}
                  </span>
                </div>

                <div
                  ref={logContainerRef}
                  style={{
                    background: "var(--bg-inset)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "10px 14px",
                    height: "180px",
                    overflowY: "auto",
                    fontFamily: "var(--font-mono)",
                    fontSize: "0.72rem",
                    color: "var(--text-primary)",
                    lineHeight: 1.5,
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {simulatorLogs ? (
                    simulatorLogs
                  ) : (
                    <span style={{ color: "var(--text-muted)" }}>
                      Simulator output will stream here in real-time when an
                      attack scenario is launched...
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* TAB 2: Model Architecture & Telemetry Database */}
      {activeTab === "architecture" && (
        <div style={{ gridColumn: "1 / -1", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: 16 }}>
          {/* World Model Architecture Card */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">LSTM World Model Architecture</span>
            </div>
            <div className="panel-body">
              <div className="settings-row">
                <span className="settings-key">Model Network Type</span>
                <span className="settings-val">
                  {health?.num_layers ?? "—"}-Layer PyTorch LSTM Network
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Hidden Dimension</span>
                <span className="settings-val">
                  {health?.hidden_size ?? "—"} units
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Dropout Regularization</span>
                <span className="settings-val">{health?.dropout ?? "—"}</span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Execution Device</span>
                <span
                  className="settings-val"
                  style={{ color: "var(--c-gold)" }}
                >
                  {health?.device?.toUpperCase() || "—"}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Input Feature Vector</span>
                <span className="settings-val">
                  {health?.features_count ?? "—"} flow features
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Temporal Lookback Window</span>
                <span className="settings-val">
                  {health?.window_size ?? "—"} consecutive flows
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Forecast Rollout Horizon</span>
                <span className="settings-val">
                  4 consecutive minutes (t+1..t+4)
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">
                  Alert Infiltration Threshold
                </span>
                <span className="settings-val">
                  0.50 (Adaptive Sustained Alert)
                </span>
              </div>
            </div>
          </div>

          {/* Database Persistence Telemetry */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">
                Persistence & Storage Telemetry
              </span>
            </div>
            <div className="panel-body">
              <div className="settings-row">
                <span className="settings-key">Database Engine</span>
                <span className="settings-val">
                  SQLite via SQLAlchemy Async (aiosqlite)
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Database Connected</span>
                <span
                  className="settings-val"
                  style={{
                    color: health?.db_connected
                      ? "var(--severity-low)"
                      : "var(--c-red)",
                  }}
                >
                  {health?.db_connected ? "YES (ACTIVE)" : "NO"}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Total Flow Records</span>
                <span className="settings-val mono">
                  {stats?.total_flows ?? 0}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Total Tracked Sessions</span>
                <span className="settings-val mono">
                  {stats?.total_sessions ?? 0}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Active High-Risk Sessions</span>
                <span
                  className="settings-val mono"
                  style={{
                    color:
                      (stats?.at_risk_sessions || 0) > 0
                        ? "var(--c-red)"
                        : "var(--severity-low)",
                  }}
                >
                  {stats?.at_risk_sessions ?? 0}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Inbound Ingress Sessions</span>
                <span className="settings-val mono">
                  {stats?.direction_breakdown?.inbound ?? 0}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Outbound Sessions</span>
                <span className="settings-val mono">
                  {stats?.direction_breakdown?.outbound ?? 0}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-key">Artifacts Checkpoint</span>
                <span
                  className="settings-val text-sm"
                  style={{
                    maxWidth: "240px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {health?.artifacts_path || "backend/artifacts/"}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Feature Reference Dictionary */}
      {activeTab === "features" && (
        <div className="panel" style={{ gridColumn: "1 / -1" }}>
          <div className="panel-header">
            <span className="panel-title">
              Temporal Flow Feature Dictionary
            </span>
            <span className="panel-meta">
              All 22 features extracted per sliding network flow window
            </span>
          </div>
          <div className="panel-body">
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: "10px",
              }}
            >
              {FEATURE_DEFINITIONS.map((f) => (
                <div
                  key={f.key}
                  style={{
                    background: "var(--bg-raised)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "10px 12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: 3,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "baseline",
                    }}
                  >
                    <strong
                      style={{
                        fontSize: "0.82rem",
                        color: "var(--text-primary)",
                      }}
                    >
                      {formatFeatureName(f.key)}
                    </strong>
                    <span
                      className="mono"
                      style={{
                        fontSize: "0.64rem",
                        color: "var(--c-gold)",
                        background: "rgba(214, 179, 106, 0.1)",
                        padding: "1px 5px",
                        borderRadius: 3,
                      }}
                    >
                      {f.unit}
                    </span>
                  </div>
                  <span
                    className="mono"
                    style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}
                  >
                    [{f.key}]
                  </span>
                  <p
                    style={{
                      fontSize: "0.72rem",
                      color: "var(--text-muted)",
                      margin: "4px 0 0 0",
                      lineHeight: 1.35,
                    }}
                  >
                    {f.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export { SettingsPanel as SettingsView };
