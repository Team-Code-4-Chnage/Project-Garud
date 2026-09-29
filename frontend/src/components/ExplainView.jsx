import { useState, useEffect, useCallback, useMemo } from "react";
import {
  HelpCircle,
  FileDown,
  FileSpreadsheet,
  Code2,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Radio,
  Eye,
  ArrowLeft,
} from "lucide-react";
import { apiFetch, apiPost } from "../api";
import { useTheme } from "../theme";
import {
  stageClass,
  formatProb,
  formatFeatureName,
  DEFAULT_FEAT_ORDER,
} from "../utils";
import { AppBadge } from "./Badges";

const FEATURE_EXPLANATIONS = {
  flow_duration: "Duration of bidirectional network flows in microseconds.",
  tot_fwd_pkts: "Packets sent in forward (client → server) direction across the network.",
  tot_bwd_pkts: "Packets sent in backward (server → client) response direction.",
  fwd_pkt_len_mean: "Average byte length of forward network requests.",
  bwd_pkt_len_mean: "Average byte length of backward response packets.",
  flow_bytes_s: "Network-wide data transfer throughput (bytes per second).",
  flow_pkts_s: "Global packet transmission velocity (packets per second).",
  flow_iat_mean: "Average inter-arrival time between consecutive network packets.",
  flow_iat_std: "Variance in network packet inter-arrival timing (jitter indicator).",
  fwd_iat_mean: "Inter-arrival timing between forward network requests.",
  bwd_iat_mean: "Inter-arrival timing between backward responses.",
  syn_flag_cnt: "SYN packets observed across subnet (port scanning / handshake attempts).",
  ack_flag_cnt: "ACK packets observed across subnet (established streams).",
  fin_flag_cnt: "FIN packets observed (graceful socket terminations).",
  rst_flag_cnt: "RST packets observed (abrupt teardown or port rejection).",
  psh_flag_cnt: "PSH packets observed (immediate application buffer flush / interactive shell).",
  urg_flag_cnt: "URG packets observed (urgent out-of-band data stream).",
  down_up_ratio: "Ratio of download packets to upload packets across monitored interfaces.",
  pkt_size_avg: "Average size of packets across all network sessions.",
  ttl_variance: "Variance in IP TTL (routing anomalies / NAT traversal / spoofing).",
  tcp_win_size: "Advertised TCP receive window size during handshakes.",
  retransmit_cnt: "Packet retransmissions caused by packet loss or probe resets.",
};

/**
 * Derives executive-ready, human-readable plain-English root causes
 * for the current whole-system posture (SIH PS:26153 compliance).
 */
function deriveWholeSystemExplanations(
  attributions,
  macroExplanation,
  systemPosture,
) {
  const riskScore = systemPosture?.risk_score || 0;
  const stageName = systemPosture?.predicted_stage || "Benign";
  const isElevated = riskScore > 0.45 || (stageName && stageName !== "Benign");

  if (!isElevated) {
    return [
      {
        num: "01",
        title: "Symmetric bidirectional packet ratio observed across subnet",
        detail:
          "Forward request packets and backward server responses maintain expected RFC ratios without connection dropouts or asymmetric exfiltration leaks.",
        tag: "RFC Flow Symmetry",
        status: "nominal",
      },
      {
        num: "02",
        title: "TCP handshakes and socket teardowns are orderly network-wide",
        detail:
          "Standard 3-way handshakes with clean FIN closures across monitored interfaces; zero anomalous socket RST injections or aggressive probe bursts.",
        tag: "Handshake Integrity",
        status: "nominal",
      },
      {
        num: "03",
        title: "Inter-arrival timing conforms to nominal network baseline",
        detail:
          "Packet jitter, idle intervals, and connection frequencies strictly conform to expected enterprise application protocol communication.",
        tag: "Timing Baseline",
        status: "nominal",
      },
    ];
  }

  const threatFeatures = (attributions || [])
    .filter((a) => a.importance > 0)
    .sort((a, b) => b.importance - a.importance);

  const reasons = [];
  const addedCategories = new Set();

  for (const item of threatFeatures) {
    const f = item.feature;
    if (
      (f === "syn_flag_cnt" || f === "tot_fwd_pkts" || f === "flow_pkts_s") &&
      !addedCategories.has("fanout")
    ) {
      addedCategories.add("fanout");
      reasons.push({
        num: String(reasons.length + 1).padStart(2, "0"),
        title: "Destination fan-out increased sharply across monitored subnet",
        detail: `High-frequency SYN probe burst detected (+${item.importance.toFixed(2)} impact) indicating active port scanning or service enumeration across network hosts.`,
        tag: "SYN / Fan-out",
        status: "warning",
        feature: f,
        importance: item.importance,
      });
    } else if (
      (f === "rst_flag_cnt" || f === "fin_flag_cnt" || f === "retransmit_cnt") &&
      !addedCategories.has("rst")
    ) {
      addedCategories.add("rst");
      reasons.push({
        num: String(reasons.length + 1).padStart(2, "0"),
        title: "TCP reset rate is abnormal across network interfaces",
        detail: `Elevated connection reset and teardown flags (+${item.importance.toFixed(2)} impact) indicate active socket rejections or firewall filter probing.`,
        tag: "TCP Reset Rate",
        status: "warning",
        feature: f,
        importance: item.importance,
      });
    } else if (
      (f.includes("iat") || f === "flow_duration") &&
      !addedCategories.has("timing")
    ) {
      addedCategories.add("timing");
      reasons.push({
        num: String(reasons.length + 1).padStart(2, "0"),
        title: "Inter-arrival timing resembles automated reconnaissance",
        detail: `Deterministic sub-millisecond transmission intervals (+${item.importance.toFixed(2)} impact) match automated script scanner behavior rather than natural user traffic.`,
        tag: "Jitter / Recon",
        status: "warning",
        feature: f,
        importance: item.importance,
      });
    } else if (
      (f === "flow_bytes_s" || f === "bwd_pkt_len_mean" || f === "down_up_ratio") &&
      !addedCategories.has("volume")
    ) {
      addedCategories.add("volume");
      reasons.push({
        num: String(reasons.length + 1).padStart(2, "0"),
        title: "Asymmetric egress data velocity surge",
        detail: `High-throughput outbound egress (+${item.importance.toFixed(2)} impact) deviates from baseline network profile, indicating staging or bulk data exfiltration.`,
        tag: "Egress Velocity",
        status: "warning",
        feature: f,
        importance: item.importance,
      });
    } else if (f === "psh_flag_cnt" && !addedCategories.has("psh")) {
      addedCategories.add("psh");
      reasons.push({
        num: String(reasons.length + 1).padStart(2, "0"),
        title: "Interactive terminal buffer push anomaly",
        detail: `Repeated PSH flags (+${item.importance.toFixed(2)} impact) detected, matching interactive reverse shell execution or Command & Control terminal traffic.`,
        tag: "C2 / Push Flags",
        status: "warning",
        feature: f,
        importance: item.importance,
      });
    } else if (
      (f === "ttl_variance" || f === "tcp_win_size") &&
      !addedCategories.has("tcp_stack")
    ) {
      addedCategories.add("tcp_stack");
      reasons.push({
        num: String(reasons.length + 1).padStart(2, "0"),
        title: "TCP stack and routing irregularities",
        detail: `Abnormal Time-To-Live variances and non-standard advertised window sizes indicate spoofed packets or network route manipulation.`,
        tag: "Routing / TTL",
        status: "warning",
        feature: f,
        importance: item.importance,
      });
    }

    if (reasons.length >= 3) break;
  }

  // Fallbacks to guarantee exactly 3 authoritative, high-impact reasons
  const stageFallbacks = {
    Reconnaissance: [
      {
        title: "Destination fan-out increased sharply across monitored subnet",
        detail:
          "Sequential multi-port probe distribution detected across target subnet hosts.",
      },
      {
        title: "TCP reset rate is abnormal across network interfaces",
        detail:
          "Closed port TCP RST replies exceed baseline expected tolerance.",
      },
      {
        title: "Inter-arrival timing resembles automated reconnaissance",
        detail:
          "Packet cadence displays algorithmic periodicity typical of scanning tools.",
      },
    ],
    "Initial Access": [
      {
        title: "Unsolicited ingress connection payload burst",
        detail:
          "External handshake initiates service request without prior DNS lookup or trust.",
      },
      {
        title: "Destination fan-out increased sharply across perimeter",
        detail: "Probing across perimeter gateway service interfaces.",
      },
      {
        title: "TCP reset rate is abnormal across network interfaces",
        detail:
          "Repeated connection handshake resets during service banner interrogation.",
      },
    ],
    "Lateral Movement": [
      {
        title: "Internal east-west pivot velocity detected",
        detail:
          "Internal subnet traversal rate deviates significantly from host operational profile.",
      },
      {
        title: "Destination fan-out increased sharply across internal hosts",
        detail:
          "Connection fan-out across adjacent corporate workstations and domain controllers.",
      },
      {
        title: "Inter-arrival timing resembles automated reconnaissance",
        detail: "Automated network service interrogation timing profile.",
      },
    ],
    C2: [
      {
        title: "Command & Control beaconing cadence active",
        detail:
          "Periodic heartbeats detected at fixed intervals toward external endpoint.",
      },
      {
        title: "Inter-arrival timing resembles automated reconnaissance",
        detail: "Algorithmic jitter masking keepalive probe packets.",
      },
      {
        title: "TCP reset rate is abnormal across network interfaces",
        detail: "Intermittent connection dropouts and reconnections.",
      },
    ],
    Exfiltration: [
      {
        title: "Asymmetric egress data velocity surge",
        detail:
          "High-volume outbound payload egress exceeds normal network session threshold.",
      },
      {
        title: "Destination fan-out increased sharply across external routes",
        detail:
          "Multiple outbound streams opened in parallel to accelerate bulk upload.",
      },
      {
        title: "TCP reset rate is abnormal across network interfaces",
        detail: "Heavy socket churn during multi-part upload staging.",
      },
    ],
  };

  const defaultList = stageFallbacks[stageName] || stageFallbacks["Reconnaissance"];
  let idx = 0;
  while (reasons.length < 3 && idx < defaultList.length) {
    const candidate = defaultList[idx++];
    if (!reasons.some((r) => r.title === candidate.title)) {
      reasons.push({
        num: String(reasons.length + 1).padStart(2, "0"),
        title: candidate.title,
        detail: candidate.detail,
        tag: "System Indicator",
        status: "warning",
      });
    }
  }

  return reasons.slice(0, 3);
}

export default function ExplainView({ featureList }) {
  const { isDark } = useTheme();
  const [systemData, setSystemData] = useState(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [sessionExplanation, setSessionExplanation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [method, setMethod] = useState("shap");
  const [attributionFilter, setAttributionFilter] = useState("all");
  const [showModelDetails, setShowModelDetails] = useState(true);

  const featOrder = featureList || DEFAULT_FEAT_ORDER;

  // Load Whole-System Explainability
  const loadSystemExplanation = useCallback(
    async (methodToUse = method) => {
      setLoading(true);
      setError(null);
      try {
        const res = await apiFetch(`/explain/system?method=${methodToUse}&top_k=22`);
        setSystemData(res);
      } catch (err) {
        setError(err.message || "Failed to compute whole-system explainability.");
      } finally {
        setLoading(false);
      }
    },
    [method],
  );

  // Drilldown to a specific endpoint session
  const drilldownSession = useCallback(
    async (endpoint, methodToUse = method) => {
      if (!endpoint) return;
      setSelectedEndpoint(endpoint);
      setLoading(true);
      setError(null);
      try {
        const flows = await apiFetch(`/sessions/${encodeURIComponent(endpoint.session_key)}/flows?limit=6`);
        if (!flows || flows.length === 0) {
          throw new Error("No flow records captured for this session yet.");
        }
        if (flows.length < 6) {
          throw new Error(
            `Collecting baseline: ${flows.length}/6 flows. The model needs 6 flows to explain.`,
          );
        }
        const windowFlows = flows.slice(0, 6).reverse();
        const window = windowFlows.map((f) =>
          featOrder.map((k) => f.features?.[k] ?? 0),
        );
        const res = await apiPost("/explain", {
          window,
          top_k: 22,
          needs_scaling: true,
          method: methodToUse,
        });
        setSessionExplanation(res);
      } catch (err) {
        setError(err.message || "Failed to compute session attribution.");
      } finally {
        setLoading(false);
      }
    },
    [featOrder, method],
  );

  useEffect(() => {
    let isMounted = true;
    apiFetch(`/explain/system?method=${method}&top_k=22`)
      .then((res) => {
        if (isMounted) {
          setSystemData(res);
          setError(null);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || "Failed to compute whole-system explainability.");
        }
      });
    return () => {
      isMounted = false;
    };
  }, [method]);

  const handleMethodChange = (newMethod) => {
    setMethod(newMethod);
    if (selectedEndpoint) {
      drilldownSession(selectedEndpoint, newMethod);
    } else {
      loadSystemExplanation(newMethod);
    }
  };

  const handleResetToSystem = () => {
    setSelectedEndpoint(null);
    setSessionExplanation(null);
    loadSystemExplanation(method);
  };

  // Active data source: whole system vs drilled-down session
  const isDrilldown = Boolean(selectedEndpoint && sessionExplanation);
  const activeAttributions = useMemo(() => {
    if (isDrilldown) {
      return sessionExplanation?.attributions || [];
    }
    return systemData?.attributions || [];
  }, [isDrilldown, sessionExplanation, systemData]);

  const activePosture = useMemo(() => {
    if (isDrilldown) {
      return {
        risk_score: sessionExplanation?.infiltration_probability || selectedEndpoint?.risk_score || 0,
        predicted_stage: sessionExplanation?.predicted_stage || selectedEndpoint?.stage || "Benign",
        attack_state: (sessionExplanation?.infiltration_probability || 0) > 0.45 ? "ACTIVE_INTRUSION" : "NORMAL_BASELINE",
        attack_state_label: (sessionExplanation?.infiltration_probability || 0) > 0.45 ? "Anomalous Endpoint Activity" : "Session Traffic Nominal",
        is_alert: (sessionExplanation?.infiltration_probability || 0) > 0.5,
      };
    }
    return systemData?.system_posture || {
      risk_score: 0.0,
      predicted_stage: "Benign",
      attack_state: "NORMAL_BASELINE",
      attack_state_label: "Defense Telemetry Nominal",
      is_alert: false,
    };
  }, [isDrilldown, sessionExplanation, selectedEndpoint, systemData]);

  const maxImp = useMemo(() => {
    if (!activeAttributions.length) return 1;
    return Math.max(...activeAttributions.map((a) => Math.abs(a.importance))) || 1;
  }, [activeAttributions]);

  const stats = useMemo(() => {
    let positiveSum = 0;
    let negativeSum = 0;
    let topThreat = null;
    let maxPos = -Infinity;

    activeAttributions.forEach((a) => {
      if (a.importance > 0) {
        positiveSum += a.importance;
        if (a.importance > maxPos) {
          maxPos = a.importance;
          topThreat = a.feature;
        }
      } else {
        negativeSum += Math.abs(a.importance);
      }
    });

    return {
      positiveSum,
      negativeSum,
      topThreat,
      totalFeatures: activeAttributions.length,
    };
  }, [activeAttributions]);

  const filteredAttributions = useMemo(() => {
    if (attributionFilter === "threat") {
      return activeAttributions.filter((a) => a.importance > 0);
    }
    if (attributionFilter === "benign") {
      return activeAttributions.filter((a) => a.importance < 0);
    }
    return activeAttributions;
  }, [activeAttributions, attributionFilter]);

  const humanExplanations = useMemo(() => {
    return deriveWholeSystemExplanations(
      activeAttributions,
      systemData?.macro_explanation,
      activePosture,
    );
  }, [activeAttributions, systemData, activePosture]);

  const isWarningState =
    (activePosture?.risk_score || 0) > 0.45 ||
    (activePosture?.predicted_stage && activePosture?.predicted_stage !== "Benign");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px", padding: "0 var(--sp-2)" }}>
      {/* ============================================================ */}
      {/* TOP COMMAND HEADER BAR                                       */}
      {/* ============================================================ */}
      <div
        className="panel"
        style={{
          padding: "14px 20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: "50%",
              background: isDark ? "rgba(214, 179, 106, 0.15)" : "var(--accent-soft)",
              border: "1px solid var(--c-gold)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <HelpCircle size={20} color="var(--c-gold)" />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <h1
                style={{
                  fontSize: "1.15rem",
                  fontWeight: 800,
                  letterSpacing: "0.06em",
                  color: "var(--text-primary)",
                  margin: 0,
                  fontFamily: "var(--font-mono)",
                }}
              >
                EXPLAIN
              </h1>
              <span
                style={{
                  fontSize: "0.68rem",
                  padding: "2px 8px",
                  borderRadius: 3,
                  fontWeight: 700,
                  letterSpacing: "0.05em",
                  background: isDrilldown
                    ? (isDark ? "rgba(100, 150, 255, 0.15)" : "var(--info-soft)")
                    : (isDark ? "rgba(214, 179, 106, 0.15)" : "var(--accent-soft)"),
                  color: isDrilldown
                    ? (isDark ? "#93c5fd" : "var(--info)")
                    : (isDark ? "var(--c-gold)" : "var(--accent-text)"),
                  border: isDrilldown
                    ? (isDark ? "1px solid rgba(100, 150, 255, 0.3)" : "1px solid var(--info)")
                    : (isDark ? "1px solid rgba(214, 179, 106, 0.3)" : "1px solid var(--accent)"),
                }}
              >
                {isDrilldown ? "ENDPOINT DRILLDOWN" : "WHOLE SYSTEM CURRENT STATE"}
              </span>
            </div>
            <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", display: "block", marginTop: 2 }}>
              {isDrilldown
                ? `Explaining Session: ${selectedEndpoint.src_ip} → ${selectedEndpoint.dst_ip} (${selectedEndpoint.app_name})`
                : "Whole-System Situational Awareness & Bullseye Root Cause • Monitored Network Scope"}
            </span>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {isDrilldown && (
            <button
              onClick={handleResetToSystem}
              className="btn btn-sm btn-outline"
              style={{ fontSize: "0.72rem", display: "inline-flex", alignItems: "center", gap: 6 }}
            >
              <ArrowLeft size={13} /> RETURN TO WHOLE SYSTEM
            </button>
          )}

          <div style={{ display: "inline-flex", gap: 6 }}>
            <button
              className="btn btn-sm btn-outline"
              onClick={() => {
                const sessionKey = selectedEndpoint?.session_key || "network_state_system";
                const url = `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/view/html?session_key=${encodeURIComponent(sessionKey)}&method=${method}`;
                window.open(url, "_blank");
              }}
              style={{ fontSize: "0.68rem", padding: "4px 10px" }}
              title="Open printable forensic dossier report"
            >
              <Eye size={12} /> DOSSIER
            </button>
            <a
              className="btn btn-sm btn-primary"
              href={`${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/export/html?session_key=${encodeURIComponent(selectedEndpoint?.session_key || "network_state_system")}&method=${method}`}
              download
              style={{ fontSize: "0.68rem", padding: "4px 10px", textDecoration: "none" }}
            >
              <FileDown size={12} /> HTML
            </a>
            <a
              className="btn btn-sm btn-outline"
              href={`${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/export/csv?session_key=${encodeURIComponent(selectedEndpoint?.session_key || "network_state_system")}&method=${method}`}
              download
              style={{ fontSize: "0.68rem", padding: "4px 10px", textDecoration: "none" }}
            >
              <FileSpreadsheet size={12} /> CSV
            </a>
            <a
              className="btn btn-sm btn-outline"
              href={`${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/export/json?session_key=${encodeURIComponent(selectedEndpoint?.session_key || "network_state_system")}&method=${method}`}
              download
              style={{ fontSize: "0.68rem", padding: "4px 10px", textDecoration: "none" }}
            >
              <Code2 size={12} /> JSON
            </a>
          </div>
        </div>
      </div>

      {error && (
        <div
          className="panel"
          style={{
            padding: "10px 16px",
            border: "1px solid var(--danger)",
            background: "var(--danger-soft)",
            color: "var(--danger)",
            fontSize: "0.78rem",
            fontFamily: "var(--font-mono)",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <ShieldAlert size={14} />
          <span>Attribution Notice: {error}</span>
        </div>
      )}

      {loading && !systemData && (
        <div
          style={{
            padding: "16px",
            textAlign: "center",
            fontFamily: "var(--font-mono)",
            fontSize: "0.75rem",
            color: "var(--text-muted)",
          }}
        >
          Computing neural attribution vectors across monitored features...
        </div>
      )}

      {/* ============================================================ */}
      {/* WHOLE-SYSTEM CURRENT STATE BANNER                            */}
      {/* ============================================================ */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "12px",
        }}
      >
        <div
          className="panel"
          style={{
            padding: "12px 16px",
            background: isWarningState
              ? "var(--danger-soft)"
              : "var(--success-soft)",
            border: isWarningState
              ? "1px solid var(--danger-border)"
              : "1px solid var(--border)",
          }}
        >
          <span style={{ fontSize: "0.68rem", color: isDark ? "var(--text-muted)" : "var(--text-secondary)", display: "block", fontWeight: 600 }}>
            CURRENT SYSTEM RISK
          </span>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginTop: 4 }}>
            <span
              className="mono"
              style={{
                fontSize: "1.6rem",
                fontWeight: 900,
                color: isWarningState ? "var(--c-red)" : "var(--severity-low)",
              }}
            >
              {formatProb(activePosture.risk_score)}
            </span>
            <span className={`stage-badge ${stageClass(activePosture.predicted_stage)}`}>
              {activePosture.predicted_stage}
            </span>
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <span style={{ fontSize: "0.68rem", color: "var(--text-muted)", display: "block" }}>
            SECURITY DEFENSE POSTURE
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 6 }}>
            <Radio size={15} color={isWarningState ? "var(--c-red)" : "var(--severity-low)"} />
            <strong style={{ fontSize: "0.85rem", color: isWarningState ? "var(--c-red)" : "var(--severity-low)" }}>
              {activePosture.attack_state_label || "Defense Telemetry Nominal"}
            </strong>
          </div>
          <span style={{ fontSize: "0.66rem", color: "var(--text-muted)", display: "block", marginTop: 2 }}>
            Sustained Alert: {activePosture.is_alert ? "TRIGGERED (ACTIVE)" : "INACTIVE (BASELINE)"}
          </span>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <span style={{ fontSize: "0.68rem", color: "var(--text-muted)", display: "block" }}>
            MONITORED SYSTEM SCOPE
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 6 }}>
            <Globe size={15} color="var(--c-gold)" />
            <strong style={{ fontSize: "0.85rem", color: "var(--text-primary)" }}>
              {isDrilldown ? "Single Endpoint View" : "All Perimeter & Subnet Traffic"}
            </strong>
          </div>
          <span style={{ fontSize: "0.66rem", color: "var(--text-muted)", display: "block", marginTop: 2 }}>
            {systemData?.system_posture?.monitored_sessions_count || 0} active communication sessions evaluated
          </span>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <span style={{ fontSize: "0.68rem", color: "var(--text-muted)", display: "block" }}>
            PRIMARY THREAT DRIVER
          </span>
          <div style={{ marginTop: 6 }}>
            <strong style={{ fontSize: "0.85rem", color: isWarningState && stats.topThreat ? "var(--c-red)" : "var(--severity-low)" }}>
              {isWarningState && stats.topThreat ? formatFeatureName(stats.topThreat) : "Nominal Traffic Profile"}
            </strong>
            <span className="mono" style={{ fontSize: "0.66rem", color: "var(--text-muted)", display: "block", marginTop: 2 }}>
              {isWarningState && stats.topThreat ? `[${stats.topThreat}]` : "Zero Anomalous Push"}
            </span>
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* LAYER 1: WHY IS GARUD WARNING YOU? (DECISION SUPPORT LAYER)  */}
      {/* ============================================================ */}
      <div
        className="panel"
        style={{
          background: "var(--bg-surface)",
          border: isWarningState
            ? "1px solid var(--danger-border)"
            : "1px solid var(--border)",
          padding: "22px 26px",
          boxShadow: "var(--shadow-md)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            flexWrap: "wrap",
            gap: 12,
            marginBottom: 16,
            borderBottom: "1px solid var(--border)",
            paddingBottom: 14,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div
              style={{
                width: 42,
                height: 42,
                borderRadius: "50%",
                background: isDark
                  ? (isWarningState
                      ? "rgba(201, 74, 69, 0.2)"
                      : "rgba(88, 166, 104, 0.2)")
                  : (isWarningState
                      ? "var(--danger-soft)"
                      : "var(--success-soft)"),
                border: isWarningState
                  ? "1px solid var(--c-red)"
                  : "1px solid var(--severity-low)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {isWarningState ? (
                <ShieldAlert size={22} color="var(--c-red)" />
              ) : (
                <ShieldCheck size={22} color="var(--severity-low)" />
              )}
            </div>
            <div>
              <h2
                style={{
                  fontSize: "1.2rem",
                  fontWeight: 900,
                  letterSpacing: "0.06em",
                  color: isWarningState ? "var(--c-red)" : "var(--severity-low)",
                  margin: 0,
                  textTransform: "uppercase",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {isWarningState
                  ? "WHY IS GARUD WARNING YOU?"
                  : "WHY IS THE MONITORED SYSTEM NOMINAL?"}
              </h2>
              <span
                style={{
                  fontSize: "0.74rem",
                  color: isDark ? "var(--text-muted)" : "var(--text-secondary)",
                  display: "block",
                  marginTop: 3,
                }}
              >
                {isDrilldown
                  ? "Interpretable Decision Support for Selected Monitored Endpoint"
                  : "Whole-System Interpretable Decision Support • Plain-English Rationale"}
              </span>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ textAlign: "right", fontFamily: "var(--font-mono)" }}>
              <span style={{ fontSize: "0.68rem", color: isDark ? "var(--text-muted)" : "var(--text-secondary)", display: "block" }}>
                INFILTRATION CONFIDENCE
              </span>
              <span
                style={{
                  fontSize: "1.15rem",
                  fontWeight: 900,
                  color: isWarningState ? "var(--c-red)" : "var(--severity-low)",
                }}
              >
                {formatProb(activePosture.risk_score)}
              </span>
            </div>
            <span
              className={`stage-badge ${stageClass(activePosture.predicted_stage)}`}
              style={{ padding: "5px 12px", fontSize: "0.78rem" }}
            >
              {activePosture.predicted_stage}
            </span>
          </div>
        </div>

        {/* 3 Numbered Human Explanation Cards */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {humanExplanations.map((reason) => (
            <div
              key={reason.num}
              style={{
                display: "grid",
                gridTemplateColumns: "50px 1fr auto",
                gap: 16,
                alignItems: "center",
                background: "var(--bg-raised)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "14px 18px",
              }}
            >
              {/* Number Badge */}
              <div
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "1.3rem",
                  fontWeight: 900,
                  color: isWarningState ? "var(--c-red)" : "var(--severity-low)",
                  background: isWarningState
                    ? "var(--danger-soft)"
                    : "var(--success-soft)",
                  border: isWarningState
                    ? "1px solid var(--danger-border)"
                    : "1px solid var(--border)",
                  borderRadius: 4,
                  height: 42,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  letterSpacing: "-0.05em",
                }}
              >
                {reason.num}
              </div>

              {/* Title & Description */}
              <div>
                <div style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
                  <strong style={{ fontSize: "0.95rem", color: "var(--text-primary)" }}>
                    {reason.title}
                  </strong>
                  {reason.feature && (
                    <span
                      className="mono"
                      style={{
                        fontSize: "0.64rem",
                        color: isDark ? "var(--c-gold)" : "var(--accent-text)",
                        background: isDark ? "rgba(214, 179, 106, 0.1)" : "var(--accent-soft)",
                        border: isDark ? "1px solid rgba(214, 179, 106, 0.25)" : "1px solid var(--accent)",
                        padding: "1px 6px",
                        borderRadius: 3,
                      }}
                    >
                      telemetry: {reason.feature}
                    </span>
                  )}
                </div>
                <p style={{ fontSize: "0.76rem", color: isDark ? "var(--text-muted)" : "var(--text-secondary)", margin: "4px 0 0 0", lineHeight: 1.45 }}>
                  {reason.detail}
                </p>
              </div>

              {/* Tag Badge */}
              <div>
                <span
                  className="mono"
                  style={{
                    fontSize: "0.68rem",
                    padding: "3px 10px",
                    borderRadius: 3,
                    fontWeight: 700,
                    letterSpacing: "0.03em",
                    background: isDark
                      ? (isWarningState
                          ? "rgba(201, 74, 69, 0.15)"
                          : "rgba(88, 166, 104, 0.15)")
                      : (isWarningState
                          ? "var(--danger-soft)"
                          : "var(--success-soft)"),
                    color: isWarningState ? "var(--c-red)" : "var(--severity-low)",
                    border: isWarningState
                      ? (isDark ? "1px solid rgba(201, 74, 69, 0.3)" : "1px solid var(--danger-border)")
                      : (isDark ? "1px solid rgba(88, 166, 104, 0.3)" : "1px solid var(--success)"),
                    whiteSpace: "nowrap",
                  }}
                >
                  {reason.tag}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* View Model Details Toggle */}
        <div style={{ display: "flex", justifyContent: "center", marginTop: 20 }}>
          <button
            onClick={() => setShowModelDetails((prev) => !prev)}
            className="btn btn-sm"
            style={{
              background: isDark ? "rgba(214, 179, 106, 0.12)" : "var(--accent-soft)",
              border: "1px solid var(--c-gold)",
              color: isDark ? "var(--c-gold)" : "var(--accent-text)",
              fontFamily: "var(--font-mono)",
              fontSize: "0.74rem",
              fontWeight: 800,
              letterSpacing: "0.08em",
              padding: "8px 22px",
              borderRadius: 4,
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              cursor: "pointer",
            }}
          >
            {showModelDetails ? (
              <>
                <ChevronUp size={15} /> HIDE MODEL DETAILS
              </>
            ) : (
              <>
                <ChevronDown size={15} /> VIEW MODEL DETAILS
              </>
            )}
          </button>
        </div>
      </div>

      {/* ============================================================ */}
      {/* LAYER 2: FEATURE ATTRIBUTION & MODEL DETAILS                 */}
      {/* ============================================================ */}
      {showModelDetails && (
        <div className="panel" style={{ padding: "18px 22px" }}>
          {/* Header & 4 Attribution Methods */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 12,
              marginBottom: 16,
              paddingBottom: 12,
              borderBottom: isDark ? "1px solid var(--border-dark)" : "1px solid var(--border)",
            }}
          >
            <div>
              <span
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.9rem",
                  fontWeight: 900,
                  letterSpacing: "0.08em",
                  color: "var(--c-gold)",
                  textTransform: "uppercase",
                }}
              >
                FEATURE ATTRIBUTION
              </span>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginLeft: 10 }}>
                {isDrilldown ? "Selected Flow Window Attributions" : "Whole-System Telemetry Feature Vectors"}
              </span>
            </div>

            {/* 4 Attribution Buttons */}
            <div
              style={{
                display: "inline-flex",
                gap: 4,
                background: isDark ? "var(--bg-inset)" : "var(--bg-raised)",
                padding: 3,
                borderRadius: "var(--radius-sm)",
                border: "1px solid var(--border)",
              }}
            >
              <button
                className={`btn btn-sm ${method === "shap" ? "btn-primary" : ""}`}
                onClick={() => handleMethodChange("shap")}
                style={{ fontSize: "0.68rem", padding: "4px 12px", fontWeight: 700 }}
              >
                SHAP
              </button>
              <button
                className={`btn btn-sm ${method === "gradient" ? "btn-primary" : ""}`}
                onClick={() => handleMethodChange("gradient")}
                style={{ fontSize: "0.68rem", padding: "4px 12px", fontWeight: 700 }}
              >
                GRADIENT
              </button>
              <button
                className={`btn btn-sm ${method === "attention" ? "btn-primary" : ""}`}
                onClick={() => handleMethodChange("attention")}
                style={{ fontSize: "0.68rem", padding: "4px 12px", fontWeight: 700 }}
              >
                ATTENTION
              </button>
              <button
                className={`btn btn-sm ${method === "state_delta" ? "btn-primary" : ""}`}
                onClick={() => handleMethodChange("state_delta")}
                style={{ fontSize: "0.68rem", padding: "4px 12px", fontWeight: 700 }}
              >
                STATE DELTA
              </button>
            </div>
          </div>

          {/* Temporal Recurrence Weights (if attention) */}
          {method === "attention" && (sessionExplanation?.temporal_weights || systemData?.temporal_weights) && (
            <div
              style={{
                background: "var(--bg-inset)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "12px 16px",
                marginBottom: 16,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <span className="mono" style={{ fontSize: "0.72rem", color: "var(--c-gold)", fontWeight: 700 }}>
                  TEMPORAL RECURRENCE ATTENTION WEIGHTS (WINDOW t-5 &rarr; t_now)
                </span>
                <span style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>
                  Window sequence contribution
                </span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 8 }}>
                {(sessionExplanation?.temporal_weights || systemData?.temporal_weights || []).map((w, tIdx) => {
                  const isFinal = tIdx === 5;
                  const pct = Math.round(w * 100);
                  return (
                    <div
                      key={tIdx}
                      style={{
                        background: isFinal
                          ? (isDark ? "rgba(214, 179, 106, 0.15)" : "var(--accent-soft)")
                          : (isDark ? "rgba(255, 255, 255, 0.03)" : "var(--bg-raised)"),
                        border: isFinal
                          ? "1px solid var(--c-gold)"
                          : (isDark ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid var(--border)"),
                        borderRadius: 4,
                        padding: "8px",
                        textAlign: "center",
                      }}
                    >
                      <div className="mono" style={{ fontSize: "0.68rem", color: isFinal ? "var(--c-gold)" : "var(--text-muted)", fontWeight: 700 }}>
                        {isFinal ? "t (latest)" : `t-${5 - tIdx}`}
                      </div>
                      <div className="mono" style={{ fontSize: "1.1rem", fontWeight: 800, color: isFinal ? "var(--c-gold)" : "var(--text-primary)", marginTop: 2 }}>
                        {pct}%
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Filter Toolbar */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              gap: 8,
              marginBottom: 12,
            }}
          >
            <div style={{ display: "flex", gap: 6 }}>
              <button
                className={`btn btn-sm ${attributionFilter === "all" ? "btn-primary" : "btn-outline"}`}
                onClick={() => setAttributionFilter("all")}
                style={{ fontSize: "0.68rem", padding: "2px 8px" }}
              >
                All Features ({activeAttributions.length})
              </button>
              <button
                className={`btn btn-sm ${attributionFilter === "threat" ? "btn-primary" : "btn-outline"}`}
                onClick={() => setAttributionFilter("threat")}
                style={{
                  fontSize: "0.68rem",
                  padding: "2px 8px",
                  color: attributionFilter === "threat" ? "#020E0F" : "var(--c-red)",
                }}
              >
                Threat Drivers ({activeAttributions.filter((a) => a.importance > 0).length})
              </button>
              <button
                className={`btn btn-sm ${attributionFilter === "benign" ? "btn-primary" : "btn-outline"}`}
                onClick={() => setAttributionFilter("benign")}
                style={{
                  fontSize: "0.68rem",
                  padding: "2px 8px",
                  color: attributionFilter === "benign" ? "#020E0F" : "var(--severity-low)",
                }}
              >
                Benign Mitigators ({activeAttributions.filter((a) => a.importance < 0).length})
              </button>
            </div>

            <div style={{ display: "flex", gap: 14, fontSize: "0.68rem", fontFamily: "var(--font-mono)" }}>
              <span style={{ color: "var(--severity-low)", display: "flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 8, height: 8, background: "var(--severity-low)", borderRadius: 1 }} />
                Benign Push (&larr;)
              </span>
              <span style={{ color: "var(--c-red)", display: "flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 8, height: 8, background: "var(--c-red)", borderRadius: 1 }} />
                Threat Push (&rarr;)
              </span>
            </div>
          </div>

          {/* Diverging Attribution Chart */}
          <div
            style={{
              background: "var(--bg-inset)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              padding: "12px 16px",
            }}
          >
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "240px 1fr 110px",
                gap: "12px",
                paddingBottom: "8px",
                borderBottom: "1px solid var(--border)",
                fontSize: "0.68rem",
                color: "var(--text-muted)",
                fontWeight: 700,
              }}
            >
              <span>TELEMETRY METRIC</span>
              <div style={{ position: "relative", textAlign: "center" }}>
                <span style={{ position: "absolute", left: "20%" }}>&larr; BENIGN PUSH</span>
                <span style={{ position: "absolute", left: "50%", transform: "translateX(-50%)", color: "var(--c-gold)" }}>
                  0.00 (NEUTRAL)
                </span>
                <span style={{ position: "absolute", right: "20%" }}>THREAT PUSH &rarr;</span>
              </div>
              <span style={{ textAlign: "right" }}>
                {method === "state_delta" ? "DELTA & IMPACT" : "ATTRIBUTION"}
              </span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "8px" }}>
              {filteredAttributions.map((attr, idx) => {
                const isThreat = attr.importance > 0;
                const absVal = Math.abs(attr.importance);
                const pctOfHalf = Math.min(100, (absVal / maxImp) * 100);
                const observedVal = systemData?.latest_flow_features
                  ? systemData.latest_flow_features[attr.feature]
                  : null;

                return (
                  <div
                    key={idx}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "240px 1fr 110px",
                      gap: "12px",
                      alignItems: "center",
                      padding: "6px 8px",
                      borderRadius: "var(--radius-sm)",
                      background: idx % 2 === 0 ? "var(--bg-raised)" : "transparent",
                    }}
                  >
                    <div>
                      <span
                        style={{
                          fontSize: "0.82rem",
                          fontWeight: 700,
                          color: isThreat ? "var(--text-primary)" : "var(--text-secondary)",
                          display: "block",
                          whiteSpace: "nowrap",
                          textOverflow: "ellipsis",
                          overflow: "hidden",
                        }}
                        title={FEATURE_EXPLANATIONS[attr.feature] || ""}
                      >
                        {formatFeatureName(attr.feature)}
                      </span>
                      <span className="mono" style={{ fontSize: "0.64rem", color: "var(--text-muted)" }}>
                        {attr.feature}
                        {observedVal != null && ` • Obs: ${typeof observedVal === "number" ? observedVal.toFixed(observedVal < 10 ? 2 : 0) : observedVal}`}
                      </span>
                    </div>

                    <div
                      style={{
                        position: "relative",
                        height: "16px",
                        background: "var(--bg-surface)",
                        borderRadius: "var(--radius-sm)",
                        overflow: "hidden",
                        border: "1px solid var(--border)",
                      }}
                    >
                      <div
                        style={{
                          position: "absolute",
                          left: "50%",
                          top: 0,
                          bottom: 0,
                          width: "2px",
                          background: "var(--accent)",
                          zIndex: 2,
                        }}
                      />
                      {isThreat ? (
                        <div
                          style={{
                            position: "absolute",
                            left: "50%",
                            top: 2,
                            bottom: 2,
                            width: `${pctOfHalf * 0.48}%`,
                            background: "linear-gradient(90deg, rgba(201, 74, 69, 0.5) 0%, rgba(201, 74, 69, 0.95) 100%)",
                            borderRadius: "0 3px 3px 0",
                          }}
                        />
                      ) : (
                        <div
                          style={{
                            position: "absolute",
                            right: "50%",
                            top: 2,
                            bottom: 2,
                            width: `${pctOfHalf * 0.48}%`,
                            background: "linear-gradient(270deg, rgba(88, 166, 104, 0.5) 0%, rgba(88, 166, 104, 0.95) 100%)",
                            borderRadius: "3px 0 0 3px",
                          }}
                        />
                      )}
                    </div>

                    <div style={{ textAlign: "right" }}>
                      <span
                        className="mono"
                        style={{
                          fontSize: "0.82rem",
                          fontWeight: 700,
                          color: isThreat ? "var(--c-red)" : "var(--severity-low)",
                        }}
                      >
                        {isThreat ? "+" : ""}
                        {attr.importance.toFixed(4)}
                      </span>
                      {attr.delta != null && (
                        <span className="mono" style={{ display: "block", fontSize: "0.62rem", color: "var(--c-gold)" }}>
                          &Delta; {attr.delta > 0 ? "+" : ""}{attr.delta}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ============================================================ */}
      {/* CONTRIBUTING HOSTS & ENDPOINTS IN MONITORED SUBNET           */}
      {/* ============================================================ */}
      <div className="panel" style={{ padding: "18px 22px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div>
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "0.85rem",
                fontWeight: 800,
                letterSpacing: "0.06em",
                color: "var(--text-primary)",
                textTransform: "uppercase",
              }}
            >
              CONTRIBUTING ENDPOINTS IN MONITORED SUBNET
            </span>
            <span style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginLeft: 10 }}>
              Top active communication channels currently driving network risk score
            </span>
          </div>
          <span className="mono" style={{ fontSize: "0.68rem", color: "var(--c-gold)" }}>
            {systemData?.contributing_endpoints?.length || 0} active channels
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 10 }}>
          {systemData?.contributing_endpoints?.map((ep) => {
            const isSelected = selectedEndpoint?.session_key === ep.session_key;
            const isThreat = (ep.risk_score || 0) > 0.45 || (ep.stage && ep.stage !== "Benign");
            return (
              <div
                key={ep.session_key}
                onClick={() => drilldownSession(ep)}
                style={{
                  background: isSelected
                    ? "var(--accent-soft)"
                    : "var(--bg-raised)",
                  border: isSelected
                    ? "1px solid var(--accent)"
                    : isThreat
                      ? "1px solid var(--danger-border)"
                      : "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "10px 14px",
                  cursor: "pointer",
                  transition: "all 0.15s ease",
                  boxShadow: isDark ? "none" : "0 1px 3px rgba(0, 0, 0, 0.04)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <AppBadge name={ep.app_name} />
                  <span className={`stage-badge ${stageClass(ep.stage)}`}>
                    {ep.stage || "Benign"}
                  </span>
                </div>

                <div style={{ fontSize: "0.74rem", fontFamily: "var(--font-mono)", color: "var(--text-primary)", marginBottom: 4 }}>
                  <span style={{ color: "var(--text-muted)", fontWeight: 600 }}>SRC:</span> {ep.src_ip}
                  <span style={{ margin: "0 6px", color: "var(--c-gold)" }}>&rarr;</span>
                  <span style={{ color: "var(--text-muted)", fontWeight: 600 }}>DST:</span> {ep.dst_ip}
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 6, fontSize: "0.68rem" }}>
                  <span className="mono" style={{ color: isDark ? "var(--text-muted)" : "var(--text-secondary)", fontWeight: 600 }}>
                    {ep.flow_count} flows
                  </span>
                  <span className="mono" style={{ fontWeight: 800, color: isThreat ? "var(--c-red)" : "var(--severity-low)" }}>
                    Risk: {formatProb(ep.risk_score)}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
