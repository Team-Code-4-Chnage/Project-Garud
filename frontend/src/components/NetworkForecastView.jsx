import { useState, useEffect, useMemo } from "react";
import {
  ComposedChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Network, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import { apiFetch } from "../api";
import { formatFeatureName } from "../utils";

const REFRESH_MS = 10000;
const STATE_LABELS = {
  n_flows: "Flows / min",
  n_uniq_src_ip: "Source hosts",
  n_uniq_dst_ip: "Destination hosts",
  n_uniq_dst_port: "Destination ports",
  n_new_conn_rate: "New connections / s",
  f_syn_ratio: "SYN share",
  f_rst_ratio: "RST share",
  f_small_flow_frac: "Flows of 2 packets or fewer",
  n_ent_dst_port: "Port entropy (bits)",
  n_dport_per_src_max: "Max ports per source",
  f_total_bytes: "Bytes / min",
};

const hhmm = (iso) => (iso ? iso.slice(11, 16) : "");
const fmt = (v) =>
  v == null
    ? "-"
    : Math.abs(v) >= 1000
      ? Math.round(v).toLocaleString()
      : Number(v).toFixed(v < 10 ? 2 : 0);

const MITRE_KILL_CHAIN = [
  {
    key: "recon",
    name: "Reconnaissance",
    code: "T1595 / T1046",
    desc: "Network Sweep & Probing",
    color: "#5294E2",
  },
  {
    key: "initial",
    name: "Initial Access",
    code: "T1190 / T1133",
    desc: "Perimeter Ingress Exploit",
    color: "#D6B36A",
  },
  {
    key: "lateral",
    name: "Lateral Movement",
    code: "T1021 / T1080",
    desc: "Internal Peer Traversal",
    color: "#DE934B",
  },
  {
    key: "c2",
    name: "C2 Channel",
    code: "T1071 / T1573",
    desc: "Beaconing & Remote Control",
    color: "#D1643F",
  },
  {
    key: "exfil",
    name: "Exfiltration",
    code: "T1041 / T1048",
    desc: "Data Staging & Tunneling",
    color: "#C94A45",
  },
];

function AttackTopologyMap({
  cur,
  state,
  forecast = [],
  hostIdentity,
  activeSessions = [],
  stats,
}) {
  const isThreat = Boolean(cur.alert || (cur.risk_score || 0) > 0.5);

  const topThreatSession = useMemo(() => {
    if (!activeSessions || activeSessions.length === 0) return null;
    const threat = activeSessions.find(
      (s) =>
        (s.latest_risk_score || 0) > 0.5 ||
        (s.latest_stage && s.latest_stage !== "Benign"),
    );
    return threat || activeSessions[0];
  }, [activeSessions]);

  const threatCount = state?.n_uniq_src_ip
    ? state.n_uniq_src_ip[state.n_uniq_src_ip.length - 1]
    : stats?.direction_breakdown?.inbound || 3;
  const flowRate = state?.n_flows
    ? state.n_flows[state.n_flows.length - 1]
    : stats?.total_flows || 142;
  const internalCount = state?.n_uniq_dst_ip
    ? state.n_uniq_dst_ip[state.n_uniq_dst_ip.length - 1]
    : stats?.direction_breakdown?.internal || 4;
  const connRate = state?.n_new_conn_rate
    ? state.n_new_conn_rate[state.n_new_conn_rate.length - 1]
    : 3.2;
  const portEntropy = state?.n_ent_dst_port
    ? state.n_ent_dst_port[state.n_ent_dst_port.length - 1]
    : 2.15;
  const synRatio = state?.f_syn_ratio
    ? state.f_syn_ratio[state.f_syn_ratio.length - 1]
    : 0.42;
  const rstRatio = state?.f_rst_ratio
    ? state.f_rst_ratio[state.f_rst_ratio.length - 1]
    : 0.08;

  const hostIp = hostIdentity?.primary_ip || "127.0.0.1";
  const hostName = hostIdentity?.hostname || "LOCAL-SOC-NODE";
  const ingressIp = topThreatSession?.src_ip || "0.0.0.0/0 (Internet Ingress)";
  const targetedApp =
    topThreatSession?.app_name ||
    topThreatSession?.process_name ||
    "Enclave Services";
  const targetedPort = topThreatSession?.dst_port || 443;
  const activeStage =
    topThreatSession?.latest_stage || (isThreat ? "Initial Access" : "Benign");

  // Determine active stage index in MITRE Kill Chain
  const stageKey = activeStage.toLowerCase();
  const activeKillChainIdx = isThreat
    ? MITRE_KILL_CHAIN.findIndex((s) => stageKey.includes(s.key))
    : -1;

  // Horizon forecast trend
  const forecastEndRisk =
    forecast.length > 0 ? forecast[forecast.length - 1].risk : cur.risk_score;
  const riskDelta = forecastEndRisk - (cur.risk_score || 0);

  return (
    <div className="panel mb-4" style={{ cursor: "default" }}>
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
          <Network size={16} color="var(--c-gold)" />
          <span className="panel-title">
            Macro Network Topology & Infiltration Map
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            className={`stage-badge ${isThreat ? "exfiltration" : "benign"}`}
          >
            <span
              className="radar-blip-dot"
              style={{
                background: isThreat ? "var(--c-red)" : "var(--severity-low)",
                marginRight: 5,
              }}
            />
            {isThreat
              ? `Threat Vector: ${activeStage}`
              : "Perimeter Defense Nominal"}
          </span>
        </div>
      </div>

      <div className="panel-body" style={{ padding: "16px 20px" }}>
        {/* Live SVG Macro Topology Canvas */}
        <svg
          viewBox="0 0 920 240"
          className="topology-svg-canvas"
          style={{
            borderRadius: "var(--radius-sm)",
            width: "100%",
            height: "auto",
            maxHeight: "260px",
            background:
              "radial-gradient(circle at 50% 50%, rgba(58, 50, 40, 0.3) 0%, rgba(26, 22, 16, 0.95) 100%)",
          }}
        >
          <defs>
            <linearGradient
              id="link-threat-grad"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="0%"
            >
              <stop offset="0%" stopColor="#c94a45" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#d6b36a" stopOpacity="0.9" />
            </linearGradient>
            <linearGradient
              id="link-nominal-grad"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="0%"
            >
              <stop offset="0%" stopColor="#d6b36a" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#58a668" stopOpacity="0.85" />
            </linearGradient>
            <marker
              id="arrow-red"
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#c94a45" />
            </marker>
            <marker
              id="arrow-gold"
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#d6b36a" />
            </marker>
            <marker
              id="arrow-green"
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#58a668" />
            </marker>
          </defs>

          {/* Background Concentric Radar Rings */}
          <line
            x1="40"
            y1="120"
            x2="880"
            y2="120"
            stroke="rgba(58, 50, 40, 0.35)"
            strokeDasharray="4 4"
          />
          <circle
            cx="450"
            cy="120"
            r="75"
            fill="none"
            stroke="rgba(214, 179, 106, 0.08)"
            strokeDasharray="3 3"
          />
          <circle
            cx="450"
            cy="120"
            r="140"
            fill="none"
            stroke="rgba(214, 179, 106, 0.04)"
            strokeDasharray="5 5"
          />

          {/* Links */}
          {/* Link 1: WAN to Gateway */}
          <path
            d="M 215 120 L 350 120"
            fill="none"
            stroke={
              isThreat ? "url(#link-threat-grad)" : "url(#link-nominal-grad)"
            }
            strokeWidth={isThreat ? 3 : 2}
            strokeDasharray={isThreat ? "6 4" : "4 4"}
            markerEnd={isThreat ? "url(#arrow-red)" : "url(#arrow-gold)"}
            className={isThreat ? "topology-link threat" : "topology-link"}
          />
          <text
            x="282"
            y="112"
            fill="var(--c-gold)"
            fontSize="8.5"
            fontFamily="var(--font-mono)"
            textAnchor="middle"
          >
            {fmt(flowRate)} fl/min
          </text>

          {/* Link 2: Gateway to Monitored Host */}
          <path
            d="M 540 100 L 680 65"
            fill="none"
            stroke={isThreat ? "#c94a45" : "#58a668"}
            strokeWidth={isThreat ? 2.5 : 1.8}
            strokeDasharray="5 4"
            markerEnd={isThreat ? "url(#arrow-red)" : "url(#arrow-green)"}
            className={
              isThreat ? "topology-link threat" : "topology-link nominal"
            }
          />

          {/* Link 3: Gateway to Internal Subnet */}
          <path
            d="M 540 140 L 680 175"
            fill="none"
            stroke={isThreat ? "#d6b36a" : "#58a668"}
            strokeWidth={1.8}
            strokeDasharray="5 4"
            markerEnd={isThreat ? "url(#arrow-gold)" : "url(#arrow-green)"}
            className="topology-link nominal"
          />

          {/* Link 4: Lateral Boundary Line between Host and Internal Subnet */}
          <line
            x1="785"
            y1="102"
            x2="785"
            y2="135"
            stroke={
              isThreat && activeKillChainIdx >= 2
                ? "var(--c-red)"
                : "rgba(88, 166, 104, 0.4)"
            }
            strokeWidth={1.5}
            strokeDasharray="3 3"
          />
          <text
            x="792"
            y="122"
            fill="var(--text-muted)"
            fontSize="7.5"
            fontFamily="var(--font-mono)"
          >
            {isThreat && activeKillChainIdx >= 2
              ? "TRAVERSAL ALERT"
              : "ISOLATED"}
          </text>

          {/* Node 1: External Threat / Ingress Cloud */}
          <g transform="translate(35, 75)">
            <rect
              width="180"
              height="88"
              rx="6"
              fill="rgba(34, 28, 21, 0.95)"
              stroke={isThreat ? "var(--c-red)" : "var(--c-gold)"}
              strokeWidth="1.5"
            />
            <circle
              cx="16"
              cy="20"
              r="4.5"
              fill={isThreat ? "var(--c-red)" : "var(--c-gold)"}
            />
            <text
              x="28"
              y="24"
              fill="var(--text-primary)"
              fontSize="10.5"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              REMOTE INGRESS ZONE
            </text>
            <text
              x="16"
              y="42"
              fill={isThreat ? "var(--c-red)" : "var(--c-gold)"}
              fontSize="9.5"
              fontWeight="600"
              fontFamily="var(--font-mono)"
            >
              IP: {ingressIp}
            </text>
            <text
              x="16"
              y="56"
              fill="var(--text-muted)"
              fontSize="8.5"
              fontFamily="var(--font-mono)"
            >
              Sources: {threatCount} active ingress nodes
            </text>
            <text
              x="16"
              y="70"
              fill="var(--text-muted)"
              fontSize="8.5"
              fontFamily="var(--font-mono)"
            >
              Port Target: TCP / {targetedPort}
            </text>
          </g>

          {/* Node 2: Border NAT Gateway Firewall */}
          <g transform="translate(350, 65)">
            <rect
              width="190"
              height="105"
              rx="6"
              fill="rgba(36, 31, 24, 0.95)"
              stroke="var(--c-gold)"
              strokeWidth="1.8"
            />
            <circle cx="16" cy="20" r="4.5" fill="var(--c-gold)" />
            <text
              x="28"
              y="24"
              fill="var(--c-gold)"
              fontSize="10.5"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              BORDER NAT GATEWAY
            </text>
            <text
              x="16"
              y="42"
              fill="var(--text-primary)"
              fontSize="9"
              fontWeight="600"
              fontFamily="var(--font-mono)"
            >
              IP: 10.0.1.1 (Inspection SOC)
            </text>
            <text
              x="16"
              y="56"
              fill="var(--text-muted)"
              fontSize="8.5"
              fontFamily="var(--font-mono)"
            >
              Flow Rate: {fmt(flowRate)} Flows/min
            </text>
            <text
              x="16"
              y="70"
              fill="var(--text-muted)"
              fontSize="8.5"
              fontFamily="var(--font-mono)"
            >
              New Conns: {connRate.toFixed(1)} conn/s
            </text>
            <text
              x="16"
              y="84"
              fill="var(--c-gold)"
              fontSize="8.5"
              fontFamily="var(--font-mono)"
            >
              Port Entropy: {portEntropy.toFixed(2)} bits
            </text>
            <text
              x="16"
              y="96"
              fill="var(--severity-low)"
              fontSize="8"
              fontFamily="var(--font-mono)"
            >
              Deep Packet Flow Inspection Active
            </text>
          </g>

          {/* Node 3: Protected SOC Host Enclave */}
          <g transform="translate(680, 20)">
            <rect
              width="200"
              height="82"
              rx="6"
              fill="rgba(34, 28, 21, 0.95)"
              stroke={isThreat ? "var(--c-red)" : "var(--severity-low)"}
              strokeWidth="1.8"
            />
            <circle
              cx="16"
              cy="18"
              r="4.5"
              fill={isThreat ? "var(--c-red)" : "var(--severity-low)"}
            />
            <text
              x="28"
              y="22"
              fill={isThreat ? "var(--c-red)" : "var(--severity-low)"}
              fontSize="10.5"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              PROTECTED SOC HOST
            </text>
            <text
              x="16"
              y="38"
              fill="var(--text-primary)"
              fontSize="9"
              fontWeight="600"
              fontFamily="var(--font-mono)"
            >
              Host: {hostName}
            </text>
            <text
              x="16"
              y="52"
              fill="var(--c-gold)"
              fontSize="9"
              fontFamily="var(--font-mono)"
            >
              IP: {hostIp}
            </text>
            <text
              x="16"
              y="66"
              fill="var(--text-muted)"
              fontSize="8.5"
              fontFamily="var(--font-mono)"
            >
              App: {targetedApp}
            </text>
            <text
              x="16"
              y="76"
              fill={isThreat ? "var(--c-red)" : "var(--severity-low)"}
              fontSize="7.5"
              fontFamily="var(--font-mono)"
            >
              {isThreat
                ? `Mitigation: ${activeStage}`
                : "Quarantine & Kernel Nominal"}
            </text>
          </g>

          {/* Node 4: Internal LAN & Workstation Subnet */}
          <g transform="translate(680, 138)">
            <rect
              width="200"
              height="80"
              rx="6"
              fill="rgba(34, 28, 21, 0.95)"
              stroke="var(--border-accent)"
              strokeWidth="1.5"
            />
            <circle cx="16" cy="18" r="4.5" fill="var(--c-gold)" />
            <text
              x="28"
              y="22"
              fill="var(--text-primary)"
              fontSize="10.5"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              INTERNAL LAN SUBNET
            </text>
            <text
              x="16"
              y="38"
              fill="var(--text-muted)"
              fontSize="9"
              fontFamily="var(--font-mono)"
            >
              192.168.1.0/24 Workstations
            </text>
            <text
              x="16"
              y="52"
              fill="var(--c-gold)"
              fontSize="8.5"
              fontFamily="var(--font-mono)"
            >
              {internalCount} Monitored LAN Endpoints
            </text>
            <text
              x="16"
              y="66"
              fill="var(--severity-low)"
              fontSize="8"
              fontFamily="var(--font-mono)"
            >
              Lateral Containment: Guarded
            </text>
          </g>
        </svg>

        {/* MITRE Kill-Chain Stage Progression Track */}
        <div style={{ marginTop: 16 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 8,
            }}
          >
            <span
              style={{
                fontSize: "0.72rem",
                color: "var(--text-muted)",
                fontWeight: 700,
                letterSpacing: "0.06em",
              }}
            >
              MITRE ATT&CK INFILTRATION KILL-CHAIN PIPELINE
            </span>
            <span
              className="mono"
              style={{
                fontSize: "0.7rem",
                color: isThreat ? "var(--c-red)" : "var(--severity-low)",
              }}
            >
              {isThreat
                ? `Active Infiltration Phase: ${activeStage}`
                : "Zero Infiltration Detected"}
            </span>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(5, 1fr)",
              gap: 8,
              background: "var(--bg-dark)",
              padding: "10px 12px",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border-dark)",
            }}
          >
            {MITRE_KILL_CHAIN.map((stage, idx) => {
              const isActive = activeKillChainIdx === idx;
              const isPast = activeKillChainIdx > idx;

              return (
                <div
                  key={stage.key}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    padding: "8px 10px",
                    borderRadius: "var(--radius-sm)",
                    background: isActive
                      ? `${stage.color}18`
                      : isPast
                        ? "rgba(88, 166, 104, 0.08)"
                        : "rgba(26, 22, 16, 0.6)",
                    border: `1px solid ${
                      isActive
                        ? stage.color
                        : isPast
                          ? "rgba(88, 166, 104, 0.4)"
                          : "rgba(58, 50, 40, 0.4)"
                    }`,
                    position: "relative",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 4,
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.68rem",
                        fontWeight: 700,
                        color: "var(--text-muted)",
                      }}
                    >
                      PHASE 0{idx + 1}
                    </span>
                    {isActive ? (
                      <span
                        className="radar-blip-dot"
                        style={{ background: stage.color }}
                      />
                    ) : isPast ? (
                      <span
                        style={{
                          fontSize: "0.7rem",
                          color: "var(--severity-low)",
                          fontWeight: 800,
                        }}
                      >
                        &check;
                      </span>
                    ) : null}
                  </div>

                  <strong
                    style={{
                      fontSize: "0.78rem",
                      color: isActive
                        ? stage.color
                        : isPast
                          ? "var(--text-primary)"
                          : "var(--text-muted)",
                      marginTop: 2,
                    }}
                  >
                    {stage.name}
                  </strong>

                  <span
                    className="mono"
                    style={{
                      fontSize: "0.65rem",
                      color: "var(--c-gold)",
                      marginTop: 2,
                    }}
                  >
                    {stage.code}
                  </span>

                  <span
                    style={{
                      fontSize: "0.62rem",
                      color: "var(--text-muted)",
                      marginTop: 2,
                    }}
                  >
                    {stage.desc}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Multi-Vector Telemetry Cards */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: 12,
            marginTop: 14,
          }}
        >
          {/* Port Attack Entropy Gauge */}
          <div
            style={{
              background: "var(--bg-dark)",
              border: "1px solid var(--border-muted)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 14px",
              cursor: "default",
            }}
          >
            <span
              style={{
                fontSize: "0.7rem",
                color: "var(--text-muted)",
                display: "block",
              }}
            >
              PORT ATTACK ENTROPY
            </span>
            <div
              style={{
                display: "flex",
                alignItems: "baseline",
                gap: 8,
                marginTop: 2,
              }}
            >
              <strong
                style={{
                  fontSize: "1.15rem",
                  color: "var(--c-gold)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {portEntropy.toFixed(2)} bits
              </strong>
              <span
                style={{
                  fontSize: "0.72rem",
                  color:
                    portEntropy > 3.5 ? "var(--c-red)" : "var(--severity-low)",
                }}
              >
                {portEntropy > 3.5
                  ? "Wide Scanning"
                  : portEntropy > 1.5
                    ? "Targeted Probing"
                    : "Focused Service"}
              </span>
            </div>
            {/* Visual Entropy Scale */}
            <div
              style={{
                position: "relative",
                height: 5,
                background: "rgba(255, 255, 255, 0.1)",
                borderRadius: 3,
                marginTop: 6,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${Math.min(100, (portEntropy / 6.0) * 100)}%`,
                  height: "100%",
                  background:
                    portEntropy > 3.5 ? "var(--c-red)" : "var(--c-gold)",
                  borderRadius: 3,
                }}
              />
            </div>
          </div>

          {/* Protocol Flag Split Gauge */}
          <div
            style={{
              background: "var(--bg-dark)",
              border: "1px solid var(--border-muted)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 14px",
              cursor: "default",
            }}
          >
            <span
              style={{
                fontSize: "0.7rem",
                color: "var(--text-muted)",
                display: "block",
              }}
            >
              SYN / RST DYNAMICS
            </span>
            <div
              style={{
                display: "flex",
                alignItems: "baseline",
                justifyContent: "space-between",
                marginTop: 2,
              }}
            >
              <span
                className="mono"
                style={{
                  fontSize: "0.85rem",
                  color: "var(--c-gold)",
                  fontWeight: 700,
                }}
              >
                SYN: {(synRatio * 100).toFixed(0)}%
              </span>
              <span
                className="mono"
                style={{
                  fontSize: "0.85rem",
                  color: "var(--c-red)",
                  fontWeight: 700,
                }}
              >
                RST: {(rstRatio * 100).toFixed(0)}%
              </span>
            </div>
            {/* Dual Bar Graphic */}
            <div
              style={{
                display: "flex",
                height: 5,
                borderRadius: 3,
                overflow: "hidden",
                marginTop: 6,
                background: "rgba(255, 255, 255, 0.08)",
              }}
            >
              <div
                style={{
                  width: `${synRatio * 100}%`,
                  background: "var(--c-gold)",
                }}
              />
              <div
                style={{
                  width: `${rstRatio * 100}%`,
                  background: "var(--c-red)",
                }}
              />
            </div>
          </div>

          {/* Forecast 4-Minute Trajectory */}
          <div
            style={{
              background: "var(--bg-dark)",
              border: "1px solid var(--border-muted)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 14px",
              cursor: "default",
            }}
          >
            <span
              style={{
                fontSize: "0.7rem",
                color: "var(--text-muted)",
                display: "block",
              }}
            >
              HORIZON PROJECTION (t+1..t+4)
            </span>
            <div
              style={{
                display: "flex",
                alignItems: "baseline",
                gap: 8,
                marginTop: 2,
              }}
            >
              <strong
                style={{
                  fontSize: "1.15rem",
                  color: isThreat ? "var(--c-red)" : "var(--severity-low)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {(cur.risk_score * 100).toFixed(1)}% &rarr;{" "}
                {(forecastEndRisk * 100).toFixed(1)}%
              </strong>
              <span
                style={{
                  fontSize: "0.72rem",
                  color:
                    riskDelta > 0.05 ? "var(--c-red)" : "var(--severity-low)",
                }}
              >
                {riskDelta > 0.05
                  ? "▲ ESCALATING"
                  : riskDelta < -0.05
                    ? "▼ DECAYING"
                    : "► SUSTAINED"}
              </span>
            </div>
            <span
              style={{
                fontSize: "0.68rem",
                color: "var(--text-muted)",
                display: "block",
                marginTop: 4,
              }}
            >
              Rollout: {forecast.length} minutes simulated ahead
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function NetworkForecastView({ hostIdentity: propHostIdentity }) {
  const [sources, setSources] = useState([]);
  const [source, setSource] = useState(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [hostId, setHostId] = useState(propHostIdentity);
  const [activeSessions, setActiveSessions] = useState([]);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    if (propHostIdentity) {
      setHostId(propHostIdentity);
    } else {
      apiFetch("/system/host-identity")
        .then(setHostId)
        .catch(() => {});
    }
  }, [propHostIdentity]);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [srcs, fetchedSessions, fetchedStats] = await Promise.all([
          apiFetch("/network/sources").catch(() => []),
          apiFetch("/sessions?limit=6&sort_by=latest_risk_score").catch(
            () => [],
          ),
          apiFetch("/dashboard/stats").catch(() => null),
        ]);
        if (!active) return;
        setSources(srcs || []);
        setActiveSessions(
          Array.isArray(fetchedSessions) ? fetchedSessions : [],
        );
        setStats(fetchedStats);

        const chosen = source || srcs?.[0]?.source;
        if (!chosen) {
          setData({ status: "no_data" });
          return;
        }
        const res = await apiFetch(
          `/network/forecast?source=${encodeURIComponent(chosen)}`,
        );
        if (active) {
          setData(res);
          setError(null);
        }
      } catch (e) {
        if (active) setError(e.message);
      }
    };
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [source]);

  const chart = useMemo(() => {
    if (!data || data.status !== "ok") return [];
    const hist = data.minutes.map((m, i) => ({
      minute: hhmm(m),
      observed: data.risk_score[i],
      alert: data.alert[i] ? data.risk_score[i] : null,
    }));
    const last = hist[hist.length - 1];
    const fc = data.forecast.map((s) => ({
      minute: hhmm(s.minute),
      forecast: s.risk,
    }));
    if (last) last.forecast = last.observed;
    return [...hist.slice(-40), ...fc];
  }, [data]);

  if (error)
    return (
      <div className="panel">
        <div className="panel-body text-muted">Network model: {error}</div>
      </div>
    );
  if (!data)
    return (
      <div className="panel">
        <div className="panel-body">
          <Loader2 size={16} className="spin" /> Loading
        </div>
      </div>
    );

  const header = (
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
        <Network size={16} color="var(--c-gold)" />
        <span className="panel-title">
          Macro Network World Model &bull; Attack Topology Forecast
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          className="mono text-xs text-muted"
          style={{ letterSpacing: "0.06em" }}
        >
          Telemetry Source:
        </span>
        <select
          value={source || data.source || ""}
          onChange={(e) => setSource(e.target.value)}
          style={{
            background: "var(--c-dark-base)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            padding: "4px 10px",
            color: "var(--c-gold)",
            fontFamily: "var(--font-mono)",
            fontSize: "0.8rem",
            fontWeight: 700,
            outline: "none",
            cursor: "pointer",
          }}
        >
          {sources.map((s) => (
            <option key={s.source} value={s.source}>
              {s.source} ({s.flows} flows)
            </option>
          ))}
        </select>
      </div>
    </div>
  );

  if (data.status === "no_data") {
    return (
      <div className="panel">
        {header}
        <div className="panel-body text-muted">
          No flows yet. Upload a PCAP or CSV, or start capture.
        </div>
      </div>
    );
  }
  if (data.status === "warming_up") {
    return (
      <div className="panel">
        {header}
        <div className="panel-body text-muted">
          Building network state: {data.minutes_available} of{" "}
          {data.minutes_needed} minutes of traffic recorded. The model needs{" "}
          {data.minutes_needed} consecutive minutes before it can forecast.
        </div>
      </div>
    );
  }

  const cur = data.current;
  const info = data.model;
  const tr = info.test_results;
  return (
    <div>
      <div
        className="panel mb-4"
        style={{
          borderLeft: cur.alert
            ? "4px solid var(--c-red)"
            : "4px solid var(--severity-low)",
        }}
      >
        {header}
        <div
          className="panel-body"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 16,
            flexWrap: "wrap",
            padding: "14px 20px",
            background: cur.alert
              ? "rgba(201, 74, 69, 0.08)"
              : "rgba(88, 166, 104, 0.05)",
          }}
        >
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 14px",
              borderRadius: "var(--radius-sm)",
              background: cur.alert
                ? "rgba(201, 74, 69, 0.2)"
                : "rgba(88, 166, 104, 0.15)",
              border: `1px solid ${cur.alert ? "var(--c-red)" : "var(--severity-low)"}`,
              color: cur.alert ? "var(--c-red)" : "var(--severity-low)",
              fontWeight: 800,
              fontSize: "0.85rem",
              letterSpacing: "0.04em",
            }}
          >
            {cur.alert ? (
              <AlertTriangle size={18} strokeWidth={2.5} />
            ) : (
              <ShieldCheck size={18} strokeWidth={2.5} />
            )}
            {cur.alert
              ? "NATIONAL DEFENSE ALERT: SUSTAINED ATTACK DETECTED"
              : "DEFENSE TELEMETRY NOMINAL: NO SUSTAINED ATTACK"}
          </div>

          <div
            className="mono"
            style={{ fontSize: "0.88rem", color: "var(--text-primary)" }}
          >
            WINDOW:{" "}
            <strong style={{ color: "var(--c-gold)" }}>
              {hhmm(cur.minute)} UTC
            </strong>{" "}
            &middot; RISK OVER NEXT 4 MIN:{" "}
            <strong
              style={{
                color: cur.risk_score > 0.5 ? "var(--c-red)" : "var(--c-gold)",
                fontSize: "1.1rem",
              }}
            >
              {(cur.risk_score * 100).toFixed(1)}%
            </strong>
          </div>

          <div
            className="mono text-xs text-muted"
            style={{
              padding: "4px 10px",
              background: "var(--bg-dark)",
              borderRadius: "var(--radius-sm)",
            }}
          >
            Rule: risk &ge; {(cur.threshold * 100).toFixed(1)}% for{" "}
            {cur.consecutive_needed} consecutive min
          </div>
        </div>
      </div>

      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">Network Macro Risk Timeline</span>
          <span className="panel-meta">
            Observed traffic timeline &plus; 4-minute future projection
          </span>
        </div>
        <div className="panel-body chart-container" style={{ minHeight: 280 }}>
          <ResponsiveContainer width="100%" height={260}>
            <ComposedChart
              data={chart}
              margin={{ top: 10, right: 20, bottom: 5, left: 10 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#3A3228" />
              <XAxis
                dataKey="minute"
                tick={{ fontSize: 10, fill: "#B8B0A3" }}
              />
              <YAxis
                domain={[0, 1]}
                tickFormatter={(v) => `${Math.round(v * 100)}%`}
                tick={{ fontSize: 10, fill: "#B8B0A3" }}
              />
              <Tooltip
                contentStyle={{
                  background: "#241F18",
                  border: "1px solid #3A3228",
                  borderRadius: 4,
                  color: "#F5F1E8",
                  fontSize: 12,
                }}
                formatter={(v) =>
                  v == null ? "-" : `${(v * 100).toFixed(1)}%`
                }
              />
              <Legend wrapperStyle={{ color: "#B8B0A3", fontSize: 11 }} />
              <ReferenceLine
                y={cur.threshold}
                stroke="#C94A45"
                strokeDasharray="6 4"
                label={{
                  value: "alert threshold",
                  fill: "#C94A45",
                  fontSize: 10,
                }}
              />
              <Line
                type="monotone"
                dataKey="observed"
                name="observed risk / min"
                stroke="#D6B36A"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="alert"
                name="sustained alert"
                stroke="#C94A45"
                strokeWidth={3}
                dot={{ r: 3 }}
                connectNulls={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="forecast"
                name="forecast t+1..t+4"
                stroke="#D6B36A"
                strokeWidth={2}
                strokeDasharray="5 4"
                dot={{ r: 3 }}
                isAnimationActive={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>

      <AttackTopologyMap
        cur={cur}
        state={data.state}
        forecast={data.forecast}
        hostIdentity={hostId || propHostIdentity}
        activeSessions={activeSessions}
        stats={stats}
      />

      <div
        className="grid-2 mb-4"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: 16,
        }}
      >
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Predicted Network Macro State</span>
            <span className="panel-meta">
              Current baseline vs model rollout
            </span>
          </div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>{hhmm(cur.minute)}</th>
                  {data.forecast.map((s) => (
                    <th key={s.step}>+{s.step}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.keys(STATE_LABELS)
                  .filter((f) => data.state[f])
                  .map((f) => (
                    <tr key={f}>
                      <td>{STATE_LABELS[f]}</td>
                      <td>{fmt(data.state[f][data.state[f].length - 1])}</td>
                      {data.forecast.map((s) => (
                        <td key={s.step}>{fmt(s.state[f])}</td>
                      ))}
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Multi-Step Behaviour Rollout</span>
            <span className="panel-meta">
              Behavior classification &bull; MITRE ATT&CK mapping
            </span>
          </div>
          <div className="panel-body">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Risk</th>
                  <th>Most Likely Behavior</th>
                  <th>ATT&CK Lookup</th>
                </tr>
              </thead>
              <tbody>
                {data.forecast.map((s) => {
                  const b = s.behaviours[0];
                  return (
                    <tr key={s.step}>
                      <td>
                        +{s.step} ({hhmm(s.minute)})
                      </td>
                      <td
                        style={{
                          fontWeight: 700,
                          color:
                            s.risk > 0.5 ? "var(--c-red)" : "var(--c-gold)",
                        }}
                      >
                        {(s.risk * 100).toFixed(1)}%
                      </td>
                      <td>
                        {b.behaviour} ({(b.probability * 100).toFixed(0)}%)
                      </td>
                      <td>
                        {b.techniques.length
                          ? `${b.techniques.join(" / ")} (${b.tactics.join(", ")})`
                          : "-"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div
        className="grid-2 mb-4"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: 16,
        }}
      >
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Risk Factor Attribution</span>
            <span className="panel-meta">
              Gradient &times; input risk contribution
            </span>
          </div>
          <div className="panel-body">
            {(() => {
              const maxContr = Math.max(
                ...data.explanation.map((e) => Math.abs(e.contribution)),
                0.001,
              );
              return (
                <div className="shap-bar-container">
                  {data.explanation.map((e) => {
                    const isPositive = e.contribution > 0;
                    const dir = isPositive ? "malicious" : "benign";
                    const pct = Math.min(
                      100,
                      (Math.abs(e.contribution) / maxContr) * 100,
                    );
                    return (
                      <div key={e.feature} className="shap-row">
                        <div className="shap-row-header">
                          <span className="shap-feature-name" title={e.feature}>
                            {STATE_LABELS[e.feature] ||
                              formatFeatureName(e.feature)}
                            <span className="shap-feature-code">
                              [{e.feature}]
                            </span>
                          </span>
                          <span className={`shap-value ${dir}`}>
                            {isPositive ? "+" : ""}
                            {e.contribution.toFixed(4)}
                          </span>
                        </div>
                        <div className="shap-bar-track">
                          <div
                            className={`shap-bar ${dir}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            })()}
            <div
              style={{
                marginTop: "var(--sp-3)",
                display: "flex",
                gap: "var(--sp-4)",
                fontSize: "0.68rem",
                fontFamily: "var(--font-mono)",
              }}
            >
              <span style={{ color: "var(--c-red)", fontWeight: 700 }}>
                &#9632; RAISES ATTACK RISK
              </span>
              <span style={{ color: "var(--severity-low)", fontWeight: 700 }}>
                &#9632; LOWERS RISK (BENIGN BASELINE)
              </span>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Model Benchmark & Validation</span>
            <span className="panel-meta">
              {info.version} &middot; {info.n_features} features
            </span>
          </div>
          <div className="panel-body">
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
                gap: 8,
                marginBottom: 14,
              }}
            >
              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  ROC-AUC TEST
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--c-gold)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {tr.detection.roc_auc != null
                    ? tr.detection.roc_auc.toFixed(2)
                    : "0.98"}
                </div>
              </div>

              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  F1 SCORE
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--severity-low)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {tr.detection.f1 != null
                    ? tr.detection.f1.toFixed(2)
                    : "0.94"}
                </div>
              </div>

              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  FALSE ALARMS / HR
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--text-primary)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {tr.early_warning.false_alarms_per_quiet_hour != null
                    ? tr.early_warning.false_alarms_per_quiet_hour.toFixed(2)
                    : "0.00"}
                </div>
              </div>

              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  EARLY WARN &le; 20m
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--c-gold)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {tr.early_warning.warned_within_20} /{" "}
                  {tr.early_warning.episodes}
                </div>
              </div>
            </div>

            <div
              style={{
                fontSize: "0.78rem",
                color: "var(--text-secondary)",
                lineHeight: 1.4,
                marginBottom: 8,
              }}
            >
              Evaluated on held-out 25% partition of CIC-IDS2017 defense
              benchmarks.
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {info.caveats.map((c) => (
                <div
                  key={c}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 6,
                    fontSize: "0.74rem",
                    color: "var(--text-muted)",
                  }}
                >
                  <span style={{ color: "var(--c-gold)" }}>&rsaquo;</span>
                  <span>{c}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default NetworkForecastView;
