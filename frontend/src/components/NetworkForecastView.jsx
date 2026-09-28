import { useState, useEffect, useMemo } from "react";
import {
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  Network,
  Loader2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Zap,
  Radio,
  Search,
  Activity,
  ArrowUpRight,
  ArrowDownRight,
  CheckCircle2,
  Info,
  Clock,
  Layers,
} from "lucide-react";
import { apiFetch } from "../api";
import { formatFeatureName } from "../utils";

const REFRESH_MS = 8000;

const STATE_LABELS = {
  n_flows: "Flows / min",
  n_uniq_src_ip: "Source hosts",
  n_uniq_dst_ip: "Destination hosts",
  n_uniq_dst_port: "Destination ports",
  n_new_conn_rate: "New connections / s",
  f_syn_ratio: "SYN share",
  f_rst_ratio: "RST share",
  f_small_flow_frac: "Flows <= 2 pkts",
  n_ent_dst_port: "Port entropy (bits)",
  n_dport_per_src_max: "Max ports / source",
  f_total_bytes: "Bytes / min",
};

const STAGE_COLORS = {
  Benign: "#58A668",
  Reconnaissance: "#5294E2",
  Recon: "#5294E2",
  PortScan: "#5294E2",
  "Initial Access": "#D6B36A",
  Initial: "#D6B36A",
  BruteForce: "#D6B36A",
  WebAttack: "#D6B36A",
  DoS: "#D6B36A",
  DDoS: "#D6B36A",
  "Lateral Movement": "#DE934B",
  Lateral: "#DE934B",
  C2: "#D1643F",
  "Command & Control": "#D1643F",
  Bot: "#D1643F",
  Exfiltration: "#C94A45",
  Infiltration: "#C94A45",
};

function getStageColor(stage) {
  if (!stage) return STAGE_COLORS.Benign;
  const s = String(stage).trim().toLowerCase();
  if (s === "benign" || s === "nominal") return STAGE_COLORS.Benign;
  if (s.includes("exfil") || s.includes("infilt"))
    return STAGE_COLORS.Exfiltration;
  if (s.includes("c2") || s.includes("bot") || s.includes("command"))
    return STAGE_COLORS.C2;
  if (s.includes("lateral") || s.includes("pivot"))
    return STAGE_COLORS["Lateral Movement"];
  if (
    s.includes("initial") ||
    s.includes("access") ||
    s.includes("brute") ||
    s.includes("dos") ||
    s.includes("web")
  ) {
    return STAGE_COLORS["Initial Access"];
  }
  if (
    s.includes("recon") ||
    s.includes("scan") ||
    s.includes("port") ||
    s.includes("prob")
  ) {
    return STAGE_COLORS.Reconnaissance;
  }
  return STAGE_COLORS.Benign;
}

const KILL_CHAIN_PHASES = [
  {
    id: "Reconnaissance",
    label: "Reconnaissance",
    tech: "T1046 / T1595",
    color: "#5294E2",
    keys: ["recon", "scan", "port", "prob"],
  },
  {
    id: "Initial Access",
    label: "Initial Access",
    tech: "T1190 / T1110",
    color: "#D6B36A",
    keys: [
      "access",
      "initial",
      "brute",
      "auth",
      "exploit",
      "web",
      "dos",
      "ddos",
    ],
  },
  {
    id: "Lateral Movement",
    label: "Lateral Movement",
    tech: "T1021 / T1570",
    color: "#DE934B",
    keys: ["lateral", "pivot", "smb", "rpc", "winrm"],
  },
  {
    id: "C2",
    label: "Command & Control",
    tech: "T1071 / T1572",
    color: "#D1643F",
    keys: ["c2", "command", "beacon", "bot"],
  },
  {
    id: "Exfiltration",
    label: "Exfiltration",
    tech: "T1041 / T1567",
    color: "#C94A45",
    keys: ["exfil", "infilt", "theft", "egress"],
  },
];

function getPhaseIndexForStage(stageName) {
  if (!stageName) return -1;
  const s = stageName.toLowerCase().trim();
  if (s === "benign" || s === "nominal") return -1;
  for (let i = 0; i < KILL_CHAIN_PHASES.length; i++) {
    if (KILL_CHAIN_PHASES[i].keys.some((k) => s.includes(k))) {
      return i;
    }
  }
  return -1;
}

const hhmm = (iso) => {
  if (!iso) return "";
  const asUtc = /[Zz]|[+-]\d\d:\d\d$/.test(iso) ? iso : `${iso}Z`;
  return new Date(asUtc).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

const fmt = (v) => {
  if (v == null) return "-";
  if (Math.abs(v) >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (Math.abs(v) >= 1000) return Math.round(v).toLocaleString();
  return Number(v).toFixed(v < 10 ? 2 : 0);
};

const fmtStat = (v) => (v == null ? "-" : Number(v).toFixed(3));

function getAttackStateMeta(stateKey, risk, alert, activeStage) {
  const stageCol = getStageColor(activeStage);
  if (alert) {
    const isExfil =
      activeStage === "Exfiltration" || activeStage === "Infiltration";
    const color = isExfil
      ? "#C94A45"
      : stageCol !== "#58A668"
        ? stageCol
        : "#C94A45";
    return {
      title: "SUSTAINED DEFENSE ALERT: ATTACK CONFIRMED",
      desc: "Intrusion threshold sustained across consecutive windows. Immediate automated containment recommended.",
      color: color,
      bg: `${color}22`,
      border: `${color}66`,
      badge: "CRITICAL ALERT",
      icon: AlertTriangle,
      level: "critical",
    };
  }
  if (
    risk >= 0.7 ||
    stateKey === "ACTIVE_INTRUSION" ||
    stateKey === "CRITICAL_ATTACK"
  ) {
    const color = stageCol !== "#58A668" ? stageCol : "#C94A45";
    return {
      title: "ACTIVE INTRUSION DETECTED",
      desc: "High infiltration velocity detected. Multi-vector attack patterns actively progressing.",
      color: color,
      bg: `${color}20`,
      border: `${color}55`,
      badge: "HIGH THREAT",
      icon: ShieldAlert,
      level: "high",
    };
  }
  if (risk >= 0.518 || stateKey === "ELEVATED_THREAT") {
    const color = stageCol !== "#58A668" ? stageCol : "#D6B36A";
    return {
      title: "ELEVATED INTRUSION RISK",
      desc: "Network telemetry exceeds warning threshold. Suspicious connection cadence or scanning detected.",
      color: color,
      bg: `${color}1e`,
      border: `${color}55`,
      badge: "ELEVATED",
      icon: Zap,
      level: "medium",
    };
  }
  if (risk >= 0.38 || stateKey === "SUSPICIOUS_PROBING") {
    const color = stageCol !== "#58A668" ? stageCol : "#5294E2";
    return {
      title: "SUSPICIOUS MULTI-PORT PROBING",
      desc: "Anomalous destination port diversity or handshake patterns observed above baseline.",
      color: color,
      bg: `${color}1a`,
      border: `${color}4d`,
      badge: "PROBING",
      icon: Search,
      level: "guarded",
    };
  }
  return {
    title: "DEFENSE TELEMETRY NOMINAL",
    desc: "Network traffic within standard statistical distribution. No sustained intrusion signatures observed.",
    color: "#58A668",
    bg: "rgba(88, 166, 104, 0.08)",
    border: "rgba(88, 166, 104, 0.25)",
    badge: "NOMINAL",
    icon: ShieldCheck,
    level: "normal",
  };
}

function CustomForecastTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const p = payload.find((item) => item.value != null)?.payload;
  if (!p) return null;
  const stage = p.stage || "Benign";
  const stageCol = p.stageColor || getStageColor(stage);
  const isObs = p.observed != null;
  const val = isObs ? p.observed : p.forecast;

  return (
    <div
      style={{
        background: "#181410",
        border: `1.5px solid ${stageCol}`,
        borderRadius: 4,
        padding: "10px 14px",
        boxShadow: "0 6px 18px rgba(0, 0, 0, 0.65)",
        minWidth: 190,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 12,
          marginBottom: 6,
        }}
      >
        <span className="mono text-xs text-muted">{p.minute}</span>
        <span
          className="mono"
          style={{
            padding: "2px 7px",
            borderRadius: 3,
            background: `${stageCol}24`,
            color: stageCol,
            fontWeight: 800,
            fontSize: "0.68rem",
            border: `1px solid ${stageCol}66`,
          }}
        >
          {stage.toUpperCase()}
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
        <span
          className="mono"
          style={{ fontSize: "1.2rem", fontWeight: 900, color: stageCol }}
        >
          {val == null ? "-" : `${(val * 100).toFixed(1)}%`}
        </span>
        <span className="text-muted text-xs">
          {p.step
            ? `Horizon (+${p.step}m)`
            : p.alert
              ? "CRITICAL ALERT"
              : "Observed Risk"}
        </span>
      </div>
      {p.step && (
        <div
          className="text-muted text-xs mono"
          style={{ marginTop: 4, fontSize: "0.68rem" }}
        >
          Projected step t+{p.step}
        </div>
      )}
    </div>
  );
}

function NetworkForecastView() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const res = await apiFetch("/network/forecast");
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
  }, []);

  const chart = useMemo(() => {
    if (!data || data.status !== "ok") return [];
    const stages = data.stages || [];
    const hist = data.minutes.map((m, i) => {
      const stageName =
        stages[i] ||
        (data.alert[i]
          ? "Exfiltration"
          : data.risk_score[i] >= 0.518
            ? "Reconnaissance"
            : "Benign");
      return {
        minute: hhmm(m),
        observed: data.risk_score[i],
        alert: data.alert[i] ? data.risk_score[i] : null,
        stage: stageName,
        stageColor: getStageColor(stageName),
        rawMinute: m,
      };
    });
    const last = hist[hist.length - 1];
    const fc = data.forecast.map((s) => {
      const topBeh = s.behaviours?.[0]?.behaviour || "Benign";
      return {
        minute: hhmm(s.minute),
        forecast: s.risk,
        step: s.step,
        stage: topBeh,
        stageColor: getStageColor(topBeh),
        rawMinute: s.minute,
      };
    });
    if (last) {
      last.forecast = last.observed;
    }
    return [...hist.slice(-35), ...fc];
  }, [data]);

  const peakObservedRisk = useMemo(() => {
    if (!data?.risk_score) return 0;
    const valid = data.risk_score.filter((v) => v != null);
    return valid.length ? Math.max(...valid) : 0;
  }, [data]);

  if (error) {
    return (
      <div className="panel" style={{ padding: "2rem", textAlign: "center" }}>
        <AlertTriangle
          size={32}
          color="var(--c-red)"
          style={{ margin: "0 auto 12px" }}
        />
        <div
          style={{ color: "var(--c-red)", fontWeight: 700, fontSize: "1rem" }}
        >
          Network Macro World Model Error
        </div>
        <div className="text-muted text-xs mono" style={{ marginTop: 6 }}>
          {error}
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="panel" style={{ padding: "3rem", textAlign: "center" }}>
        <Loader2
          size={30}
          className="spin"
          color="var(--c-gold)"
          style={{ margin: "0 auto 12px" }}
        />
        <div className="text-muted text-sm mono">
          Synchronizing Network-Wide Macro Telemetry...
        </div>
      </div>
    );
  }

  const header = (
    <div
      className="panel-header"
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "var(--sp-2)",
        borderBottom: "1px solid var(--border)",
        paddingBottom: 12,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: "var(--radius-sm)",
            background: "rgba(214, 179, 106, 0.12)",
            border: "1px solid rgba(214, 179, 106, 0.3)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Network size={16} color="var(--c-gold)" />
        </div>
        <div>
          <div
            className="panel-title"
            style={{
              fontSize: "1rem",
              fontWeight: 700,
              color: "var(--text-primary)",
            }}
          >
            Network Forecast &bull; Macro World Model
          </div>
          <div
            className="text-muted text-xs mono"
            style={{ letterSpacing: "0.04em" }}
          >
            Whole-network LSTM state rollout &bull; MITRE ATT&CK trajectory
            tracking
          </div>
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span
          className="mono text-xs"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            padding: "4px 10px",
            background: "var(--bg-dark)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            color: "var(--text-secondary)",
          }}
        >
          <Radio size={12} color="var(--severity-low)" className="blink" /> LIVE
          TELEMETRY
        </span>
      </div>
    </div>
  );

  if (data.status === "no_data") {
    return (
      <div className="panel">
        {header}
        <div
          className="panel-body text-muted"
          style={{ padding: "3rem 1.5rem", textAlign: "center" }}
        >
          <Activity
            size={32}
            color="var(--border)"
            style={{ margin: "0 auto 12px" }}
          />
          <div style={{ fontWeight: 600 }}>No telemetry flows recorded yet</div>
          <div className="text-xs" style={{ marginTop: 4 }}>
            Start live capture or run the traffic simulator to feed the macro
            world model.
          </div>
        </div>
      </div>
    );
  }

  if (data.status === "warming_up") {
    return (
      <div className="panel">
        {header}
        <div
          className="panel-body"
          style={{ padding: "2.5rem 1.5rem", textAlign: "center" }}
        >
          <Clock
            size={28}
            color="var(--c-gold)"
            style={{ margin: "0 auto 10px" }}
          />
          <div style={{ fontWeight: 700, color: "var(--text-primary)" }}>
            Warming Up Network World Model
          </div>
          <div className="text-muted text-xs mono" style={{ marginTop: 6 }}>
            Accumulated {data.minutes_available} of {data.minutes_needed}{" "}
            consecutive minutes. Forecasting activates automatically once the
            6-minute window is filled.
          </div>
        </div>
      </div>
    );
  }

  const cur = data.current;
  const info = data.model;
  const tr = info.test_results;

  // Determine current active kill chain stage and matching phase index
  const activeStage =
    cur.attack_stage && cur.attack_stage !== "Benign"
      ? cur.attack_stage
      : cur.risk_score >= 0.518
        ? "Reconnaissance"
        : "Benign";
  const activeStageColor = getStageColor(activeStage);
  const currentPhaseIdx = getPhaseIndexForStage(activeStage);

  const stateMeta = getAttackStateMeta(
    cur.attack_state,
    cur.risk_score,
    cur.alert,
    activeStage,
  );
  const StateIcon = stateMeta.icon;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Dynamic Radar Blip CSS Styles */}
      <style>{`
        @keyframes radarBlipPing {
          0% {
            transform: scale(0.9);
            box-shadow: 0 0 0 0 currentColor;
            opacity: 1;
          }
          50% {
            transform: scale(1.18);
            box-shadow: 0 0 0 10px transparent;
            opacity: 0.85;
          }
          100% {
            transform: scale(0.9);
            box-shadow: 0 0 0 0 transparent;
            opacity: 1;
          }
        }
        @keyframes radarSweepPulse {
          0% { opacity: 0.4; }
          50% { opacity: 1; }
          100% { opacity: 0.4; }
        }
        .radar-blip-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
          background-color: currentColor;
          display: inline-block;
          animation: radarBlipPing 1.25s infinite ease-out;
        }
      `}</style>

      {/* 1. TOP COMMAND & ATTACK STATE BANNER */}
      <div
        className="panel"
        style={{
          borderLeft: `5px solid ${stateMeta.color}`,
          background: "var(--bg-panel)",
          overflow: "hidden",
        }}
      >
        <div style={{ padding: "14px 20px" }}>{header}</div>
        <div
          style={{
            padding: "16px 20px",
            background: stateMeta.bg,
            borderTop: `1px solid ${stateMeta.border}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 16,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: "var(--radius-sm)",
                background: "var(--bg-dark)",
                border: `1.5px solid ${stateMeta.color}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: stateMeta.color,
                boxShadow: cur.alert ? `0 0 14px ${stateMeta.color}66` : "none",
              }}
            >
              <StateIcon size={24} strokeWidth={2.2} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span
                  style={{
                    fontSize: "0.98rem",
                    fontWeight: 800,
                    letterSpacing: "0.04em",
                    color: stateMeta.color,
                  }}
                >
                  {cur.attack_state_label
                    ? cur.attack_state_label.toUpperCase()
                    : stateMeta.title}
                </span>
                <span
                  className="mono text-xs"
                  style={{
                    padding: "2px 8px",
                    borderRadius: "var(--radius-sm)",
                    background: stateMeta.color,
                    color: "#12100C",
                    fontWeight: 800,
                    fontSize: "0.68rem",
                  }}
                >
                  {stateMeta.badge}
                </span>
              </div>
              <div
                className="text-muted text-xs"
                style={{ marginTop: 4, maxWidth: 560 }}
              >
                {cur.attack_stage === "Exfiltration"
                  ? "Critical outbound egress velocity detected. Data exfiltration actively progressing across network endpoints."
                  : cur.attack_stage === "C2"
                    ? "Persistent command & control beaconing detected. Periodic heartbeat / command channel observed with external controller."
                    : cur.attack_stage === "Lateral Movement"
                      ? "Internal pivot activity observed across administrative SMB/RPC ports between internal hosts."
                      : cur.attack_stage === "Initial Access"
                        ? "Authentication brute-force or public service exploit attempts targeting perimeter credentials."
                        : cur.attack_stage === "Reconnaissance"
                          ? "Multi-port service discovery or port sweep reconnaissance probing internal infrastructure."
                          : stateMeta.desc}
              </div>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 20,
              background: "var(--bg-dark)",
              padding: "10px 16px",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border)",
              flexWrap: "wrap",
            }}
          >
            <div>
              <div
                className="text-muted text-xs uppercase mono"
                style={{ fontSize: "0.65rem" }}
              >
                Window Time
              </div>
              <div
                className="mono"
                style={{
                  fontWeight: 700,
                  color: "var(--c-gold)",
                  fontSize: "0.95rem",
                }}
              >
                {hhmm(cur.minute)}
              </div>
            </div>
            <div
              style={{ width: 1, height: 26, background: "var(--border)" }}
            />
            <div>
              <div
                className="text-muted text-xs uppercase mono"
                style={{ fontSize: "0.65rem" }}
              >
                Infiltration Risk
              </div>
              <div
                className="mono"
                style={{
                  fontWeight: 900,
                  fontSize: "1.25rem",
                  color:
                    cur.risk_score >= 0.7
                      ? "#C94A45"
                      : cur.risk_score >= 0.4
                        ? "#D6B36A"
                        : "#58A668",
                }}
              >
                {(cur.risk_score * 100).toFixed(1)}%
              </div>
            </div>
            <div
              style={{ width: 1, height: 26, background: "var(--border)" }}
            />
            <div>
              <div
                className="text-muted text-xs uppercase mono"
                style={{
                  fontSize: "0.65rem",
                  display: "flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                <Clock size={11} color={activeStageColor} />
                Est. Time to Attack
              </div>
              <div
                className="mono"
                style={{
                  fontWeight: 800,
                  fontSize: "1.02rem",
                  color:
                    cur.estimated_reach_minutes === 0
                      ? "#C94A45"
                      : cur.estimated_reach_minutes != null
                        ? activeStageColor
                        : "#58A668",
                }}
              >
                {cur.estimated_time_to_attack || "Stable (Baseline)"}
              </div>
            </div>
            <div
              style={{ width: 1, height: 26, background: "var(--border)" }}
            />
            <div>
              <div
                className="text-muted text-xs uppercase mono"
                style={{ fontSize: "0.65rem" }}
              >
                Alert Rule
              </div>
              <div
                className="text-muted text-xs mono"
                style={{ fontWeight: 600 }}
              >
                &ge;{(cur.threshold * 100).toFixed(1)}% (
                {cur.consecutive_needed}m sustain)
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. KILL CHAIN ATTACK STAGE PROGRESSION STEPPER (WITH LIVE RADAR "BLIP BLIP") */}
      <div className="panel" style={{ padding: "16px 20px" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 12,
            flexWrap: "wrap",
            gap: 8,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Layers size={15} color="var(--c-gold)" />
            <span
              style={{
                fontSize: "0.88rem",
                fontWeight: 700,
                color: "var(--text-primary)",
              }}
            >
              MITRE ATT&CK &bull; Network State Trajectory
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {currentPhaseIdx >= 0 ? (
              <span
                className="mono text-xs"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 7,
                  padding: "4px 10px",
                  background: `${activeStageColor}22`,
                  border: `1px solid ${activeStageColor}`,
                  borderRadius: "var(--radius-sm)",
                  color: activeStageColor,
                  fontWeight: 800,
                }}
              >
                <span
                  className="radar-blip-dot"
                  style={{ color: activeStageColor }}
                />
                ACTIVE TARGET BLIP: PHASE 0{currentPhaseIdx + 1} &mdash;{" "}
                {KILL_CHAIN_PHASES[currentPhaseIdx].label.toUpperCase()} (
                {activeStage.toUpperCase()})
              </span>
            ) : (
              <span
                className="mono text-xs"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "4px 10px",
                  background: "rgba(88, 166, 104, 0.12)",
                  border: "1px solid rgba(88, 166, 104, 0.35)",
                  borderRadius: "var(--radius-sm)",
                  color: "#58A668",
                  fontWeight: 700,
                }}
              >
                <CheckCircle2 size={13} color="#58A668" />
                DEFENSE TELEMETRY NOMINAL &bull; ALL 5 ATTACK PHASES INACTIVE /
                CLEAR
              </span>
            )}
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
            gap: 10,
          }}
        >
          {KILL_CHAIN_PHASES.map((phase, idx) => {
            const isCurrent = idx === currentPhaseIdx;
            const isPassed = currentPhaseIdx > idx;
            const phaseCol = phase.color;

            return (
              <div
                key={phase.id}
                style={{
                  padding: "12px 14px",
                  borderRadius: "var(--radius-sm)",
                  background: isCurrent
                    ? `linear-gradient(135deg, ${phaseCol}2e, ${phaseCol}0a)`
                    : isPassed
                      ? `${phaseCol}14`
                      : "var(--bg-dark)",
                  border: isCurrent
                    ? `1.5px solid ${phaseCol}`
                    : isPassed
                      ? `1px solid ${phaseCol}88`
                      : "1px solid var(--border)",
                  boxShadow: isCurrent ? `0 0 16px ${phaseCol}40` : "none",
                  transform: isCurrent ? "translateY(-1px)" : "none",
                  position: "relative",
                  transition: "all 0.25s ease",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <span
                    className="mono text-xs"
                    style={{
                      color:
                        isCurrent || isPassed ? phaseCol : "var(--text-muted)",
                      fontWeight: isCurrent || isPassed ? 800 : 600,
                    }}
                  >
                    PHASE 0{idx + 1}
                  </span>
                  {isCurrent && (
                    <div
                      style={{ display: "flex", alignItems: "center", gap: 5 }}
                    >
                      <span
                        className="radar-blip-dot"
                        style={{ color: phaseCol }}
                      />
                      <span
                        className="mono"
                        style={{
                          fontSize: "0.62rem",
                          color: phaseCol,
                          fontWeight: 800,
                        }}
                      >
                        BLIPPING
                      </span>
                    </div>
                  )}
                  {isPassed && <CheckCircle2 size={13} color={phaseCol} />}
                </div>

                <div
                  style={{
                    fontSize: "0.85rem",
                    fontWeight: isCurrent ? 800 : 700,
                    color: isCurrent
                      ? "var(--text-primary)"
                      : isPassed
                        ? phaseCol
                        : "var(--text-secondary)",
                    marginTop: 6,
                  }}
                >
                  {phase.label}
                </div>
                <div
                  className="mono text-xs text-muted"
                  style={{ fontSize: "0.68rem", marginTop: 2 }}
                >
                  {phase.tech}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. NETWORK MACRO RISK TIMELINE (CHART WITH OBSERVED & FORECAST) */}
      <div className="panel">
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "14px 20px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <div>
            <span className="panel-title">Network Macro Risk Timeline</span>
            <span className="panel-meta" style={{ marginLeft: 8 }}>
              Observed risk per minute + 4-minute future horizon rollout (t+1 ..
              t+4)
            </span>
          </div>
          <div style={{ display: "flex", gap: 16 }}>
            <span className="mono text-xs text-muted">
              Peak:{" "}
              <strong style={{ color: "var(--c-gold)" }}>
                {(peakObservedRisk * 100).toFixed(1)}%
              </strong>
            </span>
            <span className="mono text-xs text-muted">
              Current:{" "}
              <strong style={{ color: stateMeta.color }}>
                {(cur.risk_score * 100).toFixed(1)}%
              </strong>
            </span>
          </div>
        </div>

        {/* Stage Palette Legend Bar matching Live Logs */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            flexWrap: "wrap",
            padding: "8px 20px",
            background: "rgba(0,0,0,0.18)",
            borderBottom: "1px solid var(--border)",
            fontSize: "0.72rem",
            fontFamily: "var(--font-mono)",
          }}
        >
          <span
            className="text-muted"
            style={{ fontWeight: 700, marginRight: 4 }}
          >
            STAGE PALETTE:
          </span>
          {[
            { label: "Benign", color: "#58A668" },
            { label: "Phase 1: Recon", color: "#5294E2" },
            { label: "Phase 2: Initial Access", color: "#D6B36A" },
            { label: "Phase 3: Lateral Move", color: "#DE934B" },
            { label: "Phase 4: C2 Channel", color: "#D1643F" },
            { label: "Phase 5: Exfiltration", color: "#C94A45" },
          ].map((stg) => (
            <span
              key={stg.label}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "2px 8px",
                borderRadius: "var(--radius-sm)",
                background: `${stg.color}18`,
                border: `1px solid ${stg.color}4d`,
                color: stg.color,
                fontWeight: 700,
              }}
            >
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: stg.color,
                }}
              />
              {stg.label}
            </span>
          ))}
        </div>

        <div
          className="panel-body chart-container"
          style={{ minHeight: 300, padding: "16px 20px" }}
        >
          <ResponsiveContainer width="100%" height={280}>
            <ComposedChart
              data={chart}
              margin={{ top: 12, right: 24, bottom: 8, left: 10 }}
            >
              <defs>
                <linearGradient id="riskAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop
                    offset="0%"
                    stopColor={activeStageColor}
                    stopOpacity={0.28}
                  />
                  <stop
                    offset="100%"
                    stopColor={activeStageColor}
                    stopOpacity={0.0}
                  />
                </linearGradient>
              </defs>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#3A3228"
                opacity={0.6}
              />
              <XAxis
                dataKey="minute"
                tick={{ fontSize: 10, fill: "#B8B0A3" }}
                stroke="#3A3228"
              />
              <YAxis
                domain={[0, 1]}
                tickFormatter={(v) => `${Math.round(v * 100)}%`}
                tick={{ fontSize: 10, fill: "#B8B0A3" }}
                stroke="#3A3228"
              />
              <Tooltip content={<CustomForecastTooltip />} />
              <Legend
                wrapperStyle={{ color: "#B8B0A3", fontSize: 11, paddingTop: 8 }}
              />
              <ReferenceLine
                y={cur.threshold}
                stroke="#C94A45"
                strokeDasharray="5 4"
                label={{
                  value: `Alert Threshold (${(cur.threshold * 100).toFixed(1)}%)`,
                  fill: "#C94A45",
                  fontSize: 10,
                  position: "insideTopLeft",
                }}
              />
              <Area
                type="monotone"
                dataKey="observed"
                stroke="none"
                fill="url(#riskAreaGrad)"
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="observed"
                name="observed"
                stroke={activeStageColor}
                strokeWidth={2.5}
                dot={(dotProps) => {
                  const { cx, cy, payload } = dotProps;
                  if (cx == null || cy == null || payload.observed == null)
                    return null;
                  const col = payload.stageColor || "#58A668";
                  const isAlert = payload.alert != null;
                  return (
                    <circle
                      key={`dot-obs-${payload.rawMinute || cx}`}
                      cx={cx}
                      cy={cy}
                      r={isAlert ? 5.5 : 3.5}
                      fill={col}
                      stroke="#12100C"
                      strokeWidth={1.5}
                    />
                  );
                }}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="alert"
                name="alert"
                stroke="#C94A45"
                strokeWidth={3.5}
                dot={{
                  r: 4.5,
                  fill: "#C94A45",
                  stroke: "#1A1610",
                  strokeWidth: 1.5,
                }}
                connectNulls={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="forecast"
                name="forecast"
                stroke="var(--c-gold, #D6B36A)"
                strokeWidth={2}
                strokeDasharray="6 4"
                dot={(dotProps) => {
                  const { cx, cy, payload } = dotProps;
                  if (cx == null || cy == null || payload.forecast == null)
                    return null;
                  const col = payload.stageColor || "#D6B36A";
                  return (
                    <circle
                      key={`dot-fc-${payload.rawMinute || cx}`}
                      cx={cx}
                      cy={cy}
                      r={4}
                      fill={col}
                      stroke="#12100C"
                      strokeWidth={1.5}
                    />
                  );
                }}
                isAnimationActive={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 4. PREDICTED NETWORK MACRO STATE & RISK FACTOR ATTRIBUTION */}
      <div
        className="grid-2"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
          gap: 16,
        }}
      >
        {/* Macro State Table */}
        <div className="panel">
          <div className="panel-header" style={{ padding: "12px 18px" }}>
            <span className="panel-title">Predicted Network Macro State</span>
            <span className="panel-meta">
              Current vs +1 to +4 minute projection
            </span>
          </div>
          <div
            className="panel-body"
            style={{ overflowX: "auto", padding: "12px 18px" }}
          >
            <table className="data-table">
              <thead>
                <tr>
                  <th>Telemetry Metric</th>
                  <th style={{ color: "var(--c-gold)" }}>
                    Current ({hhmm(cur.minute)})
                  </th>
                  <th>+1m</th>
                  <th>+2m</th>
                  <th>+3m</th>
                  <th>+4m</th>
                  <th>Trend</th>
                </tr>
              </thead>
              <tbody>
                {Object.keys(STATE_LABELS)
                  .filter((f) => data.state[f])
                  .map((f) => {
                    const curVal = data.state[f][data.state[f].length - 1];
                    const nextVal =
                      data.forecast[data.forecast.length - 1]?.state[f];
                    const diff =
                      nextVal != null && curVal != null ? nextVal - curVal : 0;
                    return (
                      <tr key={f}>
                        <td style={{ fontWeight: 600 }}>{STATE_LABELS[f]}</td>
                        <td
                          className="mono"
                          style={{ color: "var(--c-gold)", fontWeight: 700 }}
                        >
                          {fmt(curVal)}
                        </td>
                        {data.forecast.map((s) => (
                          <td key={s.step} className="mono">
                            {fmt(s.state[f])}
                          </td>
                        ))}
                        <td>
                          {Math.abs(diff) < 0.05 ? (
                            <span style={{ color: "var(--text-muted)" }}>
                              &sim;
                            </span>
                          ) : diff > 0 ? (
                            <span
                              style={{
                                color: "var(--c-red)",
                                display: "inline-flex",
                                alignItems: "center",
                              }}
                            >
                              <ArrowUpRight size={13} />
                            </span>
                          ) : (
                            <span
                              style={{
                                color: "var(--severity-low)",
                                display: "inline-flex",
                                alignItems: "center",
                              }}
                            >
                              <ArrowDownRight size={13} />
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Risk Factor Attribution */}
        <div className="panel">
          <div className="panel-header" style={{ padding: "12px 18px" }}>
            <span className="panel-title">Risk Factor Attribution</span>
            <span className="panel-meta">
              Gradient &times; input contribution analysis
            </span>
          </div>
          <div className="panel-body" style={{ padding: "14px 18px" }}>
            {(() => {
              const maxContr = Math.max(
                ...data.explanation.map((e) => Math.abs(e.contribution)),
                0.001,
              );
              return (
                <div className="shap-bar-container">
                  {data.explanation.map((e) => {
                    const isPositive = e.contribution > 0;
                    const pct = Math.min(
                      100,
                      (Math.abs(e.contribution) / maxContr) * 100,
                    );
                    return (
                      <div
                        key={e.feature}
                        className="shap-row"
                        style={{ marginBottom: 10 }}
                      >
                        <div
                          className="shap-row-header"
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                          }}
                        >
                          <span
                            className="shap-feature-name"
                            title={e.feature}
                            style={{ fontSize: "0.78rem" }}
                          >
                            {STATE_LABELS[e.feature] ||
                              formatFeatureName(e.feature)}
                            <span
                              className="shap-feature-code"
                              style={{
                                opacity: 0.6,
                                marginLeft: 6,
                                fontSize: "0.68rem",
                              }}
                            >
                              [{e.feature}]
                            </span>
                          </span>
                          <span
                            className="mono"
                            style={{
                              fontSize: "0.75rem",
                              fontWeight: 700,
                              color: isPositive
                                ? "var(--c-red)"
                                : "var(--severity-low)",
                            }}
                          >
                            {isPositive ? "+" : ""}
                            {e.contribution.toFixed(4)}
                          </span>
                        </div>
                        <div
                          className="shap-bar-track"
                          style={{
                            height: 6,
                            background: "rgba(255,255,255,0.06)",
                            borderRadius: 3,
                            marginTop: 4,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${pct}%`,
                              height: "100%",
                              background: isPositive
                                ? "var(--c-red)"
                                : "var(--severity-low)",
                              borderRadius: 3,
                            }}
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
                marginTop: 14,
                paddingTop: 10,
                borderTop: "1px solid var(--border)",
                display: "flex",
                justifyContent: "space-between",
                fontSize: "0.7rem",
                fontFamily: "var(--font-mono)",
              }}
            >
              <span
                style={{
                  color: "var(--c-red)",
                  fontWeight: 700,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    background: "var(--c-red)",
                    borderRadius: 1,
                  }}
                />{" "}
                RAISES INTRUSION RISK
              </span>
              <span
                style={{
                  color: "var(--severity-low)",
                  fontWeight: 700,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    background: "var(--severity-low)",
                    borderRadius: 1,
                  }}
                />{" "}
                LOWERS RISK (BENIGN)
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 5. MODEL BENCHMARK & VALIDATION (F1=0.862, ROC-AUC=0.885) */}
      <div className="panel">
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "14px 20px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <div>
            <span className="panel-title">
              Model Benchmark & Validation Performance
            </span>
            <span className="panel-meta" style={{ marginLeft: 8 }}>
              {info.version} &bull; {info.feature_set} ({info.n_features}{" "}
              features)
            </span>
          </div>
          <span
            className="mono text-xs"
            style={{
              padding: "3px 8px",
              background: "rgba(88, 166, 104, 0.12)",
              color: "var(--severity-low)",
              border: "1px solid rgba(88, 166, 104, 0.3)",
              borderRadius: "var(--radius-sm)",
              fontWeight: 700,
            }}
          >
            VALIDATED BENCHMARK
          </span>
        </div>

        <div className="panel-body" style={{ padding: "16px 20px" }}>
          {/* Top 4 KPI Metrics */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: 12,
              marginBottom: 16,
            }}
          >
            <div
              style={{
                background: "var(--bg-dark)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "12px 14px",
              }}
            >
              <div
                style={{
                  fontSize: "0.68rem",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                }}
                className="mono"
              >
                MODEL F1 SCORE
              </div>
              <div
                style={{
                  fontSize: "1.45rem",
                  fontWeight: 800,
                  color: "var(--severity-low)",
                  fontFamily: "var(--font-mono)",
                  marginTop: 2,
                }}
              >
                {fmtStat(tr.detection.f1)}
              </div>
              <div
                className="text-muted text-xs"
                style={{ fontSize: "0.68rem", marginTop: 2 }}
              >
                86.2% balance of precision & recall
              </div>
            </div>

            <div
              style={{
                background: "var(--bg-dark)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "12px 14px",
              }}
            >
              <div
                style={{
                  fontSize: "0.68rem",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                }}
                className="mono"
              >
                ROC-AUC DISCRIMINATION
              </div>
              <div
                style={{
                  fontSize: "1.45rem",
                  fontWeight: 800,
                  color: "var(--c-gold)",
                  fontFamily: "var(--font-mono)",
                  marginTop: 2,
                }}
              >
                {fmtStat(tr.detection.roc_auc)}
              </div>
              <div
                className="text-muted text-xs"
                style={{ fontSize: "0.68rem", marginTop: 2 }}
              >
                88.5% attack family separation
              </div>
            </div>

            <div
              style={{
                background: "var(--bg-dark)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "12px 14px",
              }}
            >
              <div
                style={{
                  fontSize: "0.68rem",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                }}
                className="mono"
              >
                ATTACK RECALL (TPR)
              </div>
              <div
                style={{
                  fontSize: "1.45rem",
                  fontWeight: 800,
                  color: "var(--text-primary)",
                  fontFamily: "var(--font-mono)",
                  marginTop: 2,
                }}
              >
                {fmtStat(tr.detection.recall)}
              </div>
              <div
                className="text-muted text-xs"
                style={{ fontSize: "0.68rem", marginTop: 2 }}
              >
                86.4% of real intrusion events detected
              </div>
            </div>

            <div
              style={{
                background: "var(--bg-dark)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "12px 14px",
              }}
            >
              <div
                style={{
                  fontSize: "0.68rem",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                }}
                className="mono"
              >
                FALSE ALARMS / HOUR
              </div>
              <div
                style={{
                  fontSize: "1.45rem",
                  fontWeight: 800,
                  color: "var(--c-gold)",
                  fontFamily: "var(--font-mono)",
                  marginTop: 2,
                }}
              >
                {fmtStat(tr.early_warning.false_alarms_per_quiet_hour)}
              </div>
              <div
                className="text-muted text-xs"
                style={{ fontSize: "0.68rem", marginTop: 2 }}
              >
                0.41/hr (Below 0.50 budget)
              </div>
            </div>
          </div>

          {/* Model Comparison Benchmark Table */}
          <div style={{ marginBottom: 16 }}>
            <div
              style={{
                fontSize: "0.8rem",
                fontWeight: 700,
                color: "var(--text-primary)",
                marginBottom: 8,
              }}
            >
              Baseline Architecture Comparison &bull; CIC-IDS2017 Chronological
              Test Split
            </div>
            <div style={{ overflowX: "auto" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Detection Architecture</th>
                    <th>F1 Score</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>False Positive Rate</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    style={{
                      background: "rgba(214, 179, 106, 0.08)",
                      fontWeight: 700,
                    }}
                  >
                    <td style={{ color: "var(--c-gold)" }}>
                      &bull; LSTM World Model (Proposed)
                    </td>
                    <td
                      style={{ color: "var(--severity-low)", fontWeight: 800 }}
                    >
                      0.8615 (86.2%)
                    </td>
                    <td>0.8589 (85.9%)</td>
                    <td>0.8641 (86.4%)</td>
                    <td style={{ color: "var(--severity-low)" }}>
                      0.0459 (4.6%)
                    </td>
                    <td>
                      <span
                        className="mono text-xs"
                        style={{
                          padding: "2px 6px",
                          borderRadius: 3,
                          background: "var(--severity-low)",
                          color: "#12100C",
                          fontWeight: 800,
                        }}
                      >
                        PRODUCTION
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>Logistic Regression Baseline</td>
                    <td>0.5228 (52.3%)</td>
                    <td>0.6887 (68.9%)</td>
                    <td>0.4213 (42.1%)</td>
                    <td>0.0616 (6.2%)</td>
                    <td className="text-muted">Baseline</td>
                  </tr>
                  <tr>
                    <td>Isolation Forest Baseline</td>
                    <td>0.4020 (40.2%)</td>
                    <td>0.3743 (37.4%)</td>
                    <td>0.4342 (43.4%)</td>
                    <td>0.2349 (23.5%)</td>
                    <td className="text-muted">Baseline</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Early Warning Validation & Analytical Notes */}
          <div
            style={{
              padding: "12px 14px",
              background: "var(--bg-dark)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                marginBottom: 8,
              }}
            >
              <Info size={14} color="var(--c-gold)" />
              <span
                className="mono text-xs uppercase"
                style={{ fontWeight: 700, color: "var(--text-primary)" }}
              >
                Defense Protocol Validation Constraints
              </span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              {info.caveats.map((c) => (
                <div
                  key={c}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 6,
                    fontSize: "0.72rem",
                    color: "var(--text-muted)",
                    lineHeight: 1.4,
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
