import { useState, useEffect, memo } from "react";
import {
  ArrowDownToLine,
  ArrowUpFromLine,
  Network,
  Terminal,
  Globe,
  Cpu,
  Shield,
  Zap,
  Activity,
  FlaskConical,
  Wifi,
  Upload,
  RotateCcw,
  X,
  AlertTriangle,
  Server,
  Laptop,
  ChevronRight,
} from "lucide-react";
import { apiFetch } from "../api";
import { stageIndex, formatTime, STAGES } from "../utils";

const SOURCE_LABELS = {
  simulated: { label: "SIMULATED", color: "var(--c-gold)", icon: FlaskConical },
  live_capture: {
    label: "LIVE CAPTURE",
    color: "var(--severity-low)",
    icon: Wifi,
  },
  csv_upload: { label: "CSV UPLOAD", color: "var(--c-muted)", icon: Upload },
  api: { label: "API INGEST", color: "var(--text-secondary)", icon: Zap },
};

export const DirBadge = memo(function DirBadge({ dir }) {
  const cfg = {
    inbound: {
      label: "IN",
      color: "var(--c-red)",
      bg: "rgba(201, 74, 69, 0.14)",
      border: "rgba(201, 74, 69, 0.35)",
      icon: ArrowDownToLine,
    },
    outbound: {
      label: "OUT",
      color: "var(--c-gold)",
      bg: "rgba(214, 179, 106, 0.14)",
      border: "rgba(214, 179, 106, 0.35)",
      icon: ArrowUpFromLine,
    },
    internal: {
      label: "INT",
      color: "var(--severity-low)",
      bg: "rgba(88, 166, 104, 0.14)",
      border: "rgba(88, 166, 104, 0.35)",
      icon: Network,
    },
    unknown: {
      label: "?",
      color: "var(--text-muted)",
      bg: "rgba(142, 134, 121, 0.1)",
      border: "rgba(142, 134, 121, 0.25)",
      icon: Network,
    },
  }[dir] || {
    label: "?",
    color: "var(--text-muted)",
    bg: "rgba(142, 134, 121, 0.1)",
    border: "rgba(142, 134, 121, 0.25)",
    icon: Network,
  };
  const Icon = cfg.icon;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: "0.72rem",
        color: cfg.color,
        fontWeight: 700,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        padding: "2px 6px",
        borderRadius: "var(--radius-sm)",
        letterSpacing: "0.04em",
        fontFamily: "var(--font-mono)",
      }}
    >
      <Icon size={11} strokeWidth={2.4} /> {cfg.label}
    </span>
  );
});

export const IdentityBadge = memo(function IdentityBadge({ identity }) {
  const norm = identity || "EXT";
  const cfg = {
    HOST: {
      label: "HOST",
      class: "id-host",
      title: "Local Protected Host",
      icon: Laptop,
    },
    LAN_PEER: {
      label: "LAN",
      class: "id-lan",
      title: "Local Subnet Device",
      icon: Network,
    },
    NAT_PEER: {
      label: "NAT",
      class: "id-nat",
      title: "External / NAT Gateway",
      icon: Globe,
    },
    EXT: {
      label: "EXT",
      class: "id-peer",
      title: "External Network Endpoint",
      icon: Globe,
    },
    UNKNOWN: {
      label: "PEER",
      class: "id-peer",
      title: "Network Peer Endpoint",
      icon: Server,
    },
  }[norm] || {
    label:
      norm.length > 4 ? norm.substring(0, 4).toUpperCase() : norm.toUpperCase(),
    class: "id-peer",
    title: "Network Peer",
    icon: Server,
  };

  const Icon = cfg.icon;
  return (
    <span className={`id-badge ${cfg.class}`} title={cfg.title}>
      <Icon size={10} style={{ marginRight: 3, flexShrink: 0 }} />
      {cfg.label}
    </span>
  );
});

export const AppBadge = memo(function AppBadge({
  name: propName,
  appName,
  processName,
  iconType,
}) {
  const name = propName || appName || processName || "General Net";
  const nameLower = name.toLowerCase();
  let badgeClass = "app-generic";
  let Icon = Network;
  let color = "var(--text-secondary)";

  if (nameLower.includes("antigravity") || nameLower.includes("code")) {
    badgeClass = "app-antigravity";
    Icon = Terminal;
    color = "#A482E6";
  } else if (
    nameLower.includes("chrome") ||
    nameLower.includes("edge") ||
    nameLower.includes("brave") ||
    nameLower.includes("firefox")
  ) {
    badgeClass = "app-chrome";
    Icon = Globe;
    color = "#4B90D6";
  } else if (nameLower.includes("python") || nameLower.includes("uvicorn")) {
    badgeClass = "app-python";
    Icon = Cpu;
    color = "var(--severity-low)";
  } else if (
    nameLower.includes("system") ||
    nameLower.includes("kernel") ||
    nameLower.includes("svchost")
  ) {
    badgeClass = "app-system";
    Icon = Shield;
    color = "var(--text-secondary)";
  } else if (nameLower.includes("node") || nameLower.includes("vite")) {
    badgeClass = "app-node";
    Icon = Zap;
    color = "var(--c-gold)";
  } else if (nameLower.includes("ping") || iconType === "activity") {
    Icon = Activity;
    color = "#E57373";
  }

  return (
    <span
      className={`app-badge ${badgeClass}`}
      title={`Process: ${processName || name}`}
    >
      <Icon size={12} color={color} strokeWidth={2.2} />
      <span>{name}</span>
    </span>
  );
});

export const PacketStat = memo(function PacketStat({
  fwdPkts,
  bwdPkts,
  bytesPerSec,
  proto,
}) {
  const tx = Math.round(fwdPkts || 0);
  const rx = Math.round(bwdPkts || 0);
  const showSub = (proto && proto !== "IP") || (bytesPerSec && bytesPerSec > 0);
  return (
    <div className="packet-stat">
      <span className="packet-stat-primary">
        TX: {tx.toLocaleString()} • RX: {rx.toLocaleString()}
      </span>
      {showSub && (
        <span className="packet-stat-sub">
          {proto && proto !== "IP" ? proto : ""}
          {bytesPerSec ? ` ${(bytesPerSec / 1024).toFixed(1)} KB/s` : ""}
        </span>
      )}
    </div>
  );
});

export const SourceBadge = memo(function SourceBadge({ src }) {
  const cfg = SOURCE_LABELS[src] || SOURCE_LABELS.api;
  const Icon = cfg.icon;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: "0.68rem",
        color: cfg.color,
        fontWeight: 600,
        background: "rgba(58, 50, 40, 0.4)",
        padding: "2px 6px",
        borderRadius: "var(--radius-sm)",
        border: "1px solid var(--border-muted)",
        letterSpacing: "0.04em",
      }}
    >
      <Icon size={10} strokeWidth={2.2} />{" "}
      {src === "simulated"
        ? "SIM"
        : src === "live_capture"
          ? "LIVE"
          : src?.toUpperCase() || "API"}
    </span>
  );
});

export const CompromiseIndicator = memo(function CompromiseIndicator({
  stage,
  riskScore,
}) {
  const isCompromised = stageIndex(stage) >= 3 && (riskScore || 0) > 0.5;
  const isExfil = stage === "Exfiltration";
  if (!isCompromised) return null;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: "0.68rem",
        fontWeight: 800,
        color: isExfil ? "var(--c-red)" : "var(--c-gold)",
        background: isExfil
          ? "rgba(201, 74, 69, 0.15)"
          : "rgba(214, 179, 106, 0.15)",
        border: `1px solid ${isExfil ? "rgba(201, 74, 69, 0.4)" : "rgba(214, 179, 106, 0.4)"}`,
        padding: "2px 6px",
        borderRadius: "var(--radius-sm)",
        animation: "compromisePulse 1.2s ease-in-out infinite",
        letterSpacing: "0.05em",
      }}
    >
      <AlertTriangle size={10} strokeWidth={2.5} />
      {isExfil ? "COMPROMISED" : "UNDER ATTACK"}
    </span>
  );
});

export const KillChain = memo(function KillChain({
  currentStage,
  forecastStages = [],
}) {
  const currentIdx = stageIndex(currentStage);
  const forecastIdxSet = new Set(forecastStages.map((s) => stageIndex(s)));

  return (
    <div className="kill-chain-pipeline">
      {STAGES.map((stage, i) => {
        const isPassed = i < currentIdx;
        const isCurrent = i === currentIdx;
        const isForecast = forecastIdxSet.has(i);

        let statusText = "UNREACHED";
        let statusClass = "unreached";
        if (isCurrent) {
          statusText = "ACTIVE STAGE";
          statusClass = "current";
        } else if (isPassed) {
          statusText = "PASSED";
          statusClass = "passed";
        } else if (isForecast) {
          statusText = "PROJECTED RISK";
          statusClass = "forecast";
        }

        return (
          <div key={stage} className={`pipeline-step-wrap ${statusClass}`}>
            <div className={`pipeline-card ${statusClass}`}>
              <div className="pipeline-top">
                <span className="pipeline-num">0{i + 1}</span>
                <span className={`pipeline-badge ${statusClass}`}>
                  {statusText}
                </span>
              </div>
              <span className="pipeline-name">{stage}</span>
            </div>
            {i < STAGES.length - 1 && (
              <div
                className={`pipeline-arrow ${isPassed ? "passed" : isCurrent || isForecast ? "forecast" : ""}`}
              >
                <ChevronRight size={18} strokeWidth={2.5} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
});

export const KillChainCompact = memo(function KillChainCompact({
  currentStage,
}) {
  const currentIdx = stageIndex(currentStage);
  return (
    <div
      className="kill-chain-compact"
      title={`Stage Progression: ${currentStage}`}
    >
      {STAGES.map((s, i) => {
        const isPassed = i < currentIdx;
        const isCurrent = i === currentIdx;
        return (
          <div key={s} style={{ display: "inline-flex", alignItems: "center" }}>
            <span
              className={`kc-dot ${isPassed ? "passed" : ""} ${isCurrent ? "current" : ""}`}
              title={`${i + 1}. ${s}`}
            />
            {i < STAGES.length - 1 && (
              <span className={`kc-connector ${isPassed ? "passed" : ""}`} />
            )}
          </div>
        );
      })}
    </div>
  );
});

export const WellbeingModal = memo(function WellbeingModal({
  isOpen,
  onClose,
}) {
  const [cycles, setCycles] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setLoading(true);
    apiFetch("/system/cycles")
      .then((res) => {
        setCycles(Array.isArray(res) ? res : res?.cycles || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="wellbeing-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Activity size={18} color="var(--c-gold)" />
            <span className="panel-title" style={{ fontSize: "1rem" }}>
              Network Wellbeing Audit
            </span>
          </div>
          <button
            className="btn btn-sm btn-outline"
            onClick={onClose}
            aria-label="Close modal"
          >
            <X size={14} /> Close
          </button>
        </div>
        <div className="modal-body">
          <div className="wellbeing-score-banner">
            <Shield size={24} color="var(--severity-low)" />
            <div>
              <strong
                style={{ fontSize: "0.9rem", color: "var(--text-primary)" }}
              >
                Host Telemetry Integrity Audit
              </strong>
              <p
                style={{
                  fontSize: "0.78rem",
                  color: "var(--text-secondary)",
                  marginTop: 2,
                }}
              >
                Cycle records archive network sessions and temporal state
                partitions for post-incident MITRE forensic analysis.
              </p>
            </div>
          </div>

          {loading ? (
            <div className="empty-state">
              <div className="loading-spinner" />
              <p>Loading audit cycles...</p>
            </div>
          ) : cycles.length === 0 ? (
            <div className="empty-state">
              <RotateCcw size={24} color="var(--text-muted)" />
              <p>
                No archived cycles recorded yet. Active cycle is currently
                collecting telemetry.
              </p>
            </div>
          ) : (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "var(--sp-2)",
              }}
            >
              {cycles.map((c) => (
                <div key={c.cycle_id} className="cycle-card">
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <span
                      className="mono"
                      style={{
                        fontWeight: 700,
                        color: "var(--c-gold)",
                        fontSize: "0.85rem",
                      }}
                    >
                      {c.cycle_id}
                    </span>
                    <span className="mono text-xs text-muted">
                      {formatTime(c.started_at)}
                    </span>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      gap: "var(--sp-4)",
                      fontSize: "0.78rem",
                      color: "var(--text-secondary)",
                    }}
                  >
                    <span>
                      Flows:{" "}
                      <strong style={{ color: "var(--text-primary)" }}>
                        {c.flow_count ?? 0}
                      </strong>
                    </span>
                    <span>
                      Sessions:{" "}
                      <strong style={{ color: "var(--text-primary)" }}>
                        {c.session_count ?? 0}
                      </strong>
                    </span>
                    <span>
                      Threats:{" "}
                      <strong
                        style={{
                          color:
                            c.threat_count > 0
                              ? "var(--c-red)"
                              : "var(--severity-low)",
                        }}
                      >
                        {c.threat_count ?? 0}
                      </strong>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
});
