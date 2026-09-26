import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Shield,
  Check,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  BellRing,
  Filter,
  Search,
  RotateCcw,
  SlidersHorizontal,
  CheckCheck,
  ArrowRight,
  Trash2,
} from "lucide-react";
import { apiFetch, apiPost } from "../api";
import { stageClass, formatTime, formatProb } from "../utils";
import { IdentityBadge } from "./Badges";

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    unacknowledged: 0,
    acknowledged: 0,
    critical_unacknowledged: 0,
    high_unacknowledged: 0,
    medium_unacknowledged: 0,
    low_unacknowledged: 0,
  });
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Filters
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [stageFilter, setStageFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [isAcknowledgingAll, setIsAcknowledgingAll] = useState(false);

  const fetchStats = useCallback(async () => {
    try {
      const s = await apiFetch("/alerts/stats");
      if (s) setStats(s);
    } catch {}
  }, []);

  const refresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      // Fetch full alert ledger (up to 500) so all client-side filters respond in 0ms
      const res = await apiFetch("/alerts?limit=500");
      setAlerts(Array.isArray(res) ? res : []);
      fetchStats();
    } catch (e) {
      console.error("Failed to load alerts:", e);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [fetchStats]);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 5000);
    return () => clearInterval(iv);
  }, [refresh]);

  // Compute live category and severity counts from current alerts in memory
  const counts = useMemo(() => {
    const c = {
      total: alerts.length,
      unack: 0,
      ack: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      recon: 0,
      initial: 0,
      lateral: 0,
      c2: 0,
      exfil: 0,
    };
    alerts.forEach((a) => {
      if (a.acknowledged) c.ack++;
      else c.unack++;
      const sev = (a.severity || "").toLowerCase();
      if (sev === "critical") c.critical++;
      else if (sev === "high") c.high++;
      else if (sev === "medium") c.medium++;
      else if (sev === "low") c.low++;

      const stg = (a.predicted_stage || "").toLowerCase();
      if (stg.includes("recon")) c.recon++;
      else if (stg.includes("initial")) c.initial++;
      else if (stg.includes("lateral")) c.lateral++;
      else if (stg.includes("c2")) c.c2++;
      else if (stg.includes("exfil")) c.exfil++;
    });
    return c;
  }, [alerts]);

  const acknowledge = async (id) => {
    // Instant optimistic UI update
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, acknowledged: true } : a)),
    );
    setStats((prev) => ({
      ...prev,
      unacknowledged: Math.max(0, prev.unacknowledged - 1),
      acknowledged: prev.acknowledged + 1,
    }));

    try {
      await apiPost(`/alerts/${id}/acknowledge`, {});
      fetchStats();
    } catch (e) {
      console.error("Failed to acknowledge alert:", e);
      refresh();
    }
  };

  const handleAcknowledgeAll = async () => {
    if (counts.unack === 0) return;
    if (
      !window.confirm(
        `Acknowledge all ${counts.unack} pending incident alert(s)?`,
      )
    ) {
      return;
    }

    setIsAcknowledgingAll(true);
    setAlerts((prev) => prev.map((a) => ({ ...a, acknowledged: true })));
    setStats((prev) => ({
      ...prev,
      acknowledged: prev.total,
      unacknowledged: 0,
      critical_unacknowledged: 0,
      high_unacknowledged: 0,
      medium_unacknowledged: 0,
      low_unacknowledged: 0,
    }));

    try {
      await apiPost("/alerts/acknowledge-all", {});
      fetchStats();
    } catch (e) {
      console.error("Failed to bulk acknowledge alerts:", e);
      refresh();
    } finally {
      setIsAcknowledgingAll(false);
    }
  };

  const handleClearAll = async () => {
    if (!window.confirm("Purge all incident alerts from database?")) return;
    try {
      await apiPost("/alerts/clear", {});
      setAlerts([]);
      fetchStats();
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  };

  const handleResetFilters = () => {
    setSeverityFilter("all");
    setStatusFilter("all");
    setStageFilter("all");
    setSearchQuery("");
  };

  // Instant zero-latency responsive filtering in memory
  const filteredAlerts = useMemo(() => {
    let list = alerts;
    if (severityFilter !== "all") {
      list = list.filter(
        (a) =>
          (a.severity || "").toLowerCase() === severityFilter.toLowerCase(),
      );
    }
    if (statusFilter === "unack") {
      list = list.filter((a) => !a.acknowledged);
    } else if (statusFilter === "ack") {
      list = list.filter((a) => a.acknowledged);
    }
    if (stageFilter !== "all") {
      list = list.filter((a) =>
        (a.predicted_stage || "")
          .toLowerCase()
          .includes(stageFilter.toLowerCase()),
      );
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (a) =>
          (a.session_key && a.session_key.toLowerCase().includes(q)) ||
          (a.predicted_stage && a.predicted_stage.toLowerCase().includes(q)) ||
          (a.recommended_action &&
            a.recommended_action.toLowerCase().includes(q)) ||
          (a.severity && a.severity.toLowerCase().includes(q)),
      );
    }
    return list;
  }, [alerts, severityFilter, statusFilter, stageFilter, searchQuery]);

  const parseSessionKey = (key) => {
    if (!key) return { src: "unknown", dst: "unknown" };
    const [ips] = key.split("@");
    const [src, dst] = (ips || "").split("->");
    return { src: src || "unknown", dst: dst || "unknown" };
  };

  return (
    <div className="alerts-container">
      {/* Overview Metric Cards Bar */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
          gap: "var(--sp-3)",
          marginBottom: "var(--sp-4)",
        }}
      >
        <div className="card" style={{ padding: "12px 16px" }}>
          <div className="stat-card-label">TOTAL INCIDENTS</div>
          <div
            className="stat-card-value mono"
            style={{ fontSize: "1.6rem", color: "var(--text-primary)" }}
          >
            {counts.total}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            Audit log records captured
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div
            className="stat-card-label"
            style={{
              color: counts.unack > 0 ? "var(--c-red)" : "var(--severity-low)",
              display: "flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            {counts.unack > 0 && (
              <span
                className="live-pulse-blip"
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--c-red)",
                }}
              />
            )}
            PENDING REVIEW
          </div>
          <div
            className="stat-card-value mono"
            style={{
              fontSize: "1.6rem",
              color: counts.unack > 0 ? "var(--c-red)" : "var(--severity-low)",
            }}
          >
            {counts.unack}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            {counts.unack > 0
              ? "Actionable incidents requiring acknowledgment"
              : "Perimeter nominal — all clear"}
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div className="stat-card-label" style={{ color: "var(--c-red)" }}>
            CRITICAL SEVERITY
          </div>
          <div
            className="stat-card-value mono"
            style={{
              fontSize: "1.6rem",
              color: counts.critical > 0 ? "var(--c-red)" : "var(--text-muted)",
            }}
          >
            {counts.critical}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            High-urgency breach indicators
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div
            className="stat-card-label"
            style={{ color: "var(--severity-low)" }}
          >
            ACKNOWLEDGED INCIDENTS
          </div>
          <div
            className="stat-card-value mono"
            style={{ fontSize: "1.6rem", color: "var(--severity-low)" }}
          >
            {counts.ack}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            Analyst confirmed & triaged
          </div>
        </div>
      </div>

      {/* Main Filter & Action Controls Bar */}
      <div
        className="card"
        style={{
          padding: "14px 16px",
          marginBottom: "var(--sp-4)",
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 10,
          }}
        >
          {/* Instant Search Box */}
          <div style={{ position: "relative", minWidth: 260, flex: 1 }}>
            <Search
              size={13}
              style={{
                position: "absolute",
                left: 10,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--text-muted)",
              }}
            />
            <input
              type="text"
              placeholder="Search target IP, MITRE stage, playbook action, or severity..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                background: "var(--c-dark-base)",
                border: "1px solid var(--border-dark)",
                borderRadius: "var(--radius-sm)",
                padding: "6px 10px 6px 30px",
                color: "var(--text-primary)",
                fontFamily: "var(--font-mono)",
                fontSize: "0.76rem",
                outline: "none",
              }}
            />
          </div>

          {/* Action Toolbar */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            <button
              className="btn btn-sm btn-outline"
              onClick={refresh}
              disabled={isRefreshing}
              title="Force reload latest alerts from backend"
              style={{ display: "inline-flex", alignItems: "center", gap: 5 }}
            >
              <RotateCcw
                size={11}
                className={isRefreshing ? "spin-animation" : ""}
              />
              REFRESH
            </button>

            {counts.unack > 0 && (
              <button
                className="btn btn-sm btn-primary"
                onClick={handleAcknowledgeAll}
                disabled={isAcknowledgingAll}
                title="Mark all pending alerts as acknowledged"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  background: "var(--c-gold)",
                  color: "#1A1610",
                  fontWeight: 700,
                }}
              >
                <CheckCheck size={13} />
                ACKNOWLEDGE ALL ({counts.unack})
              </button>
            )}

            {counts.total > 0 && (
              <button
                className="btn btn-sm btn-outline"
                onClick={handleClearAll}
                title="Clear all alerts from database"
                style={{ display: "inline-flex", alignItems: "center", gap: 5 }}
              >
                <Trash2 size={11} />
                CLEAR ALL
              </button>
            )}
          </div>
        </div>

        {/* Severity & Status & Stage Filter Buttons */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
            flexWrap: "wrap",
            paddingTop: 8,
            borderTop: "1px solid var(--border-dark)",
            fontSize: "0.74rem",
          }}
        >
          {/* Status Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                color: "var(--text-muted)",
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
              }}
            >
              STATUS:
            </span>
            <div className="tab-group" style={{ margin: 0 }}>
              {[
                { id: "all", label: "ALL", count: counts.total },
                {
                  id: "unack",
                  label: "PENDING",
                  count: counts.unack,
                  highlight: counts.unack > 0,
                },
                { id: "ack", label: "ACKNOWLEDGED", count: counts.ack },
              ].map((f) => (
                <button
                  key={f.id}
                  className={`tab-btn ${statusFilter === f.id ? "active" : ""}`}
                  onClick={() => setStatusFilter(f.id)}
                  style={{
                    padding: "3px 9px",
                    fontSize: "0.72rem",
                    color:
                      f.highlight && statusFilter !== f.id
                        ? "var(--c-red)"
                        : undefined,
                  }}
                >
                  {f.label} ({f.count})
                </button>
              ))}
            </div>
          </div>

          {/* Severity Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                color: "var(--text-muted)",
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
              }}
            >
              SEVERITY:
            </span>
            <div className="tab-group" style={{ margin: 0 }}>
              {[
                { id: "all", label: "ALL", count: counts.total },
                {
                  id: "critical",
                  label: "CRITICAL",
                  color: "var(--c-red)",
                  count: counts.critical,
                },
                {
                  id: "high",
                  label: "HIGH",
                  color: "#E67E22",
                  count: counts.high,
                },
                {
                  id: "medium",
                  label: "MEDIUM",
                  color: "var(--c-gold)",
                  count: counts.medium,
                },
                {
                  id: "low",
                  label: "LOW",
                  color: "var(--severity-low)",
                  count: counts.low,
                },
              ].map((f) => (
                <button
                  key={f.id}
                  className={`tab-btn ${severityFilter === f.id ? "active" : ""}`}
                  onClick={() => setSeverityFilter(f.id)}
                  style={{
                    padding: "3px 9px",
                    fontSize: "0.72rem",
                    color:
                      f.color && severityFilter !== f.id ? f.color : undefined,
                  }}
                >
                  {f.label} ({f.count})
                </button>
              ))}
            </div>
          </div>

          {/* MITRE Stage Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                color: "var(--text-muted)",
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
              }}
            >
              STAGE:
            </span>
            <div className="tab-group" style={{ margin: 0 }}>
              {[
                { id: "all", label: "ALL" },
                { id: "recon", label: `RECON (${counts.recon})` },
                { id: "initial", label: `INITIAL (${counts.initial})` },
                { id: "lateral", label: `LATERAL (${counts.lateral})` },
                { id: "c2", label: `C2 (${counts.c2})` },
                { id: "exfil", label: `EXFIL (${counts.exfil})` },
              ].map((f) => (
                <button
                  key={f.id}
                  className={`tab-btn ${stageFilter === f.id ? "active" : ""}`}
                  onClick={() => setStageFilter(f.id)}
                  style={{ padding: "3px 9px", fontSize: "0.72rem" }}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          {/* Clear Filters Reset */}
          {(severityFilter !== "all" ||
            statusFilter !== "all" ||
            stageFilter !== "all" ||
            searchQuery.trim()) && (
            <button
              className="btn btn-sm btn-outline"
              onClick={handleResetFilters}
              style={{
                padding: "2px 8px",
                fontSize: "0.68rem",
                color: "var(--c-gold)",
                borderColor: "rgba(214, 179, 106, 0.4)",
              }}
            >
              RESET FILTERS
            </button>
          )}
        </div>
      </div>

      {/* Incidents Table Wrap */}
      <div className="data-table-wrap">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            <p
              style={{
                marginTop: 12,
                fontFamily: "var(--font-mono)",
                fontSize: "0.85rem",
              }}
            >
              Loading security incident telemetry...
            </p>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon-shield">
              <Shield size={32} color="var(--severity-low)" strokeWidth={2.2} />
            </div>
            <div className="empty-title">
              <span
                className="live-pulse-blip"
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: "var(--severity-low)",
                }}
              />
              PERIMETER SECURE &bull; ZERO ACTIVE THREAT BREACHES
            </div>
            <div className="empty-subtitle">
              {alerts.length === 0
                ? "All network ingress and egress telemetry flows are operating within authorized baseline thresholds. No high-risk security incidents or MITRE ATT&CK patterns detected."
                : "No security incident alerts match your active filter settings. Reset filters to inspect all recorded events."}
            </div>
            <div className="empty-actions">
              {(severityFilter !== "all" ||
                statusFilter !== "all" ||
                stageFilter !== "all" ||
                searchQuery.trim()) && (
                <button
                  className="btn btn-sm btn-outline"
                  onClick={handleResetFilters}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                  }}
                >
                  <RotateCcw size={11} /> RESET ACTIVE FILTERS
                </button>
              )}
            </div>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: "95px" }}>Severity</th>
                <th style={{ minWidth: "220px" }}>Session / Host Endpoint</th>
                <th style={{ width: "160px" }}>MITRE ATT&CK Stage</th>
                <th style={{ width: "120px" }}>Infiltration Risk</th>
                <th>Recommended Mitigation Playbook</th>
                <th style={{ width: "140px" }}>Incident Time (UTC)</th>
                <th style={{ width: "130px", textAlign: "right" }}>
                  Status / Action
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((a) => {
                const { src, dst } = parseSessionKey(a.session_key);
                const sev = (a.severity || "medium").toLowerCase();
                const prob = a.infiltration_prob || 0.0;
                const isHighRisk = prob >= 0.5;

                return (
                  <tr
                    key={a.id}
                    style={{
                      cursor: "default",
                      background: a.acknowledged
                        ? undefined
                        : "rgba(201, 74, 69, 0.03)",
                    }}
                  >
                    {/* Severity */}
                    <td>
                      <span className={`severity-badge ${sev}`}>
                        {sev.toUpperCase()}
                      </span>
                    </td>

                    {/* Session Host Endpoints with Straight Column Symmetry */}
                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          fontFamily: "var(--font-mono)",
                          fontSize: "0.78rem",
                        }}
                      >
                        <span className="ip-symmetric-cell">
                          <span className="ip-digits">{src}</span>
                          <IdentityBadge ip={src} />
                        </span>
                        <ArrowRight
                          size={11}
                          color="var(--c-gold)"
                          style={{ flexShrink: 0 }}
                        />
                        <span className="ip-symmetric-cell">
                          <span className="ip-digits">{dst}</span>
                          <IdentityBadge ip={dst} />
                        </span>
                      </div>
                    </td>

                    {/* MITRE Stage with Radar Blip */}
                    <td>
                      <span
                        className={`stage-badge ${stageClass(a.predicted_stage)}`}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 5,
                        }}
                      >
                        {!a.acknowledged && (
                          <span
                            className="live-pulse-blip"
                            style={{
                              width: 6,
                              height: 6,
                              borderRadius: "50%",
                              background: "currentColor",
                            }}
                          />
                        )}
                        {a.predicted_stage || "General Threat"}
                      </span>
                    </td>

                    {/* Infiltration Risk */}
                    <td>
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 3,
                        }}
                      >
                        <span
                          className="mono"
                          style={{
                            fontWeight: 700,
                            color: isHighRisk
                              ? "var(--c-red)"
                              : "var(--c-gold)",
                            fontSize: "0.82rem",
                          }}
                        >
                          {formatProb(prob)}
                        </span>
                        <div
                          style={{
                            width: "100%",
                            height: 3,
                            background: "rgba(255, 255, 255, 0.08)",
                            borderRadius: 2,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${Math.min(100, Math.max(0, prob * 100))}%`,
                              height: "100%",
                              background: isHighRisk
                                ? "var(--c-red)"
                                : "var(--c-gold)",
                            }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Recommended Mitigation Playbook */}
                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "flex-start",
                          gap: 6,
                        }}
                      >
                        <AlertTriangle
                          size={13}
                          color="var(--c-gold)"
                          style={{ marginTop: 2, flexShrink: 0 }}
                        />
                        <span
                          className="alert-action"
                          style={{ fontSize: "0.76rem", lineHeight: 1.35 }}
                        >
                          {a.recommended_action ||
                            "Inspect flow signature, check firewall logs, and isolate host."}
                        </span>
                      </div>
                    </td>

                    {/* Incident Time */}
                    <td
                      className="mono text-sm"
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.74rem",
                      }}
                    >
                      {formatTime(a.created_at)}
                    </td>

                    {/* Status & Action */}
                    <td style={{ textAlign: "right" }}>
                      {a.acknowledged ? (
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 4,
                            color: "var(--severity-low)",
                            fontSize: "0.72rem",
                            fontWeight: 700,
                            background: "rgba(88, 166, 104, 0.1)",
                            padding: "3px 8px",
                            borderRadius: "var(--radius-sm)",
                            border: "1px solid rgba(88, 166, 104, 0.3)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          <CheckCircle2 size={11} /> Triaged
                        </span>
                      ) : (
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() => acknowledge(a.id)}
                          title="Mark incident as acknowledged by security analyst"
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 4,
                            padding: "3px 8px",
                            fontSize: "0.72rem",
                          }}
                        >
                          <Check size={11} /> Acknowledge
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export { AlertPanel as AlertsView };
