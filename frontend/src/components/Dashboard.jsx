import { useState, useEffect, useCallback } from "react";
import {
  FlaskConical,
  Database,
  Activity,
  ShieldAlert,
  AlertTriangle,
  ArrowDownLeft,
  ArrowUpRight,
  X,
  Radio,
  Play,
  Square,
} from "lucide-react";
import { apiFetch } from "../api";
import SessionTable from "./SessionTable";

export default function Dashboard({
  systemMode,
  onSelectSession,
  captureRunning = false,
  simulatorRunning = false,
  onStartLiveCapture,
  onStopLiveCapture,
  onStartSimulator,
}) {
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [simBannerDismissed, setSimBannerDismissed] = useState(false);
  const [liveBannerDismissed, setLiveBannerDismissed] = useState(false);
  const [sortBy, setSortBy] = useState("last_seen");

  const ACTIVE_WINDOW_SECONDS = 300;

  const refresh = useCallback(() => {
    const srcParam = systemMode === "live" ? "&source=live" : "";
    Promise.all([
      apiFetch(
        `/sessions?limit=100&sort_by=${sortBy}&active_within_seconds=${ACTIVE_WINDOW_SECONDS}${srcParam}`,
      ),
      apiFetch("/dashboard/stats"),
      apiFetch("/alerts/stats"),
    ])
      .then(async ([s, st, as]) => {
        let sessionList = s;
        // If strict 300s window returned 0 sessions, fallback to full recent sessions so dashboard is never blank
        if (
          (!sessionList || sessionList.length === 0) &&
          (st?.total_sessions || 0) > 0
        ) {
          try {
            const fallback = await apiFetch(
              `/sessions?limit=50&sort_by=${sortBy}${srcParam}`,
            );
            if (fallback && fallback.length > 0) {
              sessionList = fallback;
            }
          } catch {}
        }
        setSessions(sessionList || []);
        setStats(st || {});
        setAlertStats(as || {});
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [sortBy, systemMode]);

  const activeAtRisk = sessions.filter(
    (s) => (s.latest_risk_score || 0) > 0.5,
  ).length;

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 3000);
    return () => clearInterval(iv);
  }, [refresh]);

  return (
    <>
      {systemMode === "live" && !liveBannerDismissed && (
        <div
          style={{
            background: captureRunning
              ? "linear-gradient(90deg, rgba(88, 166, 104, 0.12), rgba(30, 45, 35, 0.4))"
              : "linear-gradient(90deg, rgba(88, 166, 104, 0.08), rgba(20, 30, 25, 0.4))",
            border: `1px solid ${captureRunning ? "var(--severity-low)" : "rgba(88, 166, 104, 0.4)"}`,
            borderRadius: "var(--radius)",
            padding: "var(--sp-3) var(--sp-4)",
            marginBottom: "var(--sp-4)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "var(--sp-3)",
            boxShadow: "0 2px 10px rgba(0,0,0,0.25)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 260 }}>
            <Radio
              size={16}
              color="var(--severity-low)"
              strokeWidth={2.4}
              style={{
                animation: captureRunning ? "pulse 2s infinite" : "none",
              }}
            />
            <span
              className="mono"
              style={{
                fontSize: "0.82rem",
                color: "var(--severity-low)",
                letterSpacing: "0.02em",
              }}
            >
              {captureRunning ? (
                <>
                  <strong>LIVE PACKET CAPTURE ACTIVE</strong> — Host network telemetry is actively streaming into the LSTM World Model.
                </>
              ) : (
                <>
                  <strong>LIVE TELEMETRY MODE</strong> — Host sniffer is currently idle. Click below to begin live traffic ingestion.
                </>
              )}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {captureRunning ? (
              <button
                className="btn btn-sm btn-danger"
                onClick={onStopLiveCapture}
                style={{ fontSize: "0.72rem", padding: "4px 12px" }}
              >
                <Square size={11} fill="currentColor" /> STOP CAPTURE
              </button>
            ) : (
              <button
                className="btn btn-sm btn-primary"
                onClick={() => onStartLiveCapture?.()}
                style={{ fontSize: "0.72rem", padding: "4px 14px" }}
              >
                <Play size={11} fill="currentColor" /> START LIVE CAPTURE
              </button>
            )}

            <button
              className="btn btn-sm"
              onClick={() => setLiveBannerDismissed(true)}
              style={{ padding: "4px 8px" }}
              title="Dismiss banner"
            >
              <X size={12} />
            </button>
          </div>
        </div>
      )}
      {systemMode === "simulated" &&
        stats.has_simulated_data &&
        !simBannerDismissed && (
          <div
            style={{
              background:
                "linear-gradient(90deg, rgba(214, 179, 106, 0.12), rgba(58, 50, 40, 0.4))",
              border: "1px solid var(--c-gold)",
              borderRadius: "var(--radius)",
              padding: "var(--sp-3) var(--sp-4)",
              marginBottom: "var(--sp-4)",
              display: "flex",
              alignItems: "center",
              gap: "var(--sp-3)",
              boxShadow: "0 2px 10px rgba(0,0,0,0.25)",
            }}
          >
            <FlaskConical size={16} color="var(--c-gold)" strokeWidth={2.4} />
            <span
              className="mono"
              style={{
                fontSize: "0.82rem",
                color: "var(--c-gold)",
                flex: 1,
                letterSpacing: "0.02em",
              }}
            >
              {simulatorRunning ? (
                <>
                  <strong>SIMULATION ACTIVE</strong> — Synthetic network attack
                  traffic generated by <code>traffic_simulator.py</code> is actively
                  being ingested.
                </>
              ) : (
                <>
                  <strong>SIMULATION MODE</strong> — Simulator is idle. Click below to
                  inject synthetic MITRE attack traffic scenarios.
                </>
              )}
            </span>
            {!simulatorRunning && onStartSimulator && (
              <button
                className="btn btn-sm btn-primary"
                onClick={() => onStartSimulator()}
                style={{ fontSize: "0.72rem", padding: "4px 12px" }}
              >
                <Play size={11} fill="currentColor" /> LAUNCH SIMULATOR
              </button>
            )}
            <button
              className="btn btn-sm"
              onClick={() => setSimBannerDismissed(true)}
            >
              <X size={12} /> Dismiss
            </button>
          </div>
        )}

      {/* Primary KPI Stats Grid */}
      <div className="stats-bar">
        <div className="stat-card">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span className="stat-card-label">Total Monitored Sessions</span>
            <Database size={15} color="var(--text-muted)" />
          </div>
          <div className="stat-card-value">
            {(stats.total_sessions || 0).toLocaleString()}
          </div>
        </div>

        <div className="stat-card">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span className="stat-card-label">Ingested Flows</span>
            <Activity size={15} color="var(--c-gold)" />
          </div>
          <div className="stat-card-value">
            {(stats.total_flows || 0).toLocaleString()}
          </div>
        </div>

        <div
          className="stat-card"
          style={{
            borderColor:
              activeAtRisk > 0 ? "rgba(201, 74, 69, 0.4)" : undefined,
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
              className="stat-card-label"
              style={{ color: activeAtRisk > 0 ? "var(--c-red)" : undefined }}
            >
              At-Risk Sessions
            </span>
            <ShieldAlert
              size={15}
              color={activeAtRisk > 0 ? "var(--c-red)" : "var(--text-muted)"}
            />
          </div>
          <div
            className="stat-card-value"
            style={{ color: activeAtRisk > 0 ? "var(--c-red)" : undefined }}
          >
            {activeAtRisk}
          </div>
        </div>

        <div
          className="stat-card"
          style={{
            borderColor:
              (alertStats.unacknowledged || 0) > 0
                ? "rgba(214, 179, 106, 0.4)"
                : undefined,
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
              className="stat-card-label"
              style={{
                color:
                  (alertStats.unacknowledged || 0) > 0
                    ? "var(--c-gold)"
                    : undefined,
              }}
            >
              Pending Alerts
            </span>
            <AlertTriangle
              size={15}
              color={
                (alertStats.unacknowledged || 0) > 0
                  ? "var(--c-gold)"
                  : "var(--text-muted)"
              }
            />
          </div>
          <div
            className="stat-card-value"
            style={{
              color:
                (alertStats.unacknowledged || 0) > 0
                  ? "var(--c-gold)"
                  : undefined,
            }}
          >
            {alertStats.unacknowledged || 0}
          </div>
        </div>

        {stats.direction_breakdown && (
          <div className="stat-card">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span className="stat-card-label">Inbound Flows (Rx)</span>
              <ArrowDownLeft size={15} color="var(--c-red)" />
            </div>
            <div
              className="stat-card-value"
              style={{ color: "var(--c-red)", fontSize: "1.4rem" }}
            >
              {(stats.direction_breakdown.inbound || 0).toLocaleString()}
            </div>
          </div>
        )}

        {stats.direction_breakdown && (
          <div className="stat-card">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span className="stat-card-label">Outbound Flows (Tx)</span>
              <ArrowUpRight size={15} color="var(--c-gold)" />
            </div>
            <div
              className="stat-card-value"
              style={{ color: "var(--c-gold)", fontSize: "1.4rem" }}
            >
              {(stats.direction_breakdown.outbound || 0).toLocaleString()}
            </div>
          </div>
        )}
      </div>

      {/* Mode Status */}
      <div
        style={{
          display: "flex",
          justifyContent: "flex-end",
          alignItems: "center",
          marginBottom: "var(--sp-3)",
          flexWrap: "wrap",
          gap: "var(--sp-2)",
        }}
      >
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            padding: "4px 12px",
            borderRadius: "var(--radius)",
            border: `1px solid ${systemMode === "live" ? "rgba(88, 166, 104, 0.4)" : "rgba(214, 179, 106, 0.4)"}`,
            background:
              systemMode === "live"
                ? "rgba(88, 166, 104, 0.1)"
                : "rgba(214, 179, 106, 0.1)",
            fontSize: "0.75rem",
            fontWeight: 700,
            letterSpacing: "0.04em",
            color:
              systemMode === "live" ? "var(--severity-low)" : "var(--c-gold)",
          }}
        >
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background:
                systemMode === "live"
                  ? captureRunning
                    ? "var(--severity-low)"
                    : "var(--text-muted)"
                  : simulatorRunning
                    ? "var(--c-gold)"
                    : "var(--text-muted)",
              boxShadow: `0 0 8px ${
                systemMode === "live"
                  ? captureRunning
                    ? "var(--severity-low)"
                    : "transparent"
                  : simulatorRunning
                    ? "var(--c-gold)"
                    : "transparent"
              }`,
            }}
          />
          {systemMode === "live"
            ? captureRunning
              ? "Live Sniffer: Active Ingestion"
              : "Live Mode: Sniffer Idle"
            : simulatorRunning
              ? "Simulation: Generating Traffic"
              : "Simulation: Idle"}
        </div>
      </div>

      <SessionTable
        sessions={sessions}
        loading={loading}
        sortBy={sortBy}
        setSortBy={setSortBy}
        onSelectSession={onSelectSession}
      />
    </>
  );
}
