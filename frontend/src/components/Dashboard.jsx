import { useState, useEffect, useCallback } from "react";
import {
  Database,
  Activity,
  ShieldAlert,
  AlertTriangle,
  ArrowDownLeft,
  ArrowUpRight,
} from "lucide-react";
import { apiFetch } from "../api";
import SessionTable from "./SessionTable";

export default function Dashboard({
  systemMode,
  onSelectSession,
}) {
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [loading, setLoading] = useState(true);
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
