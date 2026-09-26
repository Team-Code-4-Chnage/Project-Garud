import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  Check,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  BellRing,
  Filter,
} from "lucide-react";
import { apiFetch, apiPost } from "../api";
import { stageClass, formatTime, formatProb } from "../utils";

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");

  const refresh = useCallback(() => {
    const params = filter === "all" ? "" : `?severity=${filter}`;
    apiFetch(`/alerts${params}`)
      .then((a) => {
        setAlerts(Array.isArray(a) ? a : []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [filter]);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 4000);
    return () => clearInterval(iv);
  }, [refresh]);

  const acknowledge = async (id) => {
    try {
      await apiPost(`/alerts/${id}/acknowledge`, {});
      refresh();
    } catch (e) {
      console.error("Failed to acknowledge alert:", e);
    }
  };

  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const unackCount = alerts.filter((a) => !a.acknowledged).length;

  return (
    <>
      {/* Top Filter and Stats Bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "var(--sp-4)",
          flexWrap: "wrap",
          gap: "var(--sp-3)",
        }}
      >
        <div
          style={{ display: "flex", alignItems: "center", gap: "var(--sp-2)" }}
        >
          <Filter size={14} color="var(--c-gold)" />
          <span
            className="section-label"
            style={{ marginBottom: 0, fontSize: "0.78rem" }}
          >
            Severity Filter:
          </span>
          <div className="tab-group">
            {[
              { id: "all", label: "All" },
              { id: "critical", label: "Critical" },
              { id: "high", label: "High" },
              { id: "medium", label: "Medium" },
            ].map((f) => (
              <button
                key={f.id}
                className={`tab-btn ${filter === f.id ? "active" : ""}`}
                onClick={() => setFilter(f.id)}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div
          style={{ display: "flex", alignItems: "center", gap: "var(--sp-2)" }}
        >
          {unackCount > 0 && (
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                fontSize: "0.74rem",
                fontWeight: 700,
                color: "var(--c-red)",
                background: "rgba(201, 74, 69, 0.14)",
                border: "1px solid rgba(201, 74, 69, 0.35)",
                padding: "3px 8px",
                borderRadius: "var(--radius-sm)",
              }}
            >
              <BellRing size={12} strokeWidth={2.4} />
              {unackCount} Pending Review
            </span>
          )}
          <span
            className="mono text-sm"
            style={{ color: "var(--text-secondary)" }}
          >
            Total Incidents:{" "}
            <strong style={{ color: "var(--text-primary)" }}>
              {alerts.length}
            </strong>
          </span>
        </div>
      </div>

      <div className="data-table-wrap">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            <p>Loading incident alerts...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <Shield size={36} color="var(--severity-low)" />
            <p
              style={{
                marginTop: "8px",
                color: "var(--severity-low)",
                fontWeight: 700,
              }}
            >
              Security Perimeter Clear
            </p>
            <span className="mono text-sm text-muted">
              No high-risk security thresholds breached in this category.
            </span>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Session Target</th>
                <th>Classified Stage</th>
                <th>Infiltration Risk</th>
                <th>Recommended Mitigation Playbook</th>
                <th>Incident Time</th>
                <th style={{ textAlign: "right" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id} style={{ cursor: "default" }}>
                  <td>
                    <span className={`severity-badge ${a.severity}`}>
                      {a.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="mono text-sm" style={{ fontWeight: 600 }}>
                    {a.session_key?.substring(0, 24) || "—"}
                  </td>
                  <td>
                    <span
                      className={`stage-badge ${stageClass(a.predicted_stage)}`}
                    >
                      {a.predicted_stage}
                    </span>
                  </td>
                  <td
                    className="mono"
                    style={{
                      fontWeight: 700,
                      color:
                        (a.infiltration_prob || 0) > 0.5
                          ? "var(--c-red)"
                          : "var(--c-gold)",
                    }}
                  >
                    {formatProb(a.infiltration_prob)}
                  </td>
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
                      <span className="alert-action">
                        {a.recommended_action ||
                          "Inspect flow signature and restrict source subnet."}
                      </span>
                    </div>
                  </td>
                  <td
                    className="mono text-sm"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {formatTime(a.created_at)}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {a.acknowledged ? (
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 4,
                          color: "var(--severity-low)",
                          fontSize: "0.74rem",
                          fontWeight: 700,
                          background: "rgba(88, 166, 104, 0.1)",
                          padding: "3px 8px",
                          borderRadius: "var(--radius-sm)",
                          border: "1px solid rgba(88, 166, 104, 0.3)",
                        }}
                      >
                        <CheckCircle2 size={12} /> Acknowledged
                      </span>
                    ) : (
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => acknowledge(a.id)}
                        title="Mark alert as acknowledged by analyst"
                      >
                        <Check size={11} /> Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

export { AlertPanel as AlertsView };
