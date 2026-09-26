import { useState, useEffect } from "react";
import {
  Eye,
  FileDown,
  FileSpreadsheet,
  Code2,
  Copy,
  Check,
} from "lucide-react";
import { apiFetch } from "../api";
import { stageColor, stageClass, formatTime, formatProb } from "../utils";
import { AppBadge, DirBadge, IdentityBadge, PacketStat } from "./Badges";

export default function ReportsView() {
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [stageDist, setStageDist] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    Promise.all([
      apiFetch("/dashboard/stats").catch(() => ({})),
      apiFetch("/alerts/stats").catch(() => ({})),
      apiFetch("/dashboard/stage-distribution").catch(() => []),
      apiFetch("/sessions?limit=50").catch(() => []),
      apiFetch("/alerts?limit=50").catch(() => []),
    ])
      .then(([st, as, sd, sess, al]) => {
        setStats(st || {});
        setAlertStats(as || {});
        setStageDist(Array.isArray(sd) ? sd : []);
        setSessions(Array.isArray(sess) ? sess : []);
        setAlerts(Array.isArray(al) ? al : []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const maxCount =
    stageDist.length > 0 ? Math.max(...stageDist.map((s) => s.count)) : 1;

  const downloadReport = async (format) => {
    setExporting(true);
    try {
      const baseUrl = import.meta.env.VITE_API_URL || "http://localhost:8000";
      const url = `${baseUrl}/reports/export/${format}`;
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      const ext =
        format === "csv" ? "csv" : format === "html" ? "html" : "json";
      a.download = `netforecast_forensic_report_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, "")}.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error(`Export ${format} failed:`, err);
      window.open(
        `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/reports/export/${format}`,
        "_blank",
      );
    } finally {
      setExporting(false);
    }
  };

  const copySummary = () => {
    const summary = {
      generated_at: new Date().toISOString(),
      total_sessions: stats.total_sessions || 0,
      total_flows: stats.total_flows || 0,
      at_risk_sessions: stats.at_risk_sessions || 0,
      total_alerts: alertStats.total || 0,
      unacknowledged_alerts: alertStats.unacknowledged || 0,
      critical_unacknowledged: alertStats.critical_unacknowledged || 0,
      stage_distribution: stageDist,
      top_sessions: sessions.slice(0, 10),
    };
    navigator.clipboard.writeText(JSON.stringify(summary, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="empty-state">
        <div className="loading-spinner" />
        <p>Compiling forensic report data...</p>
      </div>
    );
  }

  return (
    <>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "var(--sp-4)",
          flexWrap: "wrap",
          gap: "var(--sp-2)",
        }}
      >
        <div>
          <span className="section-label" style={{ marginBottom: 2 }}>
            Forensic Security Audit Report
          </span>
          <p className="text-sm text-muted">
            Comprehensive cyber attack progression & MITRE ATT&CK defense
            telemetry
          </p>
        </div>
        <div style={{ display: "flex", gap: "var(--sp-2)", flexWrap: "wrap" }}>
          <button
            className="btn btn-sm btn-outline"
            onClick={() =>
              window.open(
                `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/reports/view/html`,
                "_blank",
              )
            }
            title="Open printable forensic dossier in a new browser tab"
          >
            <Eye size={12} /> View Report
          </button>
          <button
            className="btn btn-sm btn-primary"
            onClick={() => downloadReport("html")}
            disabled={exporting}
            style={{ fontWeight: 700, padding: "4px 12px" }}
          >
            <FileDown size={12} /> Export Forensic Dossier
          </button>
          <button
            className="btn btn-sm btn-outline"
            onClick={() => downloadReport("csv")}
            disabled={exporting}
          >
            <FileSpreadsheet size={12} /> Export CSV
          </button>
          <button
            className="btn btn-sm btn-outline"
            onClick={() => downloadReport("json")}
            disabled={exporting}
          >
            <Code2 size={12} /> Export JSON
          </button>
          <button
            className="btn btn-sm btn-outline"
            onClick={copySummary}
            title="Copy JSON summary to clipboard"
          >
            {copied ? (
              <Check size={12} color="var(--severity-low)" />
            ) : (
              <Copy size={12} />
            )}
            {copied ? "Copied!" : "Copy JSON"}
          </button>
        </div>
      </div>

      <div className="report-grid mb-4">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Cycle Telemetry Summary</span>
          </div>
          <div className="panel-body">
            <div className="settings-row">
              <span className="settings-key">Total Monitored Sessions</span>
              <span className="settings-val">{stats.total_sessions || 0}</span>
            </div>
            <div className="settings-row">
              <span className="settings-key">Total Network Flows</span>
              <span className="settings-val">{stats.total_flows || 0}</span>
            </div>
            <div className="settings-row">
              <span className="settings-key">At-Risk Active Sessions</span>
              <span
                className="settings-val"
                style={{
                  color:
                    (stats.at_risk_sessions || 0) > 0
                      ? "var(--severity-critical)"
                      : undefined,
                }}
              >
                {stats.at_risk_sessions || 0}
              </span>
            </div>
            <div className="settings-row">
              <span className="settings-key">Total Security Alerts</span>
              <span className="settings-val">{alertStats.total || 0}</span>
            </div>
            <div className="settings-row">
              <span className="settings-key">Pending Triage</span>
              <span
                className="settings-val"
                style={{
                  color:
                    (alertStats.unacknowledged || 0) > 0
                      ? "var(--severity-high)"
                      : undefined,
                }}
              >
                {alertStats.unacknowledged || 0}
              </span>
            </div>
            <div className="settings-row">
              <span className="settings-key">Critical Priority Pending</span>
              <span
                className="settings-val"
                style={{
                  color:
                    (alertStats.critical_unacknowledged || 0) > 0
                      ? "var(--severity-critical)"
                      : undefined,
                }}
              >
                {alertStats.critical_unacknowledged || 0}
              </span>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">MITRE ATT&CK Stage Distribution</span>
          </div>
          <div className="panel-body">
            {stageDist.length === 0 ? (
              <div className="empty-state" style={{ padding: "var(--sp-6)" }}>
                <p>No stage data yet.</p>
              </div>
            ) : (
              stageDist.map((s) => (
                <div key={s.stage} className="stage-dist-bar">
                  <span className="stage-dist-label">{s.stage}</span>
                  <div className="stage-dist-track">
                    <div
                      className="stage-dist-fill"
                      style={{
                        width: `${(s.count / maxCount) * 100}%`,
                        background: stageColor(s.stage),
                      }}
                    />
                  </div>
                  <span className="stage-dist-count">{s.count}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="panel mb-4">
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span className="panel-title">Recorded Network Sessions Audit</span>
          <span className="panel-meta">
            {sessions.length} sessions recorded
          </span>
        </div>
        <div style={{ maxHeight: "320px", overflowY: "auto" }}>
          {sessions.length === 0 ? (
            <div className="empty-state" style={{ padding: "var(--sp-6)" }}>
              <p>No session data recorded in this cycle.</p>
            </div>
          ) : (
            <table className="data-table" style={{ fontSize: "0.68rem" }}>
              <thead>
                <tr>
                  <th>Application</th>
                  <th>Direction</th>
                  <th style={{ minWidth: "185px" }}>Source (Peer / Host)</th>
                  <th style={{ minWidth: "185px" }}>Destination</th>
                  <th>Packets (Tx / Rx)</th>
                  <th>Flow Count</th>
                  <th>Risk Level</th>
                  <th>Current Stage</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.session_key}>
                    <td>
                      <AppBadge
                        name={s.app_name || s.process_name}
                        processName={s.process_name}
                      />
                    </td>
                    <td>
                      <DirBadge dir={s.direction} />
                    </td>
                    <td>
                      <div className="ip-symmetric-cell">
                        <span className="ip-digits">{s.src_ip || "—"}</span>
                        <IdentityBadge identity={s.src_identity} />
                      </div>
                    </td>
                    <td>
                      <div className="ip-symmetric-cell">
                        <span className="ip-digits">{s.dst_ip || "—"}</span>
                        <IdentityBadge identity={s.dst_identity} />
                      </div>
                    </td>
                    <td>
                      <PacketStat
                        fwdPkts={s.tot_fwd_pkts}
                        bwdPkts={s.tot_bwd_pkts}
                      />
                    </td>
                    <td className="mono" style={{ fontWeight: 600 }}>
                      {s.flow_count}
                    </td>
                    <td>
                      <span
                        className="mono"
                        style={{
                          color:
                            (s.latest_risk_score || 0) > 0.5
                              ? "var(--severity-critical)"
                              : "var(--c-gold)",
                          fontWeight: 700,
                        }}
                      >
                        {formatProb(s.latest_risk_score || 0)}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`stage-badge ${stageClass(s.latest_stage)}`}
                      >
                        <span
                          className="radar-blip-dot"
                          style={{
                            background:
                              (s.latest_risk_score || 0) > 0.5 ||
                              (s.latest_stage && s.latest_stage !== "Benign")
                                ? "var(--c-red)"
                                : "var(--severity-low)",
                            marginRight: 4,
                          }}
                        />
                        {s.latest_stage || "Benign"}
                      </span>
                    </td>
                    <td className="mono text-muted">
                      {s.last_seen ? formatTime(s.last_seen) : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="panel">
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span className="panel-title">
            Incident Alerts & Mitigation Playbooks
          </span>
          <span className="panel-meta">{alerts.length} alerts generated</span>
        </div>
        <div style={{ maxHeight: "280px", overflowY: "auto" }}>
          {alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: "var(--sp-6)" }}>
              <p>No security alerts generated. Baseline is nominal.</p>
            </div>
          ) : (
            <table className="data-table" style={{ fontSize: "0.68rem" }}>
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Severity</th>
                  <th>Session Target</th>
                  <th>Predicted Stage</th>
                  <th>Infiltration Risk</th>
                  <th>Recommended Playbook Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td className="mono">#{a.id}</td>
                    <td>
                      <span
                        className={`severity-badge ${(a.severity || "medium").toLowerCase()}`}
                      >
                        {(a.severity || "medium").toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <code style={{ fontSize: "0.62rem" }}>
                        {a.session_key}
                      </code>
                    </td>
                    <td>
                      <span
                        className={`stage-badge ${stageClass(a.predicted_stage)}`}
                      >
                        {a.predicted_stage}
                      </span>
                    </td>
                    <td className="mono">
                      {formatProb(a.infiltration_prob || 0)}
                    </td>
                    <td
                      style={{
                        fontSize: "0.65rem",
                        color: "var(--text-secondary)",
                      }}
                    >
                      {a.recommended_action}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
