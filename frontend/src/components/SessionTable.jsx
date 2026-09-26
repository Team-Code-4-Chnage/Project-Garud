import { useState, useMemo, memo } from "react";
import { Database, Search, ArrowUpDown, ArrowDown } from "lucide-react";
import {
  DirBadge,
  IdentityBadge,
  AppBadge,
  PacketStat,
  CompromiseIndicator,
  KillChainCompact,
} from "./Badges";
import { stageClass, severityClass, formatTime, formatProb, stageIndex } from "../utils";

function SessionTable({
  sessions = [],
  loading = false,
  sortBy = "last_seen",
  setSortBy,
}) {
  const [filterText, setFilterText] = useState("");

  const filteredSessions = useMemo(() => {
    if (!filterText.trim()) return sessions;
    const q = filterText.toLowerCase();
    return sessions.filter(
      (s) =>
        (s.src_ip && s.src_ip.toLowerCase().includes(q)) ||
        (s.dst_ip && s.dst_ip.toLowerCase().includes(q)) ||
        (s.app_name && s.app_name.toLowerCase().includes(q)) ||
        (s.process_name && s.process_name.toLowerCase().includes(q)) ||
        (s.latest_stage && s.latest_stage.toLowerCase().includes(q)),
    );
  }, [sessions, filterText]);

  const renderSortIcon = (field) => {
    if (sortBy === field) {
      return (
        <ArrowDown
          size={11}
          style={{
            marginLeft: 3,
            verticalAlign: "middle",
            color: "var(--c-gold)",
          }}
        />
      );
    }
    return (
      <ArrowUpDown
        size={11}
        style={{ marginLeft: 3, verticalAlign: "middle", opacity: 0.4 }}
      />
    );
  };


  return (
    <div className="data-table-wrap">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "var(--sp-2) var(--sp-4)",
          background: "var(--bg-elevated)",
          borderBottom: "1px solid var(--border)",
          gap: "var(--sp-3)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            color: "var(--text-secondary)",
            fontSize: "0.78rem",
          }}
        >
          <Database size={14} color="var(--c-gold)" />
          <span>Tracked Network Sessions ({filteredSessions.length})</span>
        </div>

        <div style={{ position: "relative", width: "220px" }}>
          <Search
            size={13}
            style={{
              position: "absolute",
              left: 8,
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--text-muted)",
            }}
          />
          <input
            type="text"
            placeholder="Search IP, app, stage..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            style={{
              width: "100%",
              background: "var(--bg-dark)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              padding: "4px 8px 4px 26px",
              color: "var(--text-primary)",
              fontFamily: "var(--font-mono)",
              fontSize: "0.75rem",
              outline: "none",
            }}
          />
        </div>
      </div>

      {loading ? (
        <div className="empty-state">
          <div className="loading-spinner" />
          <p>Loading sessions...</p>
        </div>
      ) : filteredSessions.length === 0 ? (
        <div className="empty-state">
          <Database size={36} color="var(--text-muted)" />
          <p style={{ marginTop: "8px" }}>
            No active sessions recorded for this query.
          </p>
          <span className="mono text-sm text-muted">
            Awaiting network traffic flow telemetry.
          </span>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Application</th>
              <th>Direction</th>
              <th>Source (Peer / Host)</th>
              <th>Destination</th>
              <th>Packets (Tx / Rx)</th>
              <th
                style={{ cursor: "pointer" }}
                onClick={() => setSortBy?.("flow_count")}
              >
                Flows {renderSortIcon("flow_count")}
              </th>
              <th
                style={{ cursor: "pointer" }}
                onClick={() => setSortBy?.("latest_risk_score")}
              >
                Risk Level {renderSortIcon("latest_risk_score")}
              </th>
              <th>Attack Stage</th>
              <th>MITRE Kill Chain</th>
              <th
                style={{ cursor: "pointer" }}
                onClick={() => setSortBy?.("last_seen")}
              >
                Last Seen {renderSortIcon("last_seen")}
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredSessions.map((s) => {
              const isCompromised =
                stageIndex(s.latest_stage) >= 3 &&
                (s.latest_risk_score || 0) > 0.5;
              return (
                <tr
                  key={s.session_key}
                  style={{
                    background: isCompromised
                      ? `linear-gradient(90deg, rgba(201, 74, 69, 0.1), transparent)`
                      : undefined,
                  }}
                >
                  <td>
                    <AppBadge
                      appName={s.app_name}
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
                      proto="IP"
                    />
                  </td>
                  <td className="mono" style={{ fontWeight: 700 }}>
                    {s.flow_count}
                  </td>
                  <td>
                    <div className="risk-cell">
                      <div
                        className={`risk-bar ${severityClass(s.latest_risk_score)}`}
                      />
                      <span
                        style={{
                          fontWeight: 700,
                          color:
                            (s.latest_risk_score || 0) > 0.5
                              ? "var(--c-red)"
                              : "var(--text-primary)",
                        }}
                      >
                        {formatProb(s.latest_risk_score)}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                      }}
                    >
                      <span
                        className={`stage-badge ${stageClass(s.latest_stage)}`}
                      >
                        {s.latest_stage}
                      </span>
                      <CompromiseIndicator
                        stage={s.latest_stage}
                        riskScore={s.latest_risk_score}
                      />
                    </div>
                  </td>
                  <td>
                    <KillChainCompact
                      currentStage={s.max_stage_reached || s.latest_stage}
                    />
                  </td>
                  <td
                    className="mono text-sm"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {formatTime(s.last_seen)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default memo(SessionTable);
