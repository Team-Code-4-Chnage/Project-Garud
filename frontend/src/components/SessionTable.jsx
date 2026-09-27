import { useState, useMemo, memo } from "react";
import {
  Database,
  Search,
  ArrowUpDown,
  ArrowDown,
  ChevronRight,
  ChevronDown,
  Layers,
} from "lucide-react";
import {
  DirBadge,
  IdentityBadge,
  AppBadge,
  PacketStat,
  CompromiseIndicator,
  KillChainCompact,
} from "./Badges";
import {
  stageClass,
  severityClass,
  formatTime,
  formatProb,
  stageIndex,
} from "../utils";

// backend/app/process_resolver.py emits these placeholder labels when it cannot resolve a real
// process (see resolve_process): app_name "General Traffic" or "Port {n} ({proto})", process_name
// "Unknown" or "Port {n}". A port number is not a stable application identity -- unrelated hosts
// frequently reuse the same ephemeral port -- so these must never be grouped together, only real,
// resolved app/process names.
function isResolvedAppName(name) {
  return (
    Boolean(name) && name !== "General Traffic" && !/^Port \d+ \(/.test(name)
  );
}
function isResolvedProcessName(name) {
  return Boolean(name) && name !== "Unknown" && !/^Port \d+$/.test(name);
}

function groupKeyOf(s) {
  if (isResolvedAppName(s.app_name)) return `app:${s.app_name}`;
  if (isResolvedProcessName(s.process_name)) return `proc:${s.process_name}`;
  return `ip:${s.src_ip || "?"}`;
}

function groupSessions(sessions) {
  const groups = new Map();
  for (const s of sessions) {
    const key = groupKeyOf(s);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  }
  return Array.from(groups.entries()).map(([key, rows]) => {
    const best = rows.reduce((a, b) => {
      const ra = a.latest_risk_score || 0;
      const rb = b.latest_risk_score || 0;
      if (rb !== ra) return rb > ra ? b : a;
      return (b.last_seen || "") > (a.last_seen || "") ? b : a;
    });
    return {
      key,
      count: rows.length,
      rows: [...rows].sort(
        (a, b) => (b.latest_risk_score || 0) - (a.latest_risk_score || 0),
      ),
      app_name: best.app_name,
      process_name: best.process_name,
      direction: best.direction,
      src_ip: best.src_ip,
      src_identity: best.src_identity,
      dst_ip: best.dst_ip,
      dst_identity: best.dst_identity,
      latest_risk_score: Math.max(...rows.map((r) => r.latest_risk_score || 0)),
      latest_stage: best.latest_stage,
      max_stage_reached: rows.reduce(
        (m, r) =>
          stageIndex(r.max_stage_reached || r.latest_stage) > stageIndex(m)
            ? r.max_stage_reached || r.latest_stage
            : m,
        best.max_stage_reached || best.latest_stage,
      ),
      flow_count: rows.reduce((sum, r) => sum + (r.flow_count || 0), 0),
      tot_fwd_pkts: rows.reduce((sum, r) => sum + (r.tot_fwd_pkts || 0), 0),
      tot_bwd_pkts: rows.reduce((sum, r) => sum + (r.tot_bwd_pkts || 0), 0),
      last_seen: rows.reduce(
        (m, r) => ((r.last_seen || "") > m ? r.last_seen : m),
        best.last_seen || "",
      ),
    };
  });
}

function portOf(s) {
  return s.dst_port ? `:${s.dst_port}` : "";
}

function SessionTable({
  sessions = [],
  loading = false,
  sortBy = "last_seen",
  setSortBy,
  onSelectSession,
}) {
  const [filterText, setFilterText] = useState("");
  const [groupByApp, setGroupByApp] = useState(true);
  const [expanded, setExpanded] = useState(() => new Set());

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

  const groups = useMemo(
    () => (groupByApp ? groupSessions(filteredSessions) : []),
    [groupByApp, filteredSessions],
  );

  const toggleExpanded = (key) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

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
          <span>
            Tracked Network Sessions ({filteredSessions.length}
            {groupByApp && groups.length !== filteredSessions.length
              ? ` in ${groups.length} apps`
              : ""}
            )
          </span>
        </div>

        <div
          style={{ display: "flex", alignItems: "center", gap: "var(--sp-3)" }}
        >
          <button
            className="btn btn-sm btn-outline"
            onClick={() => setGroupByApp((g) => !g)}
            title={
              groupByApp
                ? "Showing one row per application; each app may have several active destinations. Click to list every individual session instead."
                : "Showing every individual (app, destination) session separately. Click to collapse each application back into one row."
            }
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              whiteSpace: "nowrap",
            }}
          >
            <Layers size={11} />
            {groupByApp ? "Grouped by app" : "All sessions"}
          </button>

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
                style={{ cursor: "pointer", textAlign: "right" }}
                onClick={() => setSortBy?.("last_seen")}
              >
                Last Seen {renderSortIcon("last_seen")}
              </th>
            </tr>
          </thead>
          <tbody>
            {(groupByApp ? groups : filteredSessions).map((row) => {
              const isGroup = groupByApp;
              const s = row;
              const isCompromised =
                stageIndex(s.latest_stage) >= 3 &&
                (s.latest_risk_score || 0) > 0.5;
              const rowKey = isGroup ? row.key : row.session_key;
              const isOpen = isGroup && expanded.has(row.key);
              const mainRow = (
                <tr
                  key={rowKey}
                  onClick={
                    isGroup && row.count > 1
                      ? () => toggleExpanded(row.key)
                      : undefined
                  }
                  style={{
                    cursor: isGroup && row.count > 1 ? "pointer" : undefined,
                    background: isCompromised
                      ? `linear-gradient(90deg, rgba(201, 74, 69, 0.1), transparent)`
                      : undefined,
                  }}
                >
                  <td>
                    <div
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                      }}
                    >
                      {isGroup &&
                        row.count > 1 &&
                        (isOpen ? (
                          <ChevronDown size={12} />
                        ) : (
                          <ChevronRight size={12} />
                        ))}
                      <AppBadge
                        appName={s.app_name}
                        processName={s.process_name}
                      />
                      {isGroup && row.count > 1 && (
                        <span
                          className="mono text-xs"
                          style={{
                            color: "var(--c-gold)",
                            background: "var(--bg-dark)",
                            borderRadius: "var(--radius-sm)",
                            padding: "1px 6px",
                            fontWeight: 700,
                          }}
                        >
                          &times;{row.count}
                        </span>
                      )}
                    </div>
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
                    {isGroup && row.count > 1 ? (
                      <span className="mono text-sm text-muted">
                        {row.count} destinations
                        {isOpen ? "" : " (expand to see ports)"}
                      </span>
                    ) : (
                      <div className="ip-symmetric-cell">
                        <span className="ip-digits">
                          {s.dst_ip || "—"}
                          {portOf(s)}
                        </span>
                        <IdentityBadge identity={s.dst_identity} />
                      </div>
                    )}
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
                    <div
                      className="risk-cell"
                      title={
                        isGroup && row.count > 1
                          ? "Highest risk among this app's active destinations"
                          : undefined
                      }
                    >
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
                    style={{ color: "var(--text-muted)", textAlign: "right" }}
                  >
                    {formatTime(s.last_seen)}
                  </td>
                </tr>
              );
              if (!isOpen) return mainRow;
              return (
                <>
                  {mainRow}
                  {row.rows.map((d) => (
                    <tr
                      key={d.session_key}
                      style={{ background: "var(--bg-elevated)" }}
                    >
                      <td style={{ paddingLeft: "var(--sp-5)" }} />
                      <td>
                        <DirBadge dir={d.direction} />
                      </td>
                      <td>
                        <div className="ip-symmetric-cell">
                          <span className="ip-digits">{d.src_ip || "—"}</span>
                          <IdentityBadge identity={d.src_identity} />
                        </div>
                      </td>
                      <td>
                        <div className="ip-symmetric-cell">
                          <span className="ip-digits">
                            {d.dst_ip || "—"}
                            {portOf(d)}
                          </span>
                          <IdentityBadge identity={d.dst_identity} />
                        </div>
                      </td>
                      <td>
                        <PacketStat
                          fwdPkts={d.tot_fwd_pkts}
                          bwdPkts={d.tot_bwd_pkts}
                          proto="IP"
                        />
                      </td>
                      <td className="mono" style={{ fontWeight: 700 }}>
                        {d.flow_count}
                      </td>
                      <td>
                        <div className="risk-cell">
                          <div
                            className={`risk-bar ${severityClass(d.latest_risk_score)}`}
                          />
                          <span
                            style={{
                              fontWeight: 700,
                              color:
                                (d.latest_risk_score || 0) > 0.5
                                  ? "var(--c-red)"
                                  : "var(--text-primary)",
                            }}
                          >
                            {formatProb(d.latest_risk_score)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span
                          className={`stage-badge ${stageClass(d.latest_stage)}`}
                        >
                          {d.latest_stage}
                        </span>
                      </td>
                      <td>
                        <KillChainCompact
                          currentStage={d.max_stage_reached || d.latest_stage}
                        />
                      </td>
                      <td
                        className="mono text-sm"
                        style={{
                          color: "var(--text-muted)",
                          textAlign: "right",
                        }}
                      >
                        {formatTime(d.last_seen)}
                      </td>
                    </tr>
                  ))}
                </>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default memo(SessionTable);
