import { useRef, useEffect, useMemo, useState, memo } from "react";
import {
  Radio,
  ShieldCheck,
  Pause,
  Play,
  Trash2,
  Search,
  RefreshCw,
  SlidersHorizontal,
} from "lucide-react";
import { formatTime, formatProb, isAttackFlow, stageClass, formatIpEndpoint } from "../utils";
import { apiFetch } from "../api";
import { DirBadge, SourceBadge } from "./Badges";

function LiveLogsView({
  lines = [],
  connected = false,
  onClear,
  onReloadRecent,
  systemMode = "live",
  _captureRunning = false,
}) {
  const containerRef = useRef(null);
  const [mitre, setMitre] = useState({});
  const [isPaused, setIsPaused] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [clearedBefore, setClearedBefore] = useState(0);
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [autoScroll, _setAutoScroll] = useState(true);

  useEffect(() => {
    apiFetch("/mitre/mapping")
      .then((m) => setMitre(m.legacy_stages || {}))
      .catch(() => setMitre({}));
  }, []);

  const techniques = (stage) =>
    (mitre[stage]?.techniques || []).map((t) => t.technique_id).join(" / ");

  // Accurate counts across all current lines
  const categoryCounts = useMemo(() => {
    const counts = {
      all: lines.length,
      threats: 0,
      benign: 0,
      recon: 0,
      initial: 0,
      lateral: 0,
      c2: 0,
      exfil: 0,
    };
    lines.forEach((l) => {
      const isThreat = isAttackFlow(l);
      if (isThreat) {
        counts.threats++;
      } else {
        counts.benign++;
      }
      const st = (l.predicted_stage || "").toLowerCase();
      if (st.includes("recon")) counts.recon++;
      else if (st.includes("initial")) counts.initial++;
      else if (st.includes("lateral")) counts.lateral++;
      else if (st.includes("c2")) counts.c2++;
      else if (st.includes("exfil")) counts.exfil++;
    });
    return counts;
  }, [lines]);

  // Dynamic filtering
  const visibleLines = useMemo(() => {
    let list = lines;
    if (clearedBefore > 0) {
      list = list.slice(0, Math.max(0, list.length - clearedBefore));
    }

    if (categoryFilter === "threats") {
      list = list.filter(isAttackFlow);
    } else if (categoryFilter === "benign") {
      list = list.filter((l) => !isAttackFlow(l));
    } else if (categoryFilter !== "all") {
      list = list.filter((l) => {
        if (!isAttackFlow(l)) return false;
        const st = (l.predicted_stage || "").toLowerCase();
        if (categoryFilter === "recon") return st.includes("recon");
        if (categoryFilter === "initial") return st.includes("initial");
        if (categoryFilter === "lateral") return st.includes("lateral");
        if (categoryFilter === "c2") return st.includes("c2");
        if (categoryFilter === "exfil") return st.includes("exfil");
        return true;
      });
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (l) =>
          (l.src_ip && l.src_ip.toLowerCase().includes(q)) ||
          (l.dst_ip && l.dst_ip.toLowerCase().includes(q)) ||
          (l.predicted_stage && l.predicted_stage.toLowerCase().includes(q)) ||
          (l.app_name && l.app_name.toLowerCase().includes(q)) ||
          (l.process_name && l.process_name.toLowerCase().includes(q)) ||
          (l.protocol && l.protocol.toLowerCase().includes(q)),
      );
    }
    return list;
  }, [lines, clearedBefore, categoryFilter, searchQuery]);

  const topKey = visibleLines[0]
    ? `${visibleLines[0]._ts || visibleLines[0].timestamp}-${visibleLines[0].src_ip}-${visibleLines[0].dst_ip}`
    : null;

  useEffect(() => {
    if (!isPaused && autoScroll && containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [topKey, isPaused, autoScroll]);

  return (
    <div className="terminal">
      {/* Terminal Toolbar Header */}
      <div
        className="terminal-header"
        style={{ flexWrap: "wrap", gap: "var(--sp-2)" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              padding: "2px 8px",
              background: connected
                ? systemMode === "live"
                  ? "rgba(88, 166, 104, 0.15)"
                  : "rgba(214, 179, 106, 0.15)"
                : "rgba(201, 74, 69, 0.15)",
              border: `1px solid ${
                connected
                  ? systemMode === "live"
                    ? "rgba(88, 166, 104, 0.4)"
                    : "rgba(214, 179, 106, 0.4)"
                  : "rgba(201, 74, 69, 0.4)"
              }`,
              borderRadius: "var(--radius-sm)",
              fontSize: "0.72rem",
              fontWeight: 700,
              color: connected
                ? systemMode === "live"
                  ? "var(--severity-low)"
                  : "var(--c-gold)"
                : "var(--c-red)",
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: connected
                  ? systemMode === "live"
                    ? "var(--severity-low)"
                    : "var(--c-gold)"
                  : "var(--c-red)",
                boxShadow: `0 0 6px ${
                  connected
                    ? systemMode === "live"
                      ? "var(--severity-low)"
                      : "var(--c-gold)"
                    : "var(--c-red)"
                }`,
              }}
            />
            {connected
              ? systemMode === "live"
                ? "Live Telemetry Feed"
                : "Simulated Event Feed"
              : "Offline (Reconnecting)"}
          </div>

          <span className="terminal-title">
            Flow Event Telemetry ({visibleLines.length} shown of {lines.length})
          </span>
        </div>

        {/* Toolbar Controls */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "var(--sp-2)",
            flexWrap: "wrap",
          }}
        >
          <div style={{ position: "relative", width: "190px" }}>
            <Search
              size={12}
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
              placeholder="Search IP, Stage, App..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                background: "var(--bg-inset)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "3px 8px 3px 24px",
                color: "var(--text-primary)",
                fontFamily: "var(--font-mono)",
                fontSize: "0.74rem",
                outline: "none",
              }}
            />
          </div>

          <button
            className={`btn btn-sm ${isPaused ? "btn-primary" : "btn-outline"}`}
            onClick={() => setIsPaused(!isPaused)}
            title={
              isPaused ? "Resume auto-scroll" : "Pause stream scroll to inspect"
            }
          >
            {isPaused ? <Play size={11} /> : <Pause size={11} />}
            {isPaused ? "RESUME" : "PAUSE"}
          </button>



          <button
            className="btn btn-sm btn-outline"
            onClick={() => {
              setClearedBefore(0);
              if (onClear) onClear();
            }}
            title="Clear display view and session stream buffer"
          >
            <Trash2 size={11} /> CLEAR
          </button>

          {onReloadRecent && (
            <button
              className="btn btn-sm btn-outline"
              onClick={() => {
                setClearedBefore(0);
                onReloadRecent();
              }}
              title="Reload recent 100 flows from database"
            >
              <RefreshCw size={11} /> RELOAD RECENT
            </button>
          )}
        </div>
      </div>

      {/* Category Filter Bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "6px 12px",
          background: "var(--bg-surface)",
          borderBottom: "1px solid var(--border)",
          overflowX: "auto",
          fontSize: "0.72rem",
          fontFamily: "var(--font-mono)",
          userSelect: "none",
        }}
      >
        <span
          style={{
            color: "var(--text-muted)",
            marginRight: 4,
            fontWeight: 700,
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
          }}
        >
          <SlidersHorizontal size={11} /> Filter:
        </span>
        {[
          {
            id: "all",
            label: "ALL FLOWS",
            color: "var(--text-primary)",
            count: categoryCounts.all,
          },
          {
            id: "threats",
            label: "THREATS ONLY",
            color: "var(--c-red)",
            count: categoryCounts.threats,
          },
          {
            id: "benign",
            label: "BENIGN",
            color: "var(--success)",
            count: categoryCounts.benign,
          },
          {
            id: "recon",
            label: "RECON",
            color: "var(--info)",
            count: categoryCounts.recon,
          },
          {
            id: "initial",
            label: "INITIAL ACCESS",
            color: "var(--warning)",
            count: categoryCounts.initial,
          },
          {
            id: "lateral",
            label: "LATERAL MOVE",
            color: "#E8873A",
            count: categoryCounts.lateral,
          },
          {
            id: "c2",
            label: "C2 CHANNEL",
            color: "#E5633E",
            count: categoryCounts.c2,
          },
          {
            id: "exfil",
            label: "EXFILTRATION",
            color: "var(--danger)",
            count: categoryCounts.exfil,
          },
        ].map((c) => {
          const isActive = categoryFilter === c.id;
          return (
            <button
              key={c.id}
              className={`live-filter-chip ${isActive ? "active" : ""}`}
              onClick={() => setCategoryFilter(c.id)}
              style={{
                borderColor: isActive ? c.color : "var(--border)",
                color: c.color,
                background: isActive ? "var(--bg-chip-active, #ffffff)" : "transparent",
              }}
            >
              <span>{c.label}</span>
              <span className="filter-count-badge">
                {c.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Column Headers */}
      {visibleLines.length > 0 && (
        <div className="terminal-row terminal-row-header">
          <span>Time</span>
          <span>Stage & Technique</span>
          <span>Source &rarr; Destination</span>
          <span>Application</span>
          <span>Risk Probability</span>
          <span>Flow Telemetry</span>
          <span style={{ textAlign: "right" }}>Origin</span>
        </div>
      )}

      {/* Terminal Rows Body */}
      <div className="terminal-body" ref={containerRef}>
        {visibleLines.length === 0 ? (
          <div className="terminal-empty">
            {lines.length === 0 ? (
              connected ? (
                <>
                  <ShieldCheck
                    size={32}
                    color={systemMode === "live" ? "var(--severity-low)" : "var(--c-gold)"}
                  />
                  <p
                    style={{
                      marginTop: "10px",
                      color: systemMode === "live" ? "var(--severity-low)" : "var(--c-gold)",
                      fontWeight: 700,
                      fontSize: "0.95rem",
                    }}
                  >
                    {systemMode === "live"
                      ? "Live Telemetry Operational • Listening on Network Adapters"
                      : "Simulation Mode • Awaiting Ingested Attack Telemetry"}
                  </p>
                  <p
                    style={{
                      fontSize: "0.78rem",
                      color: "var(--text-muted)",
                      marginTop: "4px",
                    }}
                  >
                    {systemMode === "live"
                      ? "World Model is actively monitoring real-time network traffic from host processes."
                      : "Configure and launch MITRE attack scenarios via Settings & Lab."}
                  </p>
                  <div
                    style={{
                      marginTop: 16,
                      display: "flex",
                      gap: 10,
                      justifyContent: "center",
                      flexWrap: "wrap",
                    }}
                  >
                    {systemMode === "live" && (
                      <div
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          color: "var(--severity-low)",
                          fontSize: "0.8rem",
                          fontWeight: 700,
                        }}
                      >
                        <span
                          className="radar-blip-dot"
                          style={{ background: "var(--severity-low)" }}
                        />
                        Live Sniffer Active &bull; Streaming Host Telemetry...
                      </div>
                    )}
                    {onReloadRecent && (
                      <button
                        className="btn btn-sm btn-outline"
                        onClick={() => {
                          setClearedBefore(0);
                          onReloadRecent();
                        }}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                        }}
                      >
                        <RefreshCw size={12} /> Reload Recent Flows
                      </button>
                    )}
                  </div>
                </>
              ) : (
                <>
                  <Radio size={32} color="var(--c-gold)" />
                  <p
                    style={{
                      marginTop: "10px",
                      color: "var(--c-gold)",
                      fontWeight: 700,
                      fontSize: "0.95rem",
                    }}
                  >
                    Connecting to Live Flow Engine...
                  </p>
                  <p
                    style={{
                      fontSize: "0.78rem",
                      color: "var(--text-muted)",
                      marginTop: "4px",
                    }}
                  >
                    Ensure FastAPI backend is running on port 8000.
                  </p>
                </>
              )
            ) : (
              <>
                <ShieldCheck size={32} color="var(--c-gold)" />
                <p
                  style={{
                    marginTop: "10px",
                    color: "var(--c-gold)",
                    fontWeight: 700,
                    fontSize: "0.95rem",
                  }}
                >
                  No Flow Records Matched Active Filter
                </p>
                <p
                  style={{
                    fontSize: "0.78rem",
                    color: "var(--text-muted)",
                    marginTop: "4px",
                  }}
                >
                  Adjust stage filter or clear search terms to view all{" "}
                  {lines.length} recorded events.
                </p>
              </>
            )}
          </div>
        ) : (
          visibleLines.map((line, i) => {
            const isThreat = isAttackFlow(line);
            const stage = isThreat
              ? (line.predicted_stage && line.predicted_stage !== "Benign" ? line.predicted_stage : "Attack Alert")
              : "Benign";
            const tech = isThreat ? techniques(stage) : null;
            return (
              <div
                key={
                  line.id ||
                  `${line._ts || line.timestamp}-${line.src_ip}-${line.dst_ip}-${i}`
                }
                className={`terminal-row stage-${stageClass(stage)}`}
              >
                <span className="ts">
                  {formatTime(line._ts || line.timestamp)}
                </span>

                <span className="attack-flag" title={tech || stage}>
                  {isThreat ? (
                    <span
                      className="radar-blip-dot"
                      style={{ background: "var(--c-red)", marginRight: 5 }}
                    />
                  ) : (
                    <span
                      className="radar-blip-dot"
                      style={{
                        background: "var(--severity-low)",
                        marginRight: 5,
                      }}
                    />
                  )}
                  {stage}
                  {tech && <span className="attack-technique"> [{tech}]</span>}
                </span>

                <span
                  className="terminal-ip-cell"
                  title={`${line.src_ip || "?"}:${line.src_port || ""} → ${line.dst_ip || "?"}:${line.dst_port || ""}`}
                >
                  <span
                    className="ip-digits ip-endpoint"
                    title={`${line.src_ip || "?"}${line.src_port ? `:${line.src_port}` : ""}`}
                  >
                    {formatIpEndpoint(line.src_ip, line.src_port)}
                  </span>
                  <span
                    className="sep"
                    style={{ margin: "0 6px", color: "var(--c-gold)", flexShrink: 0 }}
                  >
                    &rarr;
                  </span>
                  <span
                    className="ip-digits ip-endpoint"
                    title={`${line.dst_ip || "?"}${line.dst_port ? `:${line.dst_port}` : ""}`}
                  >
                    {formatIpEndpoint(line.dst_ip, line.dst_port)}
                  </span>
                </span>

                <span className="val app-cell" title={line.app_name || line.process_name || ""}>
                  {line.app_name || line.process_name ? (
                    <span
                      className="app-badge app-generic"
                      style={{
                        padding: "1px 6px",
                        fontSize: "0.7rem",
                        maxWidth: "140px",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        display: "inline-block",
                      }}
                    >
                      {line.app_name || line.process_name}
                    </span>
                  ) : (
                    <DirBadge dir={line.direction} />
                  )}
                </span>

                <span
                  className="val prob-cell"
                  style={{
                    color:
                      (line.infiltration_prob || 0) > 0.5
                        ? "var(--c-red)"
                        : isThreat
                          ? "var(--c-gold)"
                          : "var(--severity-low)",
                    fontWeight: 700,
                  }}
                >
                  {formatProb(line.infiltration_prob ?? line.infiltration_probability)}
                </span>

                <span className="val" style={{ fontSize: "0.74rem" }}>
                  TX: {line.tot_fwd_pkts || 0} / RX: {line.tot_bwd_pkts || 0}
                  {line.protocol ? ` (${line.protocol})` : ""}
                </span>

                <span style={{ textAlign: "right" }}>
                  <SourceBadge src={line.source} />
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default memo(LiveLogsView);
