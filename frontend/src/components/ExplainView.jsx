import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Eye,
  AlertTriangle,
  FileDown,
  FileSpreadsheet,
  Code2,
  TrendingUp,
  TrendingDown,
  ShieldCheck,
  ShieldAlert,
  Search,
  SlidersHorizontal,
  Info,
} from "lucide-react";
import { apiFetch, apiPost } from "../api";
import {
  stageClass,
  formatProb,
  formatFeatureName,
  DEFAULT_FEAT_ORDER,
} from "../utils";
import { AppBadge, DirBadge, IdentityBadge } from "./Badges";

const FEATURE_EXPLANATIONS = {
  flow_duration: "Duration of the bidirectional network flow in microseconds.",
  tot_fwd_pkts: "Packets sent in forward (client → server) direction.",
  tot_bwd_pkts: "Packets sent in backward (server → client) direction.",
  fwd_pkt_len_mean: "Average byte length of forward packets.",
  bwd_pkt_len_mean: "Average byte length of backward response packets.",
  flow_bytes_s: "Data transfer throughput (bytes per second).",
  flow_pkts_s: "Transmission speed (packets per second).",
  flow_iat_mean: "Average inter-arrival time between consecutive packets.",
  flow_iat_std: "Variance in packet inter-arrival timing (jitter indicator).",
  fwd_iat_mean: "Inter-arrival timing between forward requests.",
  bwd_iat_mean: "Inter-arrival timing between backward responses.",
  syn_flag_cnt: "SYN packets observed (connection setup or port scanning).",
  ack_flag_cnt: "ACK packets observed (established stream data transfer).",
  fin_flag_cnt: "FIN packets observed (graceful socket teardown).",
  rst_flag_cnt: "RST packets observed (abrupt teardown or connection reset).",
  psh_flag_cnt: "PSH packets observed (immediate application buffer flush).",
  urg_flag_cnt: "URG packets observed (urgent out-of-band data stream).",
  down_up_ratio: "Ratio of download packets to upload packets.",
  pkt_size_avg: "Average size of packets across the flow session.",
  ttl_variance:
    "Variance in IP TTL (indicates multi-hop routing anomalies/spoofing).",
  tcp_win_size: "Advertised TCP receive window size during handshake.",
  retransmit_cnt:
    "Packet retransmissions caused by packet loss or probe resets.",
};

export default function ExplainView({ featureList }) {
  const [sessions, setSessions] = useState([]);
  const [selected, setSelected] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [latestFlowFeatures, setLatestFlowFeatures] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [method, setMethod] = useState("gradient");
  const [searchQuery, setSearchQuery] = useState("");
  const [attributionFilter, setAttributionFilter] = useState("all");

  const featOrder = featureList || DEFAULT_FEAT_ORDER;

  const explain = useCallback(
    (session, methodToUse = method) => {
      if (!session) return;
      setSelected(session);
      setLoading(true);
      setError(null);
      apiFetch(
        `/sessions/${encodeURIComponent(session.session_key)}/flows?limit=6`,
      )
        .then((flows) => {
          if (!flows || flows.length === 0) {
            throw new Error("No flow records captured for this session yet.");
          }
          if (flows.length < 6) {
            throw new Error(
              `Collecting baseline: ${flows.length}/6 flows. The world model needs a full 6-flow window of real observations before it can explain a prediction.`,
            );
          }
          setLatestFlowFeatures(flows[0]?.features || null);
          const windowFlows = flows.slice(0, 6).reverse();
          const window = windowFlows.map((f) =>
            featOrder.map((k) => f.features?.[k] ?? 0),
          );
          return apiPost("/explain", {
            window,
            top_k: 22,
            needs_scaling: true,
            method: methodToUse,
          });
        })
        .then((result) => {
          setExplanation(result);
          setLoading(false);
        })
        .catch((err) => {
          setError(err.message || "Failed to compute feature attribution.");
          setLoading(false);
        });
    },
    [featOrder, method],
  );

  useEffect(() => {
    let mounted = true;
    apiFetch("/sessions?limit=50")
      .then((data) => {
        if (!mounted) return;
        const list = Array.isArray(data) ? data : [];
        setSessions(list);
        if (list.length > 0) {
          setSelected((prev) => {
            if (prev && list.some((s) => s.session_key === prev.session_key))
              return prev;
            const highestRisk = [...list].sort(
              (a, b) => (b.latest_risk_score || 0) - (a.latest_risk_score || 0),
            )[0];
            explain(highestRisk, "gradient");
            return highestRisk;
          });
        }
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, [explain]);

  const handleMethodChange = (newMethod) => {
    setMethod(newMethod);
    if (selected) {
      explain(selected, newMethod);
    }
  };

  const attributions = useMemo(() => {
    return explanation?.attributions || [];
  }, [explanation]);

  const maxImp = useMemo(() => {
    if (!attributions.length) return 1;
    return Math.max(...attributions.map((a) => Math.abs(a.importance))) || 1;
  }, [attributions]);

  const stats = useMemo(() => {
    let positiveSum = 0;
    let negativeSum = 0;
    let topThreat = null;
    let maxPos = -Infinity;

    attributions.forEach((a) => {
      if (a.importance > 0) {
        positiveSum += a.importance;
        if (a.importance > maxPos) {
          maxPos = a.importance;
          topThreat = a.feature;
        }
      } else {
        negativeSum += Math.abs(a.importance);
      }
    });

    return {
      positiveSum,
      negativeSum,
      topThreat,
      totalFeatures: attributions.length,
    };
  }, [attributions]);

  const filteredAttributions = useMemo(() => {
    if (attributionFilter === "threat") {
      return attributions.filter((a) => a.importance > 0);
    }
    if (attributionFilter === "benign") {
      return attributions.filter((a) => a.importance < 0);
    }
    return attributions;
  }, [attributions, attributionFilter]);

  const filteredSessions = sessions.filter((s) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (s.src_ip || "").toLowerCase().includes(q) ||
      (s.dst_ip || "").toLowerCase().includes(q) ||
      (s.app_name || "").toLowerCase().includes(q) ||
      (s.process_name || "").toLowerCase().includes(q) ||
      (s.latest_stage || "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="explain-layout">
      {/* Left Panel: Active Session Picker */}
      <div
        className="panel"
        style={{ display: "flex", flexDirection: "column" }}
      >
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span className="panel-title">Select Monitored Session</span>
          <span className="panel-meta">{filteredSessions.length} active</span>
        </div>

        <div
          style={{
            padding: "8px 12px",
            borderBottom: "1px solid var(--border-dark)",
            background: "var(--bg-dark)",
          }}
        >
          <div style={{ position: "relative" }}>
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
              placeholder="Search IP, Application, Stage..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                padding: "4px 8px 4px 26px",
                fontSize: "0.72rem",
                background: "var(--c-dark-base)",
                border: "1px solid var(--border-dark)",
                borderRadius: "var(--radius-sm)",
                color: "var(--text-primary)",
                fontFamily: "var(--font-mono)",
                outline: "none",
              }}
            />
          </div>
        </div>

        <div
          style={{
            flex: 1,
            maxHeight: "calc(100vh - 230px)",
            overflowY: "auto",
            padding: "8px",
          }}
        >
          {filteredSessions.length === 0 ? (
            <div className="empty-state" style={{ padding: "var(--sp-6)" }}>
              <p>No matching sessions found.</p>
            </div>
          ) : (
            filteredSessions.map((s) => {
              const isSelected = selected?.session_key === s.session_key;
              const isThreat =
                (s.latest_risk_score || 0) > 0.5 ||
                (s.latest_stage && s.latest_stage !== "Benign");
              return (
                <div
                  key={s.session_key}
                  onClick={() => explain(s)}
                  className={`session-picker-card ${isSelected ? "selected" : ""}`}
                >
                  <div className="session-picker-header">
                    <AppBadge
                      name={s.app_name || s.process_name}
                      processName={s.process_name}
                    />
                    <DirBadge dir={s.direction} />
                  </div>

                  <div className="session-picker-endpoints">
                    <div className="session-endpoint-row">
                      <span className="session-endpoint-tag">SRC</span>
                      <span className="session-endpoint-ip">{s.src_ip}</span>
                      <IdentityBadge identity={s.src_identity} />
                    </div>
                    <div className="session-endpoint-row">
                      <span className="session-endpoint-tag">DST</span>
                      <span className="session-endpoint-ip">{s.dst_ip}</span>
                      <IdentityBadge identity={s.dst_identity} />
                    </div>
                  </div>

                  <div className="session-picker-footer">
                    <span
                      className={`stage-badge ${stageClass(s.latest_stage)}`}
                    >
                      <span
                        className="radar-blip-dot"
                        style={{
                          background: isThreat
                            ? "var(--c-red)"
                            : "var(--severity-low)",
                          marginRight: 4,
                        }}
                      />
                      {s.latest_stage || "Benign"}
                    </span>
                    <span className="session-flow-count mono">
                      {s.flow_count} flows
                    </span>
                    <span
                      className="session-risk-val"
                      style={{
                        color:
                          (s.latest_risk_score || 0) > 0.5
                            ? "var(--severity-critical)"
                            : "var(--c-gold)",
                      }}
                    >
                      {formatProb(s.latest_risk_score || 0)}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Right Panel: Feature Attribution Analysis */}
      <div
        className="panel"
        style={{ display: "flex", flexDirection: "column" }}
      >
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "var(--sp-2)",
          }}
        >
          <div>
            <span className="panel-title">
              Feature Attribution & Explanations
            </span>
            <span className="panel-meta" style={{ marginLeft: "var(--sp-2)" }}>
              {explanation?.method_used === "shap"
                ? "Game-Theoretic Shapley Values"
                : "Gradient × Input Attributions"}{" "}
              (22 Temporal Features)
            </span>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "var(--sp-2)",
              flexWrap: "wrap",
            }}
          >
            <div
              style={{
                display: "inline-flex",
                gap: 4,
                background: "var(--surface)",
                padding: 2,
                borderRadius: "var(--radius-sm)",
                border: "1px solid var(--border)",
              }}
            >
              <button
                className={`btn btn-sm ${method === "gradient" ? "btn-primary" : ""}`}
                onClick={() => handleMethodChange("gradient")}
                style={{ fontSize: "0.68rem", padding: "3px 8px" }}
                title="Fast sub-second gradient attribution"
              >
                Fast (Gradient)
              </button>
              <button
                className={`btn btn-sm ${method === "shap" ? "btn-primary" : ""}`}
                onClick={() => handleMethodChange("shap")}
                style={{ fontSize: "0.68rem", padding: "3px 8px" }}
                title="Deep game-theoretic Shapley value attribution (~3-5s)"
              >
                Deep (SHAP)
              </button>
            </div>

            <div style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
              <button
                className="btn btn-sm btn-outline"
                onClick={() => {
                  if (!selected) return;
                  const url = `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/view/html?session_key=${encodeURIComponent(selected.session_key)}&method=${method}`;
                  window.open(url, "_blank");
                }}
                disabled={!selected}
                style={{ fontSize: "0.68rem", padding: "3px 8px" }}
                title="Open printable feature attribution report in a new tab"
              >
                <Eye size={12} /> VIEW DOSSIER
              </button>
              <a
                className="btn btn-sm btn-primary"
                href={
                  selected
                    ? `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/export/html?session_key=${encodeURIComponent(selected.session_key)}&method=${method}`
                    : "#"
                }
                download
                style={{
                  fontSize: "0.68rem",
                  padding: "3px 10px",
                  textDecoration: "none",
                  pointerEvents: selected ? "auto" : "none",
                  opacity: selected ? 1 : 0.5,
                }}
              >
                <FileDown size={12} /> HTML
              </a>
              <a
                className="btn btn-sm btn-outline"
                href={
                  selected
                    ? `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/export/csv?session_key=${encodeURIComponent(selected.session_key)}&method=${method}`
                    : "#"
                }
                download
                style={{
                  fontSize: "0.68rem",
                  padding: "3px 8px",
                  textDecoration: "none",
                  pointerEvents: selected ? "auto" : "none",
                  opacity: selected ? 1 : 0.5,
                }}
              >
                <FileSpreadsheet size={12} /> CSV
              </a>
              <a
                className="btn btn-sm btn-outline"
                href={
                  selected
                    ? `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/explain/export/json?session_key=${encodeURIComponent(selected.session_key)}&method=${method}`
                    : "#"
                }
                download
                style={{
                  fontSize: "0.68rem",
                  padding: "3px 8px",
                  textDecoration: "none",
                  pointerEvents: selected ? "auto" : "none",
                  opacity: selected ? 1 : 0.5,
                }}
              >
                <Code2 size={12} /> JSON
              </a>
            </div>
          </div>
        </div>

        <div
          className="panel-body"
          style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}
        >
          {loading ? (
            <div className="empty-state">
              <div className="loading-spinner" />
              <p>
                Computing {method.toUpperCase()} feature attributions for{" "}
                {selected?.app_name || selected?.process_name || "session"}...
              </p>
            </div>
          ) : error ? (
            <div className="empty-state">
              <AlertTriangle size={28} color="var(--severity-high)" />
              <p>{error}</p>
            </div>
          ) : !explanation ? (
            <div className="empty-state">
              <Eye size={28} color="var(--text-muted)" />
              <p>
                Select an active session from the left panel to inspect its
                feature attribution profile.
              </p>
            </div>
          ) : (
            <>
              {/* Attribution KPI Cards */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: "12px",
                  marginBottom: "18px",
                }}
              >
                <div
                  style={{
                    background: "var(--bg-dark)",
                    border: "1px solid var(--border-dark)",
                    borderRadius: "var(--radius-sm)",
                    padding: "10px 14px",
                    cursor: "default",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.7rem",
                      color: "var(--text-muted)",
                      display: "block",
                    }}
                  >
                    MODEL INFILTRATION RISK
                  </span>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "baseline",
                      gap: 8,
                      marginTop: 2,
                    }}
                  >
                    <span
                      className="mono"
                      style={{
                        fontSize: "1.4rem",
                        fontWeight: 800,
                        color:
                          (explanation.infiltration_probability || 0) > 0.5
                            ? "var(--c-red)"
                            : "var(--c-gold)",
                      }}
                    >
                      {formatProb(explanation.infiltration_probability)}
                    </span>
                    <span
                      className={`stage-badge ${stageClass(explanation.predicted_stage)}`}
                    >
                      {explanation.predicted_stage}
                    </span>
                  </div>
                </div>

                <div
                  style={{
                    background: "var(--bg-dark)",
                    border: "1px solid var(--border-dark)",
                    borderRadius: "var(--radius-sm)",
                    padding: "10px 14px",
                    cursor: "default",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.7rem",
                      color: "var(--text-muted)",
                      display: "block",
                    }}
                  >
                    ATTACK RISK CONTRIBUTORS
                  </span>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      marginTop: 4,
                    }}
                  >
                    <TrendingUp size={16} color="var(--c-red)" />
                    <span
                      className="mono"
                      style={{
                        fontSize: "1.1rem",
                        fontWeight: 700,
                        color: "var(--c-red)",
                      }}
                    >
                      +{stats.positiveSum.toFixed(3)}
                    </span>
                    <span
                      style={{
                        fontSize: "0.72rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      pushing to threat
                    </span>
                  </div>
                </div>

                <div
                  style={{
                    background: "var(--bg-dark)",
                    border: "1px solid var(--border-dark)",
                    borderRadius: "var(--radius-sm)",
                    padding: "10px 14px",
                    cursor: "default",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.7rem",
                      color: "var(--text-muted)",
                      display: "block",
                    }}
                  >
                    BENIGN MITIGATING FACTORS
                  </span>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      marginTop: 4,
                    }}
                  >
                    <TrendingDown size={16} color="var(--severity-low)" />
                    <span
                      className="mono"
                      style={{
                        fontSize: "1.1rem",
                        fontWeight: 700,
                        color: "var(--severity-low)",
                      }}
                    >
                      -{stats.negativeSum.toFixed(3)}
                    </span>
                    <span
                      style={{
                        fontSize: "0.72rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      pushing to normal
                    </span>
                  </div>
                </div>

                <div
                  style={{
                    background: "var(--bg-dark)",
                    border: "1px solid var(--border-dark)",
                    borderRadius: "var(--radius-sm)",
                    padding: "10px 14px",
                    cursor: "default",
                  }}
                >
                  <span
                    style={{
                      fontSize: "0.7rem",
                      color: "var(--text-muted)",
                      display: "block",
                    }}
                  >
                    PRIMARY ATTACK VECTOR
                  </span>
                  <div style={{ marginTop: 4 }}>
                    <strong
                      style={{
                        fontSize: "0.85rem",
                        color: stats.topThreat
                          ? "var(--c-red)"
                          : "var(--severity-low)",
                      }}
                    >
                      {stats.topThreat
                        ? formatFeatureName(stats.topThreat)
                        : "Nominal Traffic"}
                    </strong>
                    <span
                      style={{
                        display: "block",
                        fontSize: "0.7rem",
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {stats.topThreat ? `[${stats.topThreat}]` : "No anomaly"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Attribution Filter Buttons */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                  marginBottom: 12,
                  padding: "6px 0",
                  borderBottom: "1px solid var(--border-dark)",
                }}
              >
                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    className={`btn btn-sm ${attributionFilter === "all" ? "btn-primary" : "btn-outline"}`}
                    onClick={() => setAttributionFilter("all")}
                    style={{ fontSize: "0.68rem", padding: "2px 8px" }}
                  >
                    All Features ({attributions.length})
                  </button>
                  <button
                    className={`btn btn-sm ${attributionFilter === "threat" ? "btn-primary" : "btn-outline"}`}
                    onClick={() => setAttributionFilter("threat")}
                    style={{
                      fontSize: "0.68rem",
                      padding: "2px 8px",
                      color:
                        attributionFilter === "threat"
                          ? "#1A1610"
                          : "var(--c-red)",
                    }}
                  >
                    Threat Drivers Only (
                    {attributions.filter((a) => a.importance > 0).length})
                  </button>
                  <button
                    className={`btn btn-sm ${attributionFilter === "benign" ? "btn-primary" : "btn-outline"}`}
                    onClick={() => setAttributionFilter("benign")}
                    style={{
                      fontSize: "0.68rem",
                      padding: "2px 8px",
                      color:
                        attributionFilter === "benign"
                          ? "#1A1610"
                          : "var(--severity-low)",
                    }}
                  >
                    Benign Mitigators (
                    {attributions.filter((a) => a.importance < 0).length})
                  </button>
                </div>

                <div
                  style={{
                    display: "flex",
                    gap: 14,
                    fontSize: "0.68rem",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <span
                    style={{
                      color: "var(--severity-low)",
                      display: "flex",
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
                    />
                    Benign Impact (&larr; Negative)
                  </span>
                  <span
                    style={{
                      color: "var(--c-red)",
                      display: "flex",
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
                    />
                    Attack Threat Impact (Positive &rarr;)
                  </span>
                </div>
              </div>

              {/* Bi-Directional Diverging Attribution Chart */}
              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border-dark)",
                  borderRadius: "var(--radius-sm)",
                  padding: "12px 16px",
                }}
              >
                {/* Center Axis Header */}
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "240px 1fr 100px",
                    gap: "12px",
                    paddingBottom: "8px",
                    borderBottom: "1px solid rgba(58, 50, 40, 0.5)",
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    fontWeight: 700,
                  }}
                >
                  <span>FEATURE & FLOW METRIC</span>
                  <div style={{ position: "relative", textAlign: "center" }}>
                    <span style={{ position: "absolute", left: "20%" }}>
                      &larr; BENIGN PUSH
                    </span>
                    <span
                      style={{
                        position: "absolute",
                        left: "50%",
                        transform: "translateX(-50%)",
                        color: "var(--c-gold)",
                      }}
                    >
                      0.00 (NEUTRAL)
                    </span>
                    <span style={{ position: "absolute", right: "20%" }}>
                      ATTACK PUSH &rarr;
                    </span>
                  </div>
                  <span style={{ textAlign: "right" }}>WEIGHT & DELTA</span>
                </div>

                {/* Rows */}
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                    marginTop: "8px",
                  }}
                >
                  {filteredAttributions.map((attr, idx) => {
                    const isThreat = attr.importance > 0;
                    const absVal = Math.abs(attr.importance);
                    const pctOfHalf = Math.min(100, (absVal / maxImp) * 100);
                    const observedVal = latestFlowFeatures
                      ? latestFlowFeatures[attr.feature]
                      : null;
                    const explanationText =
                      FEATURE_EXPLANATIONS[attr.feature] || "";

                    return (
                      <div
                        key={idx}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "240px 1fr 100px",
                          gap: "12px",
                          alignItems: "center",
                          padding: "6px 8px",
                          borderRadius: "var(--radius-sm)",
                          background:
                            idx % 2 === 0
                              ? "rgba(36, 31, 24, 0.4)"
                              : "transparent",
                          transition: "background 0.15s ease",
                        }}
                      >
                        {/* Feature Title and technical key */}
                        <div style={{ overflow: "hidden" }}>
                          <div
                            style={{
                              display: "flex",
                              alignItems: "baseline",
                              gap: 6,
                            }}
                          >
                            <span
                              style={{
                                fontSize: "0.82rem",
                                fontWeight: 700,
                                color: isThreat
                                  ? "var(--text-primary)"
                                  : "var(--text-muted)",
                                whiteSpace: "nowrap",
                                textOverflow: "ellipsis",
                                overflow: "hidden",
                              }}
                              title={explanationText}
                            >
                              {formatFeatureName(attr.feature)}
                            </span>
                            <span
                              className="mono"
                              style={{
                                fontSize: "0.64rem",
                                color: "var(--text-muted)",
                                background: "rgba(255, 255, 255, 0.05)",
                                padding: "1px 4px",
                                borderRadius: 2,
                              }}
                            >
                              {attr.feature}
                            </span>
                          </div>
                          {observedVal != null && (
                            <span
                              className="mono"
                              style={{
                                fontSize: "0.66rem",
                                color: "var(--c-gold)",
                                display: "block",
                                marginTop: 1,
                              }}
                            >
                              Observed:{" "}
                              {typeof observedVal === "number"
                                ? observedVal.toFixed(observedVal < 10 ? 2 : 0)
                                : observedVal}
                            </span>
                          )}
                        </div>

                        {/* Bi-Directional Diverging Bar */}
                        <div
                          style={{
                            position: "relative",
                            height: "16px",
                            background: "rgba(26, 22, 16, 0.8)",
                            borderRadius: "var(--radius-sm)",
                            overflow: "hidden",
                            border: "1px solid rgba(58, 50, 40, 0.6)",
                          }}
                        >
                          {/* Center dividing line */}
                          <div
                            style={{
                              position: "absolute",
                              left: "50%",
                              top: 0,
                              bottom: 0,
                              width: "2px",
                              background: "rgba(214, 179, 106, 0.35)",
                              zIndex: 2,
                            }}
                          />

                          {/* Bar Graphic */}
                          {isThreat ? (
                            // Pushes right (Crimson Red)
                            <div
                              style={{
                                position: "absolute",
                                left: "50%",
                                top: 2,
                                bottom: 2,
                                width: `${pctOfHalf * 0.48}%`,
                                background:
                                  "linear-gradient(90deg, rgba(201, 74, 69, 0.5) 0%, rgba(201, 74, 69, 0.95) 100%)",
                                borderRadius: "0 3px 3px 0",
                              }}
                            />
                          ) : (
                            // Pushes left (Sage Green)
                            <div
                              style={{
                                position: "absolute",
                                right: "50%",
                                top: 2,
                                bottom: 2,
                                width: `${pctOfHalf * 0.48}%`,
                                background:
                                  "linear-gradient(270deg, rgba(88, 166, 104, 0.5) 0%, rgba(88, 166, 104, 0.95) 100%)",
                                borderRadius: "3px 0 0 3px",
                              }}
                            />
                          )}
                        </div>

                        {/* Numerical Attribution Score */}
                        <div style={{ textAlign: "right" }}>
                          <span
                            className="mono"
                            style={{
                              fontSize: "0.82rem",
                              fontWeight: 700,
                              color: isThreat
                                ? "var(--c-red)"
                                : "var(--severity-low)",
                            }}
                          >
                            {isThreat ? "+" : ""}
                            {attr.importance.toFixed(4)}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
