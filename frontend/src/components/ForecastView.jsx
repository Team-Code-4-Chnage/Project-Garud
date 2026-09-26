import { useState, useEffect, useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  Activity,
  AlertTriangle,
  ShieldCheck,
  Loader2,
  ArrowLeft,
  Eye,
  FileDown,
  ShieldAlert,
} from "lucide-react";
import { apiFetch, apiPost } from "../api";
import {
  stageClass,
  stageColor,
  formatTime,
  formatProb,
  formatDuration,
  formatFeatureName,
  DEFAULT_FEAT_ORDER,
} from "../utils";
import {
  DirBadge,
  SourceBadge,
  CompromiseIndicator,
  KillChain,
} from "./Badges";

const WINDOW_SIZE = 6;

export default function ForecastView({ session, onBack, featureList }) {
  const [forecast, setForecast] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const featOrder = featureList || DEFAULT_FEAT_ORDER;
  const sessionKey = session?.session_key;

  useEffect(() => {
    if (!sessionKey) return;
    let active = true;

    (async () => {
      setLoading(true);
      setError(null);
      setForecast(null);
      setExplanation(null);
      try {
        const allFlows = await apiFetch(
          `/sessions/${encodeURIComponent(sessionKey)}/flows?limit=100`,
        );
        if (!active) return;
        setFlows(allFlows);
        if (!allFlows || allFlows.length === 0) {
          setError("No flow records captured for this session yet.");
          return;
        }
        if (allFlows.length < WINDOW_SIZE) {
          return;
        }
        const windowFlows = allFlows.slice(0, WINDOW_SIZE).reverse();
        const window = windowFlows.map((f) =>
          featOrder.map((k) => f.features?.[k] ?? 0),
        );
        const [fc, exp] = await Promise.all([
          apiPost("/forecast", {
            window,
            k_steps: 4,
            n_mc_samples: 20,
            needs_scaling: true,
          }),
          apiPost("/explain", { window, top_k: 10, needs_scaling: true }),
        ]);
        if (!active) return;
        setForecast(fc);
        setExplanation(exp);
      } catch (e) {
        if (active) setError(e.message);
      } finally {
        if (active) setLoading(false);
      }
    })();

    return () => {
      active = false;
    };
  }, [sessionKey, featOrder]);

  const avgStepMs = useMemo(() => {
    if (!flows || flows.length < 2) return null;
    const times = flows
      .map((f) => new Date(f.timestamp).getTime())
      .filter((t) => !Number.isNaN(t));
    if (times.length < 2) return null;
    const deltas = [];
    for (let i = 0; i < times.length - 1; i++)
      deltas.push(Math.abs(times[i] - times[i + 1]));
    const avg = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    return avg > 0 ? avg : null;
  }, [flows]);

  function formatEta(steps) {
    if (!avgStepMs) return null;
    const ms = avgStepMs * steps;
    if (ms < 1000) return "<1s";
    if (ms < 60000) return `~${Math.round(ms / 1000)}s`;
    if (ms < 3600000) return `~${Math.round(ms / 60000)}m`;
    return `~${Math.round(ms / 3600000)}h`;
  }

  if (!session) {
    return (
      <div className="empty-state">
        <Activity size={28} color="var(--text-muted)" />
        <p>Select a session from the Dashboard to view its attack forecast.</p>
      </div>
    );
  }

  if (loading && !forecast) {
    return (
      <div className="empty-state">
        <div className="loading-spinner" />
        <p>Running forecast model...</p>
      </div>
    );
  }

  if (error && !forecast) {
    return (
      <div className="empty-state">
        <AlertTriangle size={28} color="var(--severity-high)" />
        <p>{error}</p>
      </div>
    );
  }

  if (!loading && !forecast && flows.length < WINDOW_SIZE) {
    return (
      <div className="empty-state">
        <Loader2 size={28} color="var(--text-muted)" className="spin-icon" />
        <p>
          Collecting baseline: {flows.length}/{WINDOW_SIZE} flows
        </p>
        <span className="mono text-xs text-muted">
          The world model needs a full {WINDOW_SIZE}-flow window of real
          observations before it can forecast. Come back once more traffic has
          been captured for this session.
        </span>
      </div>
    );
  }

  const chartData =
    forecast?.steps?.map((s) => ({
      step: `+${s.step}`,
      stepNum: s.step,
      mean: s.infiltration_prob_mean,
      ema: s.infiltration_prob_ema,
      upper: Math.min(1, s.infiltration_prob_mean + s.infiltration_prob_std),
      lower: Math.max(0, s.infiltration_prob_mean - s.infiltration_prob_std),
      stage: s.predicted_stage,
    })) || [];

  const forecastStages = [...new Set(chartData.map((d) => d.stage))];
  const maxImportance = explanation?.attributions
    ? Math.max(...explanation.attributions.map((a) => Math.abs(a.importance)))
    : 1;

  const hasAttackSignal = Boolean(
    forecast?.alert_triggered ||
    chartData.some((d) => d.stage && d.stage !== "Benign") ||
    chartData.some((d) => (d.mean ?? 0) > 0.1) ||
    (explanation?.infiltration_probability ?? 0) > 0.1 ||
    (session.max_stage_reached && session.max_stage_reached !== "Benign") ||
    (session.latest_risk_score ?? 0) > 0.1,
  );

  if (forecast && !hasAttackSignal) {
    return (
      <div className="empty-state">
        <ShieldCheck size={28} color="var(--severity-low)" />
        <p style={{ color: "var(--severity-low)" }}>
          No attack activity projected
        </p>
        <span className="mono text-xs text-muted">
          {session.src_ip} &rarr; {session.dst_ip} — the model forecasts this
          session staying Benign across all {chartData.length} steps, and it has
          no prior risk on record. Nothing to visualize.
        </span>
        <button
          className="btn btn-sm"
          onClick={onBack}
          style={{ marginTop: "var(--sp-3)" }}
        >
          &larr; BACK TO DASHBOARD
        </button>
      </div>
    );
  }

  return (
    <>
      {/* Official Government Threat Intelligence Dossier Header */}
      <div
        className="panel mb-4"
        style={{ borderLeft: "4px solid var(--c-gold)" }}
      >
        <div
          className="panel-header"
          style={{ flexWrap: "wrap", gap: "var(--sp-2)" }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <button
              className="btn btn-sm btn-outline"
              onClick={onBack}
              title="Return to master dashboard"
            >
              <ArrowLeft size={13} /> BACK
            </button>
            <span className="panel-title" style={{ fontSize: "1rem" }}>
              Incident Dossier: {session.src_ip} &rarr; {session.dst_ip}
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
            {loading && (
              <span
                className="mono"
                style={{
                  fontSize: "0.74rem",
                  color: "var(--c-gold)",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "3px 8px",
                  background: "rgba(214, 179, 106, 0.15)",
                  borderRadius: "var(--radius-sm)",
                }}
              >
                <span
                  className="loading-spinner"
                  style={{ width: 12, height: 12, borderWidth: 2, margin: 0 }}
                />
                SYNCING REAL-TIME MODEL
              </span>
            )}
            {error && (
              <span className="severity-badge high" title={error}>
                TELEMETRY REFRESH INTERRUPTED
              </span>
            )}
            {forecast?.alert_triggered && (
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "3px 10px",
                  borderRadius: "var(--radius-sm)",
                  background: "rgba(201, 74, 69, 0.2)",
                  border: "1px solid var(--c-red)",
                  color: "var(--c-red)",
                  fontWeight: 800,
                  fontSize: "0.8rem",
                  letterSpacing: "0.04em",
                }}
              >
                <ShieldAlert size={13} />
                PROJECTED ATTACK STEP +{forecast.alert_at_step}
                {formatEta(forecast.alert_at_step) && (
                  <> (ETA {formatEta(forecast.alert_at_step)})</>
                )}
              </span>
            )}

            <button
              className="btn btn-sm btn-outline"
              onClick={() =>
                window.open(
                  `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/forecast/view/html?session_key=${encodeURIComponent(session.session_key)}`,
                  "_blank",
                )
              }
              title="Open printable forecast dossier in a new browser tab"
            >
              <Eye size={12} /> View Report
            </button>
            <a
              className="btn btn-sm btn-primary"
              href={`${import.meta.env.VITE_API_URL || "http://localhost:8000"}/forecast/export/html?session_key=${encodeURIComponent(session.session_key)}`}
              download
              style={{ textDecoration: "none" }}
            >
              <FileDown size={12} /> Export Forecast Dossier
            </a>
          </div>
        </div>

        <div
          className="panel-body"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "var(--sp-4)",
            flexWrap: "wrap",
            padding: "12px 18px",
            background: "var(--bg-dark)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="mono text-xs text-muted">Classified Stage:</span>
            <span
              className={`stage-badge ${stageClass(session.latest_stage)}`}
              style={{ fontSize: "0.82rem", padding: "3px 10px" }}
            >
              {session.latest_stage}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span className="mono text-xs text-muted">Direction:</span>
            <DirBadge dir={session.direction} />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span className="mono text-xs text-muted">Telemetry Source:</span>
            <SourceBadge src={session.source} />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span className="mono text-xs text-muted">Risk Score:</span>
            <span
              className="mono"
              style={{
                fontWeight: 800,
                fontSize: "0.95rem",
                color:
                  (session.latest_risk_score || 0) > 0.5
                    ? "var(--c-red)"
                    : "var(--c-gold)",
              }}
            >
              {formatProb(session.latest_risk_score)}
            </span>
          </div>

          <CompromiseIndicator
            stage={session.max_stage_reached || session.latest_stage}
            riskScore={session.latest_risk_score}
          />
        </div>
      </div>

      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">
            MITRE ATT&CK Kill Chain Progression
          </span>
          <span className="panel-meta">
            Sequential threat pipeline telemetry
          </span>
        </div>
        <div className="panel-body">
          <KillChain
            currentStage={session.latest_stage}
            forecastStages={forecastStages}
          />
        </div>
      </div>

      <div className="forecast-grid">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">
              Temporal Attack Progression Forecast
            </span>
            <span className="panel-meta">
              Monte Carlo (n=20) &bull; EMA (&alpha;=0.4)
            </span>
          </div>
          <div
            className="panel-body chart-container"
            style={{ minHeight: 320 }}
          >
            <p
              className="mono text-xs text-muted"
              style={{ marginBottom: "var(--sp-2)" }}
            >
              Projected probability this session is compromised,{" "}
              {chartData.length} steps into the future
              {avgStepMs
                ? ` (~${formatEta(1)?.replace("~", "")} per step, based on this session's own flow rate)`
                : ""}
              . The shaded band indicates model uncertainty across 20 Monte
              Carlo rollouts.
            </p>
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart
                data={chartData}
                margin={{ top: 10, right: 20, bottom: 5, left: 10 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#3A3228" />
                <XAxis
                  dataKey="step"
                  tick={{ fontSize: 11, fill: "#B8B0A3" }}
                  label={{
                    value: "Forecast Steps Ahead",
                    position: "insideBottom",
                    offset: -3,
                    fontSize: 11,
                    fill: "#B8B0A3",
                  }}
                />
                <YAxis
                  domain={[0, 1]}
                  ticks={[0, 0.25, 0.5, 0.75, 1.0]}
                  tick={{ fontSize: 11, fill: "#B8B0A3" }}
                  label={{
                    value: "Infiltration Risk",
                    angle: -90,
                    position: "insideLeft",
                    fontSize: 11,
                    fill: "#B8B0A3",
                  }}
                />
                <Tooltip
                  contentStyle={{
                    background: "#241F18",
                    border: "1px solid #3A3228",
                    borderRadius: 4,
                    fontSize: 12,
                    color: "#F5F1E8",
                  }}
                  labelStyle={{ color: "#D6B36A", fontWeight: 700 }}
                  formatter={(value, name) => [
                    typeof value === "number" ? value.toFixed(3) : value,
                    name,
                  ]}
                  labelFormatter={(label, payload) => {
                    const eta = payload?.[0]?.payload?.stepNum
                      ? formatEta(payload[0].payload.stepNum)
                      : null;
                    return `Step ${label}${eta ? ` (ETA ${eta})` : ""}`;
                  }}
                />
                <Legend
                  verticalAlign="top"
                  height={28}
                  wrapperStyle={{ fontSize: 11, color: "#B8B0A3" }}
                />
                <Area
                  type="monotone"
                  dataKey="upper"
                  stroke="none"
                  fill="#D6B36A"
                  fillOpacity={0.12}
                  stackId="band"
                  isAnimationActive={false}
                  name="Uncertainty band"
                  legendType="none"
                />
                <Area
                  type="monotone"
                  dataKey="lower"
                  stroke="none"
                  fill="#1A1610"
                  fillOpacity={1}
                  stackId="band"
                  isAnimationActive={false}
                  legendType="none"
                />
                <Area
                  type="monotone"
                  dataKey="mean"
                  stroke="#D6B36A"
                  strokeWidth={2.5}
                  fill="none"
                  name="Risk (MC mean)"
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="ema"
                  stroke="#B8B0A3"
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                  fill="none"
                  name="Smoothed trend (EMA)"
                  isAnimationActive={false}
                />
                <ReferenceLine
                  y={forecast?.threshold || 0.5}
                  stroke="#C94A45"
                  strokeDasharray="6 4"
                  strokeWidth={1.5}
                  label={{
                    value: "Alert threshold (0.5)",
                    position: "right",
                    fill: "#C94A45",
                    fontSize: 10,
                    fontWeight: 700,
                  }}
                />
              </AreaChart>
            </ResponsiveContainer>

            <div className="stage-track">
              {chartData.map((d, i) => (
                <div
                  key={i}
                  className="stage-track-item"
                  style={{
                    background: stageColor(d.stage) + "18",
                    color: stageColor(d.stage),
                  }}
                >
                  {d.stage}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">
              Feature Attribution (Explainable AI)
            </span>
            <span className="panel-meta">
              {explanation?.method_used === "shap"
                ? "Shapley Values (Game-Theoretic)"
                : "Gradient × Input"}
            </span>
          </div>
          <div className="panel-body">
            {explanation && (
              <>
                <div
                  style={{
                    marginBottom: "var(--sp-3)",
                    display: "flex",
                    gap: "var(--sp-4)",
                    alignItems: "baseline",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <span
                      className="mono"
                      style={{
                        fontSize: "1.2rem",
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
                      className="text-sm text-muted"
                      style={{ marginLeft: "var(--sp-2)" }}
                    >
                      Infiltration Risk
                    </span>
                  </div>
                  <span
                    className={`stage-badge ${stageClass(explanation.predicted_stage)}`}
                  >
                    {explanation.predicted_stage}
                  </span>
                </div>

                <div className="shap-bar-container">
                  {explanation.attributions.map((attr, i) => {
                    const isMalicious = attr.importance > 0;
                    const dir =
                      attr.direction || (isMalicious ? "malicious" : "benign");
                    const pct = Math.min(
                      100,
                      (Math.abs(attr.importance) / maxImportance) * 100,
                    );
                    return (
                      <div key={i} className="shap-row">
                        <div className="shap-row-header">
                          <span
                            className="shap-feature-name"
                            title={attr.feature}
                          >
                            {formatFeatureName(attr.feature)}
                            <span className="shap-feature-code">
                              [{attr.feature}]
                            </span>
                          </span>
                          <span className={`shap-value ${dir}`}>
                            {isMalicious ? "+" : ""}
                            {attr.importance.toFixed(4)}
                          </span>
                        </div>
                        <div className="shap-bar-track">
                          <div
                            className={`shap-bar ${dir}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div
                  style={{
                    marginTop: "var(--sp-3)",
                    display: "flex",
                    gap: "var(--sp-4)",
                    fontSize: "0.68rem",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <span style={{ color: "var(--c-red)", fontWeight: 700 }}>
                    &#9632; PUSHES &rarr; MALICIOUS
                  </span>
                  <span
                    style={{ color: "var(--severity-low)", fontWeight: 700 }}
                  >
                    &#9632; PUSHES &rarr; BENIGN
                  </span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Session Flow Telemetry Records</span>
          <span className="panel-meta">
            {flows.length} flow records &middot; most recent first
          </span>
        </div>
        <div style={{ maxHeight: "380px", overflowY: "auto" }}>
          {flows.length === 0 ? (
            <div className="empty-state">
              <p>No flow records.</p>
            </div>
          ) : (
            <table className="data-table" style={{ fontSize: "0.68rem" }}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp</th>
                  <th>Duration</th>
                  <th>Fwd Pkts</th>
                  <th>Bwd Pkts</th>
                  <th>Bytes/s</th>
                  <th>Pkts/s</th>
                  <th>SYN</th>
                  <th>ACK</th>
                  <th>RST</th>
                  <th>PSH</th>
                  <th>FIN</th>
                  <th>URG</th>
                  <th>TTL Var</th>
                  <th>TCP Win</th>
                  <th>Retx</th>
                  <th>Infiltration Risk</th>
                  <th>Predicted Stage</th>
                  <th>Origin</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((f, i) => {
                  const feat = f.features || {};
                  const prob = f.infiltration_prob || 0;
                  const isAlert = prob > 0.5;
                  return (
                    <tr
                      key={f.id}
                      style={{
                        cursor: "default",
                        background: isAlert
                          ? "rgba(201, 74, 69, 0.08)"
                          : undefined,
                      }}
                    >
                      <td style={{ color: "var(--text-muted)" }}>
                        {flows.length - i}
                      </td>
                      <td>{formatTime(f.timestamp)}</td>
                      <td>{formatDuration(feat.flow_duration)}</td>
                      <td>{(feat.tot_fwd_pkts ?? 0).toFixed(0)}</td>
                      <td>{(feat.tot_bwd_pkts ?? 0).toFixed(0)}</td>
                      <td>{(feat.flow_bytes_s ?? 0).toFixed(0)}</td>
                      <td>{(feat.flow_pkts_s ?? 0).toFixed(1)}</td>
                      <td
                        style={{
                          color:
                            (feat.syn_flag_cnt ?? 0) > 3
                              ? "var(--severity-high)"
                              : undefined,
                        }}
                      >
                        {(feat.syn_flag_cnt ?? 0).toFixed(0)}
                      </td>
                      <td>{(feat.ack_flag_cnt ?? 0).toFixed(0)}</td>
                      <td
                        style={{
                          color:
                            (feat.rst_flag_cnt ?? 0) > 0
                              ? "var(--severity-medium)"
                              : undefined,
                        }}
                      >
                        {(feat.rst_flag_cnt ?? 0).toFixed(0)}
                      </td>
                      <td>{(feat.psh_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.fin_flag_cnt ?? 0).toFixed(0)}</td>
                      <td
                        style={{
                          color:
                            (feat.urg_flag_cnt ?? 0) > 0
                              ? "var(--severity-critical)"
                              : undefined,
                        }}
                      >
                        {(feat.urg_flag_cnt ?? 0).toFixed(0)}
                      </td>
                      <td>{(feat.ttl_variance ?? 0).toFixed(1)}</td>
                      <td>{(feat.tcp_win_size ?? 0).toFixed(0)}</td>
                      <td
                        style={{
                          color:
                            (feat.retransmit_cnt ?? 0) > 2
                              ? "var(--severity-high)"
                              : undefined,
                        }}
                      >
                        {(feat.retransmit_cnt ?? 0).toFixed(0)}
                      </td>
                      <td
                        style={{
                          color: isAlert
                            ? "var(--severity-critical)"
                            : "var(--severity-low)",
                          fontWeight: isAlert ? 700 : 400,
                        }}
                      >
                        {formatProb(prob)}
                      </td>
                      <td>
                        <span
                          className={`stage-badge ${stageClass(f.predicted_stage || "Benign")}`}
                        >
                          {f.predicted_stage || "Benign"}
                        </span>
                      </td>
                      <td>
                        <SourceBadge src={f.source} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
