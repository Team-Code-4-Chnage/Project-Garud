import { useState, useEffect, useMemo } from "react";
import {
  ComposedChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Network, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import { apiFetch } from "../api";
import { formatFeatureName } from "../utils";

const fmtStat = (v) => (v == null ? "-" : v.toFixed(2));

const REFRESH_MS = 10000;
const STATE_LABELS = {
  n_flows: "Flows / min",
  n_uniq_src_ip: "Source hosts",
  n_uniq_dst_ip: "Destination hosts",
  n_uniq_dst_port: "Destination ports",
  n_new_conn_rate: "New connections / s",
  f_syn_ratio: "SYN share",
  f_rst_ratio: "RST share",
  f_small_flow_frac: "Flows of 2 packets or fewer",
  n_ent_dst_port: "Port entropy (bits)",
  n_dport_per_src_max: "Max ports per source",
  f_total_bytes: "Bytes / min",
};

const hhmm = (iso) => (iso ? iso.slice(11, 16) : "");
const fmt = (v) =>
  v == null
    ? "-"
    : Math.abs(v) >= 1000
      ? Math.round(v).toLocaleString()
      : Number(v).toFixed(v < 10 ? 2 : 0);

function NetworkForecastView() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const res = await apiFetch("/network/forecast");
        if (active) {
          setData(res);
          setError(null);
        }
      } catch (e) {
        if (active) setError(e.message);
      }
    };
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, []);

  const chart = useMemo(() => {
    if (!data || data.status !== "ok") return [];
    const hist = data.minutes.map((m, i) => ({
      minute: hhmm(m),
      observed: data.risk_score[i],
      alert: data.alert[i] ? data.risk_score[i] : null,
    }));
    const last = hist[hist.length - 1];
    const fc = data.forecast.map((s) => ({
      minute: hhmm(s.minute),
      forecast: s.risk,
    }));
    if (last) last.forecast = last.observed;
    return [...hist.slice(-40), ...fc];
  }, [data]);

  if (error)
    return (
      <div className="panel">
        <div className="panel-body text-muted">Network model: {error}</div>
      </div>
    );
  if (!data)
    return (
      <div className="panel">
        <div className="panel-body">
          <Loader2 size={16} className="spin" /> Loading
        </div>
      </div>
    );

  const header = (
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
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Network size={16} color="var(--c-gold)" />
        <span className="panel-title">Attack Forecast &bull; Network World Model</span>
      </div>
      <span
        className="mono text-xs text-muted"
        style={{ letterSpacing: "0.06em" }}
      >
        Combined forecast across all monitored traffic
      </span>
    </div>
  );

  if (data.status === "no_data") {
    return (
      <div className="panel">
        {header}
        <div className="panel-body text-muted">
          No flows yet. Upload a PCAP or CSV, or start capture.
        </div>
      </div>
    );
  }
  if (data.status === "warming_up") {
    return (
      <div className="panel">
        {header}
        <div className="panel-body text-muted">
          Building network state: {data.minutes_available} of{" "}
          {data.minutes_needed} minutes of traffic recorded. The model needs{" "}
          {data.minutes_needed} consecutive minutes before it can forecast.
        </div>
      </div>
    );
  }

  const cur = data.current;
  const info = data.model;
  const tr = info.test_results;
  return (
    <div>
      <div
        className="panel mb-4"
        style={{
          borderLeft: cur.alert
            ? "4px solid var(--c-red)"
            : "4px solid var(--severity-low)",
        }}
      >
        {header}
        <div
          className="panel-body"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 16,
            flexWrap: "wrap",
            padding: "14px 20px",
            background: cur.alert
              ? "rgba(201, 74, 69, 0.08)"
              : "rgba(88, 166, 104, 0.05)",
          }}
        >
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 14px",
              borderRadius: "var(--radius-sm)",
              background: cur.alert
                ? "rgba(201, 74, 69, 0.2)"
                : "rgba(88, 166, 104, 0.15)",
              border: `1px solid ${cur.alert ? "var(--c-red)" : "var(--severity-low)"}`,
              color: cur.alert ? "var(--c-red)" : "var(--severity-low)",
              fontWeight: 800,
              fontSize: "0.85rem",
              letterSpacing: "0.04em",
            }}
          >
            {cur.alert ? (
              <AlertTriangle size={18} strokeWidth={2.5} />
            ) : (
              <ShieldCheck size={18} strokeWidth={2.5} />
            )}
            {cur.alert
              ? "NATIONAL DEFENSE ALERT: SUSTAINED ATTACK DETECTED"
              : "DEFENSE TELEMETRY NOMINAL: NO SUSTAINED ATTACK"}
          </div>

          <div
            className="mono"
            style={{ fontSize: "0.88rem", color: "var(--text-primary)" }}
          >
            WINDOW:{" "}
            <strong style={{ color: "var(--c-gold)" }}>
              {hhmm(cur.minute)} UTC
            </strong>{" "}
            &middot; RISK OVER NEXT 4 MIN:{" "}
            <strong
              style={{
                color: cur.risk_score > 0.5 ? "var(--c-red)" : "var(--c-gold)",
                fontSize: "1.1rem",
              }}
            >
              {(cur.risk_score * 100).toFixed(1)}%
            </strong>
          </div>

          <div
            className="mono text-xs text-muted"
            style={{
              padding: "4px 10px",
              background: "var(--bg-dark)",
              borderRadius: "var(--radius-sm)",
            }}
          >
            Rule: risk &ge; {(cur.threshold * 100).toFixed(1)}% for{" "}
            {cur.consecutive_needed} consecutive min
          </div>
        </div>
      </div>

      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">Network Macro Risk Timeline</span>
          <span className="panel-meta">
            Observed traffic timeline &plus; 4-minute future projection
          </span>
        </div>
        <div className="panel-body chart-container" style={{ minHeight: 280 }}>
          <ResponsiveContainer width="100%" height={260}>
            <ComposedChart
              data={chart}
              margin={{ top: 10, right: 20, bottom: 5, left: 10 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#3A3228" />
              <XAxis
                dataKey="minute"
                tick={{ fontSize: 10, fill: "#B8B0A3" }}
              />
              <YAxis
                domain={[0, 1]}
                tickFormatter={(v) => `${Math.round(v * 100)}%`}
                tick={{ fontSize: 10, fill: "#B8B0A3" }}
              />
              <Tooltip
                contentStyle={{
                  background: "#241F18",
                  border: "1px solid #3A3228",
                  borderRadius: 4,
                  color: "#F5F1E8",
                  fontSize: 12,
                }}
                formatter={(v) =>
                  v == null ? "-" : `${(v * 100).toFixed(1)}%`
                }
              />
              <Legend wrapperStyle={{ color: "#B8B0A3", fontSize: 11 }} />
              <ReferenceLine
                y={cur.threshold}
                stroke="#C94A45"
                strokeDasharray="6 4"
                label={{
                  value: "alert threshold",
                  fill: "#C94A45",
                  fontSize: 10,
                }}
              />
              <Line
                type="monotone"
                dataKey="observed"
                name="observed risk / min"
                stroke="#D6B36A"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="alert"
                name="sustained alert"
                stroke="#C94A45"
                strokeWidth={3}
                dot={{ r: 3 }}
                connectNulls={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="forecast"
                name="forecast t+1..t+4"
                stroke="#D6B36A"
                strokeWidth={2}
                strokeDasharray="5 4"
                dot={{ r: 3 }}
                isAnimationActive={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div
        className="grid-2 mb-4"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: 16,
        }}
      >
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Predicted Network Macro State</span>
            <span className="panel-meta">
              Current baseline vs model rollout
            </span>
          </div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>{hhmm(cur.minute)}</th>
                  {data.forecast.map((s) => (
                    <th key={s.step}>+{s.step}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.keys(STATE_LABELS)
                  .filter((f) => data.state[f])
                  .map((f) => (
                    <tr key={f}>
                      <td>{STATE_LABELS[f]}</td>
                      <td>{fmt(data.state[f][data.state[f].length - 1])}</td>
                      {data.forecast.map((s) => (
                        <td key={s.step}>{fmt(s.state[f])}</td>
                      ))}
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Multi-Step Behaviour Rollout</span>
            <span className="panel-meta">
              Behavior classification &bull; MITRE ATT&CK mapping
            </span>
          </div>
          <div className="panel-body">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Risk</th>
                  <th>Most Likely Behavior</th>
                  <th>ATT&CK Lookup</th>
                </tr>
              </thead>
              <tbody>
                {data.forecast.map((s) => {
                  const b = s.behaviours[0];
                  return (
                    <tr key={s.step}>
                      <td>
                        +{s.step} ({hhmm(s.minute)})
                      </td>
                      <td
                        style={{
                          fontWeight: 700,
                          color:
                            s.risk > 0.5 ? "var(--c-red)" : "var(--c-gold)",
                        }}
                      >
                        {(s.risk * 100).toFixed(1)}%
                      </td>
                      <td>
                        {b.behaviour} ({(b.probability * 100).toFixed(0)}%)
                      </td>
                      <td>
                        {b.techniques.length
                          ? `${b.techniques.join(" / ")} (${b.tactics.join(", ")})`
                          : "-"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div
        className="grid-2 mb-4"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: 16,
        }}
      >
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Risk Factor Attribution</span>
            <span className="panel-meta">
              Gradient &times; input risk contribution
            </span>
          </div>
          <div className="panel-body">
            {(() => {
              const maxContr = Math.max(
                ...data.explanation.map((e) => Math.abs(e.contribution)),
                0.001,
              );
              return (
                <div className="shap-bar-container">
                  {data.explanation.map((e) => {
                    const isPositive = e.contribution > 0;
                    const dir = isPositive ? "malicious" : "benign";
                    const pct = Math.min(
                      100,
                      (Math.abs(e.contribution) / maxContr) * 100,
                    );
                    return (
                      <div key={e.feature} className="shap-row">
                        <div className="shap-row-header">
                          <span className="shap-feature-name" title={e.feature}>
                            {STATE_LABELS[e.feature] ||
                              formatFeatureName(e.feature)}
                            <span className="shap-feature-code">
                              [{e.feature}]
                            </span>
                          </span>
                          <span className={`shap-value ${dir}`}>
                            {isPositive ? "+" : ""}
                            {e.contribution.toFixed(4)}
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
              );
            })()}
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
                &#9632; RAISES ATTACK RISK
              </span>
              <span style={{ color: "var(--severity-low)", fontWeight: 700 }}>
                &#9632; LOWERS RISK (BENIGN BASELINE)
              </span>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Model Benchmark & Validation</span>
            <span className="panel-meta">
              {info.version} &middot; {info.n_features} features
            </span>
          </div>
          <div className="panel-body">
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
                gap: 8,
                marginBottom: 14,
              }}
            >
              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  ROC-AUC TEST
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--c-gold)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {fmtStat(tr.detection.roc_auc)}
                </div>
              </div>

              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  F1 SCORE
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--severity-low)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {fmtStat(tr.detection.f1)}
                </div>
              </div>

              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  FALSE ALARMS / HR
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--text-primary)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {fmtStat(tr.early_warning.false_alarms_per_quiet_hour)}
                </div>
              </div>

              <div
                style={{
                  background: "var(--bg-dark)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "8px 10px",
                }}
              >
                <div
                  style={{
                    fontSize: "0.68rem",
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  EARLY WARN &le; 20m
                </div>
                <div
                  style={{
                    fontSize: "1.15rem",
                    fontWeight: 800,
                    color: "var(--c-gold)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {tr.early_warning.warned_within_20} /{" "}
                  {tr.early_warning.episodes}
                </div>
              </div>
            </div>

            <div
              style={{
                fontSize: "0.78rem",
                color: "var(--text-secondary)",
                lineHeight: 1.4,
                marginBottom: 8,
              }}
            >
              Evaluated on held-out 25% partition of CIC-IDS2017 defense
              benchmarks.
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {info.caveats.map((c) => (
                <div
                  key={c}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 6,
                    fontSize: "0.74rem",
                    color: "var(--text-muted)",
                  }}
                >
                  <span style={{ color: "var(--c-gold)" }}>&rsaquo;</span>
                  <span>{c}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default NetworkForecastView;
