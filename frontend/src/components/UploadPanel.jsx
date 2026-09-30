import { useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Info,
  ShieldCheck,
  Upload,
} from "lucide-react";
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiUpload } from "../api";
import ForecastChart, { getPointMeta, getStageMeta } from "./ForecastChart";

const pct = (v, d = 1) => (v == null ? "-" : `${(v * 100).toFixed(d)}%`);
const num = (v) => (v == null ? "-" : Number(v).toLocaleString());
const fix = (v, d = 2) => (v == null ? "-" : Number(v).toFixed(d));

const shortTime = (iso, withDate) =>
  withDate ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : iso.slice(11, 16);
const longTime = (iso) => `${iso.slice(0, 10)} ${iso.slice(11, 16)}`;

// Plain-language reading of an AUC value
function grade(auc) {
  if (auc == null) return { text: "not measurable (one class only)", color: "var(--text-muted)" };
  if (auc >= 0.9) return { text: "strong", color: "#34D399" };
  if (auc >= 0.75) return { text: "moderate", color: "#F6B144" };
  if (auc >= 0.6) return { text: "weak", color: "#E8873A" };
  return { text: "close to chance", color: "#F64541" };
}

function Card({ label, value, sub, color }) {
  return (
    <div className="stat-card">
      <div className="stat-card-label">{label}</div>
      <div className="stat-card-value" style={{ color }}>
        {value}
      </div>
      {sub && (
        <div className="text-muted text-xs" style={{ marginTop: 2 }}>
          {sub}
        </div>
      )}
    </div>
  );
}

function Panel({ title, meta, children, body = true }) {
  return (
    <div className="panel" style={{ marginBottom: "var(--sp-3)" }}>
      <div className="panel-header">
        <span className="panel-title">{title}</span>
        {meta && <span className="panel-meta">{meta}</span>}
      </div>
      {body ? <div className="panel-body">{children}</div> : children}
    </div>
  );
}

const mono = { lineHeight: 1.7, color: "var(--text-secondary)" };

function Pipeline({ steps }) {
  return (
    <Panel title="Automatic Processing" meta={`${steps.reduce((a, s) => a + s.seconds, 0).toFixed(1)} s`}>
      <div style={{ display: "grid", gap: 8 }}>
        {steps.map((s) => (
          <div key={s.step} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <CheckCircle2 size={16} color="#34D399" style={{ marginTop: 2, flex: "none" }} />
            <div style={{ flex: 1 }}>
              <span className="mono text-xs uppercase" style={{ fontWeight: 700, color: "var(--text-primary)" }}>
                {s.step}
              </span>
              <span className="mono text-xs" style={{ color: "var(--text-secondary)", marginLeft: 8 }}>
                {s.detail}
              </span>
            </div>
            <span className="mono text-xs text-muted">{s.seconds}s</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function SegmentBar({ segments, active, onPick }) {
  if (segments.length <= 1) return null;
  return (
    <Panel title="Activity Periods in the File" meta="the timeline is split where traffic stops for over an hour">
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {segments.map((s) => {
          const on = s.id === active;
          const peak = s.peak_risk;
          return (
            <button
              key={s.id}
              className="btn"
              disabled={s.status !== "ok"}
              onClick={() => onPick(s.id)}
              style={{
                borderColor: on ? "var(--c-gold)" : undefined,
                background: on ? "rgba(214,179,106,0.12)" : undefined,
                textAlign: "left",
              }}
            >
              <div className="mono text-xs">{longTime(s.start)} &rarr; {longTime(s.end)}</div>
              <div className="mono text-xs text-muted">
                {s.minutes} min &bull; {num(s.flows)} flows &bull;{" "}
                {s.status === "ok" ? `forecast peak ${pct(peak, 0)}` : "too short for the model"}
              </div>
            </button>
          );
        })}
      </div>
    </Panel>
  );
}

function ForecastBlock({ seg }) {
  const fc = seg.forecast;
  const adapted = useMemo(() => {
    const first = fc.steps[0];
    const top = first.behaviours[0];
    const attackNow = first.risk >= fc.threshold && top.behaviour !== "Benign";
    return {
      status: "ok",
      minutes: seg.per_minute.map((p) => p.minute),
      risk_score: seg.per_minute.map((p) => p.model_risk),
      stages: seg.per_minute.map((p) => (p.flagged > 0 ? p.behaviour : "Benign")),
      alert: seg.per_minute.map((p) => p.alert),
      forecast: fc.steps,
      current: { attack_stage: attackNow ? top.behaviour : "Benign", threshold: fc.threshold },
    };
  }, [seg, fc]);

  return (
    <Panel
      title="Forecast at the End of This Period"
      meta={`issued after ${longTime(seg.end)} by the network-state model, unadjusted`}
      body={false}
    >
      <div style={{ padding: "8px 12px 12px" }}>
        <ForecastChart forecastData={adapted} maxHistory={180} />
      </div>
      <div className="panel-body" style={{ overflowX: "auto", paddingTop: 0 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Minute</th>
              <th>Risk</th>
              <th>Most likely behaviour</th>
              <th>Next most likely</th>
              <th>Flows</th>
              <th>Distinct dest. ports</th>
            </tr>
          </thead>
          <tbody>
            {fc.steps.map((s) => {
              const meta = getStageMeta(s.behaviours[0].behaviour);
              return (
                <tr key={s.step}>
                  <td className="mono">
                    t+{s.step} ({s.minute.slice(11, 16)})
                  </td>
                  <td style={{ fontWeight: 700, color: s.risk >= fc.threshold ? "var(--c-red)" : undefined }}>
                    {pct(s.risk, 0)}
                  </td>
                  <td>
                    <span style={{ color: meta.color, fontWeight: 700 }}>&bull; {s.behaviours[0].behaviour}</span>{" "}
                    <span className="text-muted">{pct(s.behaviours[0].probability, 0)}</span>
                  </td>
                  <td className="text-muted">
                    {s.behaviours.slice(1).map((b) => `${b.behaviour} ${pct(b.probability, 0)}`).join(", ")}
                  </td>
                  <td>{num(Math.round(s.state.n_flows ?? 0))}</td>
                  <td>{num(Math.round(s.state.n_uniq_dst_port ?? 0))}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="mono text-xs text-muted" style={{ marginTop: 6 }}>
          Alert rule of the model: risk at or above {pct(fc.threshold, 1)} for {fc.sustained_minutes_needed} minutes in a
          row. Currently {fc.alert ? "ACTIVE" : "not active"}.
        </div>
      </div>
    </Panel>
  );
}

// Same colour language as the dashboard's Attack Probability Forecast: green is normal, the line turns
// cyan, amber, orange and red as the risk and the predicted behaviour escalate.
const RISK_KEY = [
  { color: "#34D399", text: "Normal" },
  { color: "#39DFEB", text: "Probing (below threshold)" },
  { color: "#F6B144", text: "Elevated" },
  { color: "#E8873A", text: "Warning" },
  { color: "#E5633E", text: "High" },
  { color: "#F64541", text: "Critical (85% and above)" },
];

function TimelineBlock({ seg, labelled }) {
  const thr = seg.forecast.threshold;
  const span = new Date(seg.end) - new Date(seg.start) > 24 * 3600 * 1000;
  const gradId = `riskLine${seg.id}`;
  const data = useMemo(
    () =>
      seg.per_minute.map((p) => {
        const stage = p.flagged > 0 ? p.behaviour : "Benign";
        const meta = p.model_risk == null ? null : getPointMeta(p.model_risk, stage, thr);
        return {
          t: shortTime(p.minute, span),
          risk: p.model_risk,
          color: meta ? meta.color : "#34D399",
          stage: meta ? meta.label : "-",
          actual: labelled ? (p.labelled_attacks > 0 ? 1 : 0) : null,
          flaggedShare: p.flows ? p.flagged / p.flows : 0,
          alert: p.alert,
        };
      }),
    [seg, thr, span, labelled],
  );
  const stops = data.map((d, i) => ({ offset: data.length > 1 ? (i / (data.length - 1)) * 100 : 0, color: d.color }));

  const renderDot = ({ cx, cy, payload }) => {
    if (cx == null || cy == null || payload.risk == null) return null;
    if (payload.alert) {
      return <circle key={`d${cx}`} cx={cx} cy={cy} r={5} fill={payload.color} stroke="#fff" strokeWidth={1.5} />;
    }
    return <circle key={`d${cx}`} cx={cx} cy={cy} r={2.2} fill={payload.color} stroke="none" />;
  };

  return (
    <Panel
      title="Prediction Timeline"
      meta={labelled ? "model risk, coloured by severity, over the attack minutes labelled in the file" : "model risk, coloured by severity, and the share of flows the classifier flagged"}
    >
      <div style={{ height: 300 }}>
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: -8 }}>
            <defs>
              <linearGradient id={gradId} x1="0" y1="0" x2="1" y2="0">
                {stops.map((st, i) => (
                  <stop key={i} offset={`${st.offset}%`} stopColor={st.color} />
                ))}
              </linearGradient>
              <linearGradient id={`${gradId}Fill`} x1="0" y1="0" x2="1" y2="0">
                {stops.map((st, i) => (
                  <stop key={i} offset={`${st.offset}%`} stopColor={st.color} stopOpacity={0.22} />
                ))}
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={28} />
            <YAxis domain={[0, 1]} tick={{ fontSize: 10 }} tickFormatter={(v) => `${Math.round(v * 100)}%`} />
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload || !payload.length) return null;
                const d = payload[0].payload;
                return (
                  <div className="mono" style={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 4, padding: "8px 12px", fontSize: 11 }}>
                    <div style={{ color: "var(--text-muted)", marginBottom: 4 }}>{d.t}</div>
                    <div>
                      Risk: <strong style={{ color: d.color }}>{d.risk == null ? "-" : pct(d.risk, 1)}</strong>
                    </div>
                    <div>
                      Level: <span style={{ color: d.color, fontWeight: 700 }}>&bull; {d.stage}</span>
                    </div>
                    {d.alert && <div style={{ color: "#F64541", fontWeight: 700 }}>Sustained alert</div>}
                    {labelled ? (
                      <div>File labels: {d.actual ? "attack in this minute" : "no attack"}</div>
                    ) : (
                      <div>Flows flagged: {pct(d.flaggedShare, 0)}</div>
                    )}
                  </div>
                );
              }}
            />
            {labelled ? (
              <Area type="stepAfter" dataKey="actual" name="Attack minutes in the file" stroke="none" fill="#F64541" fillOpacity={0.14} isAnimationActive={false} />
            ) : (
              <Area type="monotone" dataKey="flaggedShare" name="Share of flows flagged" stroke="none" fill="#F6B144" fillOpacity={0.16} isAnimationActive={false} />
            )}
            <Area type="monotone" dataKey="risk" stroke="none" fill={`url(#${gradId}Fill)`} connectNulls isAnimationActive={false} />
            <ReferenceLine y={thr} stroke="#F6B144" strokeDasharray="5 4" label={{ value: `Threshold ${thr.toFixed(2)}`, fontSize: 10, fill: "#F6B144", position: "insideTopRight" }} />
            <Line type="monotone" dataKey="risk" stroke={`url(#${gradId})`} strokeWidth={2.5} dot={renderDot} activeDot={{ r: 5 }} connectNulls isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px 16px", marginTop: 8 }} className="mono text-xs">
        {RISK_KEY.map((k) => (
          <span key={k.text} style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-secondary)" }}>
            <span style={{ width: 16, height: 3, borderRadius: 2, background: k.color }} /> {k.text}
          </span>
        ))}
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-secondary)" }}>
          <span style={{ width: 9, height: 9, borderRadius: "50%", border: "2px solid #fff", background: "#F64541" }} /> Sustained alert
        </span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-secondary)" }}>
          <span style={{ width: 16, height: 8, background: labelled ? "rgba(246,69,65,0.25)" : "rgba(246,177,68,0.3)" }} />
          {labelled ? "Attack minutes labelled in the file" : "Share of flows flagged"}
        </span>
      </div>
    </Panel>
  );
}

function QualityBlock({ seg }) {
  const bt = seg.backtest;
  const se = seg.state_evaluation;
  if (!bt && !se) return null;
  const track = se?.n_flows_tracking;
  const span = new Date(seg.end) - new Date(seg.start) > 24 * 3600 * 1000;
  return (
    <Panel title="How Good Was the Forecast on This File" meta="every forecast issued inside the period, checked against what happened next">
      {bt && (
        <div style={{ overflowX: "auto", marginBottom: 12 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Forecast for</th>
                <th>Windows checked</th>
                <th>ROC-AUC (attack in that minute)</th>
                <th>PR-AUC</th>
                <th>Reading</th>
              </tr>
            </thead>
            <tbody>
              {bt.per_horizon.map((h) => {
                const g = grade(h.roc_auc);
                return (
                  <tr key={h.horizon}>
                    <td>t+{h.horizon} min</td>
                    <td>{h.windows}</td>
                    <td>{fix(h.roc_auc, 3)}</td>
                    <td>{fix(h.pr_auc, 3)}</td>
                    <td style={{ color: g.color, fontWeight: 700 }}>{g.text}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="mono text-xs" style={{ ...mono, marginTop: 6 }}>
            {bt.attack_minutes} attack minutes and {bt.quiet_minutes} quiet minutes in this period.
            {bt.early_warning && (
              <>
                {" "}
                Early warning: {bt.early_warning.warned_within_20_min} of {bt.early_warning.episodes} attack episodes
                were warned within 20 minutes before onset
                {bt.early_warning.median_lead_minutes != null && ` (median lead ${bt.early_warning.median_lead_minutes} min)`};{" "}
                {bt.early_warning.false_alarm_events} false alarm events in {fix(bt.early_warning.quiet_hours, 1)} quiet hours.
              </>
            )}
            {bt.next_minute_behaviour_accuracy_on_attack_minutes && (
              <>
                {" "}
                Behaviour named correctly for the next minute in {bt.next_minute_behaviour_accuracy_on_attack_minutes.correct} of{" "}
                {bt.next_minute_behaviour_accuracy_on_attack_minutes.minutes} attack minutes.
              </>
            )}
          </div>
        </div>
      )}
      {se && (
        <>
          <div style={{ overflowX: "auto", marginBottom: 8 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>State prediction error</th>
                  {se.horizons.map((h) => (
                    <th key={h}>t+{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Model (mean squared error)</td>
                  {se.model_mse.map((v, i) => (
                    <td key={i}>{fix(v, 3)}</td>
                  ))}
                </tr>
                <tr>
                  <td>Repeat last minute</td>
                  {se.persistence_mse.map((v, i) => (
                    <td key={i}>{fix(v, 3)}</td>
                  ))}
                </tr>
                <tr>
                  <td>Model better than repeating</td>
                  {se.model_mse.map((v, i) => (
                    <td key={i} style={{ color: v < se.persistence_mse[i] ? "#34D399" : "#F64541", fontWeight: 700 }}>
                      {v < se.persistence_mse[i] ? "yes" : "no"}
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>
          {track && track.length > 1 && (
            <div style={{ height: 200 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart
                  data={track.map((r) => ({ t: shortTime(r.minute, span), predicted: r.predicted, actual: r.actual }))}
                  margin={{ top: 8, right: 16, bottom: 0, left: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={28} />
                  <YAxis tick={{ fontSize: 10 }} />
                  <Tooltip formatter={(v) => Math.round(v).toLocaleString()} />
                  <Legend />
                  <Line type="monotone" dataKey="actual" name="Flows in the minute (actual)" stroke="#34D399" dot={false} strokeWidth={2} />
                  <Line type="monotone" dataKey="predicted" name="Predicted one minute ahead" stroke="#F6B144" dot={false} strokeDasharray="5 4" strokeWidth={2} />
                </ComposedChart>
              </ResponsiveContainer>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

function FlowBlock({ result }) {
  const ev = result.evaluation;
  const labels = result.labels;
  const rows = Object.entries(labels.predicted_counts).sort((a, b) => b[1] - a[1]);
  const total = rows.reduce((a, [, v]) => a + v, 0) || 1;
  return (
    <>
      {ev ? (
        <Panel title="Flow Classifier against the Labels in the File" meta={`label column: ${result.schema.label_column}`}>
          <div className="stats-bar" style={{ marginBottom: 10 }}>
            <Card label="ROC-AUC" value={fix(ev.roc_auc, 3)} sub={grade(ev.roc_auc).text} color={grade(ev.roc_auc).color} />
            <Card label="Recall" value={pct(ev.recall)} sub={`${num(ev.true_positive)} of ${num(ev.malicious)} attack flows`} />
            <Card label="Precision" value={pct(ev.precision)} sub={`${num(ev.false_positive)} benign flows flagged`} />
            <Card label="False-positive rate" value={pct(ev.false_positive_rate, 2)} sub={`of ${num(ev.benign)} benign flows`} />
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Attack family in the file</th>
                  <th>Flows</th>
                  <th>Detected</th>
                  <th>Named correctly</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(ev.families).map(([f, v]) => (
                  <tr key={f}>
                    <td style={{ color: getStageMeta(f).color, fontWeight: 700 }}>{f}</td>
                    <td>{num(v.rows)}</td>
                    <td>{pct(v.detected)}</td>
                    <td>{pct(v.family_correct)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}
      <Panel
        title={labels.source === "file" ? "Behaviour Predicted by the Flow Classifier" : "Predicted Labels (the file has none)"}
        meta={`${num(result.summary.flagged_flows)} of ${num(result.rows)} flows flagged`}
      >
        <div style={{ display: "grid", gap: 6 }}>
          {rows.map(([name, v]) => (
            <div key={name} style={{ display: "grid", gridTemplateColumns: "130px 1fr 90px", gap: 8, alignItems: "center" }}>
              <span className="mono text-xs" style={{ color: getStageMeta(name).color, fontWeight: 700 }}>
                {name}
              </span>
              <div style={{ background: "var(--bg-inset)", borderRadius: 3, height: 10 }}>
                <div style={{ width: `${Math.max(0.5, (v / total) * 100)}%`, height: 10, borderRadius: 3, background: getStageMeta(name).color }} />
              </div>
              <span className="mono text-xs text-muted">{num(v)}</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}

function SessionsBlock({ result }) {
  if (!result.top_sessions.length) return null;
  return (
    <Panel title="Highest-Scoring Sessions" meta={`grouping: ${result.sessions_grouping}`}>
      <div style={{ overflowX: "auto" }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Session</th>
              <th>Flows</th>
              <th>Flagged</th>
              <th>Max probability</th>
              <th>Behaviour</th>
            </tr>
          </thead>
          <tbody>
            {result.top_sessions.slice(0, 10).map((r) => (
              <tr key={r.session}>
                <td className="mono">{r.session}</td>
                <td>{num(r.flows)}</td>
                <td>{num(r.flagged)}</td>
                <td>{fix(r.max_prob, 3)}</td>
                <td style={{ color: getStageMeta(r.behaviour).color, fontWeight: 700 }}>{r.behaviour}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function ConversionBlock({ result, onDownload, downloading }) {
  const s = result.schema;
  return (
    <Panel title="How the File Was Converted" meta={`${s.format}${result.container ? `, ${result.container}` : ""}`}>
      <div className="mono text-xs" style={mono}>
        <div>
          Read directly: {Object.keys(s.read).length} of 22 features
          {Object.keys(s.derived).length > 0 && `; derived from other columns: ${Object.keys(s.derived).join(", ")}`}
        </div>
        {s.defaulted.length > 0 && <div>Not in the file, set to 0: {s.defaulted.join(", ")}</div>}
        {s.nonfinite_values_set_to_zero > 0 && <div>Infinite or missing values set to 0: {num(s.nonfinite_values_set_to_zero)}</div>}
        {s.timestamp_column && <div>Time taken from column: {s.timestamp_column}</div>}
        {s.assumptions.map((a, i) => (
          <div key={i}>Assumption: {a}</div>
        ))}
        {s.warnings.map((w, i) => (
          <div key={i} style={{ color: "var(--c-gold)" }}>Warning: {w}</div>
        ))}
      </div>
      <button className="btn" onClick={onDownload} disabled={downloading} style={{ marginTop: 10, display: "inline-flex", gap: 6, alignItems: "center" }}>
        <Download size={14} /> {downloading ? "Preparing..." : "Download labelled CSV (converted layout with predicted labels)"}
      </button>
    </Panel>
  );
}

function Report({ result, onDownload, downloading }) {
  const okSegs = result.segments.filter((s) => s.status === "ok");
  const [pick, setPick] = useState(null);
  const active = pick ?? okSegs[okSegs.length - 1]?.id;
  const seg = result.segments.find((s) => s.id === active);
  const labelled = result.labels.source === "file";
  const lastSeg = seg?.forecast;

  return (
    <>
      <Pipeline steps={result.pipeline} />
      <div className="stats-bar" style={{ marginBottom: "var(--sp-3)" }}>
        <Card label="Flows analysed" value={num(result.rows)} sub={`${result.timeline.segments_total} activity period${result.timeline.segments_total === 1 ? "" : "s"}`} />
        <Card
          label="Flagged as attacks"
          value={num(result.summary.flagged_flows)}
          sub={pct(result.summary.attack_share, 2) + " of flows"}
          color={result.summary.flagged_flows > 0 ? "var(--c-gold)" : undefined}
        />
        <Card
          label="Forecast peak, next 4 min"
          value={lastSeg ? pct(lastSeg.peak_risk, 0) : "-"}
          sub={lastSeg ? `threshold ${pct(lastSeg.threshold, 0)}` : "no period long enough"}
          color={lastSeg && lastSeg.peak_risk >= lastSeg.threshold ? "var(--c-red)" : undefined}
        />
        <Card label="Labels" value={labelled ? "from file" : "predicted"} sub={labelled ? result.labels.column : "no label column found"} />
      </div>

      <SegmentBar segments={result.timeline.segments} active={active} onPick={setPick} />
      {seg ? (
        <>
          <ForecastBlock key={`f${seg.id}`} seg={seg} />
          <TimelineBlock key={`t${seg.id}`} seg={seg} labelled={labelled} />
          <QualityBlock key={`q${seg.id}`} seg={seg} />
        </>
      ) : (
        <Panel title="Network Forecast">
          <p className="mono text-sm text-muted">
            No activity period in this file is long enough for the network-state model (it needs 6 continuous minutes).
            Per-flow results are shown below.
          </p>
        </Panel>
      )}
      <FlowBlock result={result} />
      <SessionsBlock result={result} />
      <ConversionBlock result={result} onDownload={onDownload} downloading={downloading} />
      <Panel title="Notes">
        <div className="mono text-xs" style={mono}>
          {result.notes.map((n, i) => (
            <div key={i} style={{ display: "flex", gap: 6 }}>
              <Info size={13} style={{ marginTop: 3, flex: "none" }} /> <span>{n}</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}

export default function UploadPanel() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const fileRef = useRef(null);
  const lastFile = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    lastFile.current = file;
    setUploading(true);
    setProgress(0);
    setResult(null);
    setError(null);
    try {
      setResult(await apiUpload("/offline/analyze", file, setProgress));
    } catch (e) {
      setError(e.message);
    }
    setUploading(false);
    if (fileRef.current) fileRef.current.value = "";
  };

  const download = async () => {
    if (!lastFile.current) return;
    setDownloading(true);
    try {
      const blob = await apiUpload("/offline/convert", lastFile.current, null, { blob: true });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${lastFile.current.name.replace(/\.[^.]+$/, "")}_garud.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e.message);
    }
    setDownloading(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  };

  return (
    <>
      <div style={{ marginBottom: "var(--sp-4)" }}>
        <span className="section-label" style={{ fontSize: "0.85rem" }}>
          Offline File Analysis
        </span>
        <p className="mono text-sm" style={{ color: "var(--text-secondary)", marginTop: "var(--sp-1)" }}>
          Upload any flow table (CSV, TSV, JSON, Parquet, Zeek, Suricata, NetFlow, gzip or zip) or a packet capture
          (PCAP/PCAPNG). Everything happens automatically: the layout is recognised, columns are converted to the
          model's 22 flow features, flows are labelled, and the forecast is computed on the dates inside the file.
          There is no size limit.
        </p>
        <p
          className="mono text-xs"
          style={{ color: "var(--severity-low)", marginTop: "var(--sp-1)", display: "flex", gap: 6, alignItems: "center" }}
        >
          <ShieldCheck size={14} /> Isolated from the live system: nothing here is added to live sessions, alerts, logs,
          the map or the live forecast.
        </p>
      </div>

      <div
        className={`upload-zone ${dragging ? "dragging" : ""}`}
        onClick={() => fileRef.current?.click()}
        onDrop={onDrop}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
      >
        {uploading ? (
          <>
            <div className="loading-spinner" style={{ margin: "0 auto var(--sp-3)", width: 28, height: 28 }} />
            <p style={{ fontWeight: 700, color: "var(--c-gold)" }}>
              {progress < 1 ? `Uploading ${(progress * 100).toFixed(0)}%` : "Converting, labelling and forecasting..."}
            </p>
            <span className="mono text-xs text-muted" style={{ display: "block", marginTop: 4 }}>
              Large files can take a few minutes
            </span>
          </>
        ) : (
          <>
            <Upload size={38} className="upload-icon" style={{ color: "var(--c-gold)", margin: "0 auto var(--sp-2)" }} />
            <p style={{ fontWeight: 700, fontSize: "1rem", color: "var(--text-primary)" }}>
              Drop a flow table or packet capture here, or click to browse
            </p>
            <span className="mono text-xs text-muted" style={{ display: "block", marginTop: 4 }}>
              Any file name works; the type is recognised by content
            </span>
          </>
        )}
        <input ref={fileRef} type="file" style={{ display: "none" }} onChange={(e) => handleFile(e.target.files[0])} />
      </div>

      {error && (
        <div
          className="mt-4"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            color: "var(--c-red)",
            background: "rgba(201, 74, 69, 0.1)",
            padding: "var(--sp-3)",
            borderRadius: "var(--radius)",
            border: "1px solid rgba(201, 74, 69, 0.3)",
          }}
        >
          <AlertTriangle size={18} />
          <span className="mono" style={{ fontWeight: 600 }}>{error}</span>
        </div>
      )}

      {result && (
        <div className="mt-4">
          <Report key={result.filename + result.rows} result={result} onDownload={download} downloading={downloading} />
        </div>
      )}
    </>
  );
}

export { UploadPanel as IngestPanel };
