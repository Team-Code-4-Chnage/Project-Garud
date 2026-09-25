import { useState, useEffect, useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ResponsiveContainer, Legend,
} from 'recharts';
import { Activity, AlertTriangle, ShieldCheck, Loader2 } from 'lucide-react';
import { apiFetch, apiPost } from '../api';
import {
  stageClass, stageColor, formatTime, formatProb,
  formatDuration,
  DEFAULT_FEAT_ORDER,
} from '../utils';
import {
  DirBadge, SourceBadge,
  CompromiseIndicator, KillChain,
} from './Badges';

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
        const allFlows = await apiFetch(`/sessions/${encodeURIComponent(sessionKey)}/flows?limit=100`);
        if (!active) return;
        setFlows(allFlows);
        if (!allFlows || allFlows.length === 0) {
          setError('No flow records captured for this session yet.');
          return;
        }
        if (allFlows.length < WINDOW_SIZE) {
          return;
        }
        const windowFlows = allFlows.slice(0, WINDOW_SIZE).reverse();
        const window = windowFlows.map(f => featOrder.map(k => f.features?.[k] ?? 0));
        const [fc, exp] = await Promise.all([
          apiPost('/forecast', { window, k_steps: 4, n_mc_samples: 20, needs_scaling: true }),
          apiPost('/explain', { window, top_k: 10, needs_scaling: true }),
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

    return () => { active = false; };
  }, [sessionKey, featOrder]);

  const avgStepMs = useMemo(() => {
    if (!flows || flows.length < 2) return null;
    const times = flows.map(f => new Date(f.timestamp).getTime()).filter(t => !Number.isNaN(t));
    if (times.length < 2) return null;
    const deltas = [];
    for (let i = 0; i < times.length - 1; i++) deltas.push(Math.abs(times[i] - times[i + 1]));
    const avg = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    return avg > 0 ? avg : null;
  }, [flows]);

  function formatEta(steps) {
    if (!avgStepMs) return null;
    const ms = avgStepMs * steps;
    if (ms < 1000) return '<1s';
    if (ms < 60000) return `~${Math.round(ms / 1000)}s`;
    if (ms < 3600000) return `~${Math.round(ms / 60000)}m`;
    return `~${Math.round(ms / 3600000)}h`;
  }

  if (!session) {
    return (
      <div className="empty-state">
        <Activity size={28} color="var(--text-muted)"/>
        <p>Select a session from the Dashboard to view its attack forecast.</p>
      </div>
    );
  }

  if (loading && !forecast) {
    return <div className="empty-state"><div className="loading-spinner"/><p>Running forecast model...</p></div>;
  }

  if (error && !forecast) {
    return <div className="empty-state"><AlertTriangle size={28} color="var(--severity-high)"/><p>{error}</p></div>;
  }

  if (!loading && !forecast && flows.length < WINDOW_SIZE) {
    return (
      <div className="empty-state">
        <Loader2 size={28} color="var(--text-muted)" className="spin-icon"/>
        <p>Collecting baseline: {flows.length}/{WINDOW_SIZE} flows</p>
        <span className="mono text-xs text-muted">
          The world model needs a full {WINDOW_SIZE}-flow window of real observations before it can forecast. Come back once more traffic has been captured for this session.
        </span>
      </div>
    );
  }

  const chartData = forecast?.steps?.map(s => ({
    step: `+${s.step}`,
    stepNum: s.step,
    mean: s.infiltration_prob_mean,
    ema: s.infiltration_prob_ema,
    upper: Math.min(1, s.infiltration_prob_mean + s.infiltration_prob_std),
    lower: Math.max(0, s.infiltration_prob_mean - s.infiltration_prob_std),
    stage: s.predicted_stage,
  })) || [];

  const forecastStages = [...new Set(chartData.map(d => d.stage))];
  const maxImportance = explanation?.attributions
    ? Math.max(...explanation.attributions.map(a => Math.abs(a.importance)))
    : 1;

  const hasAttackSignal = Boolean(
    forecast?.alert_triggered ||
    chartData.some(d => d.stage && d.stage !== 'Benign') ||
    chartData.some(d => (d.mean ?? 0) > 0.1) ||
    (explanation?.infiltration_probability ?? 0) > 0.1 ||
    (session.max_stage_reached && session.max_stage_reached !== 'Benign') ||
    (session.latest_risk_score ?? 0) > 0.1
  );

  if (forecast && !hasAttackSignal) {
    return (
      <div className="empty-state">
        <ShieldCheck size={28} color="var(--severity-low)"/>
        <p style={{ color: 'var(--severity-low)' }}>No attack activity projected</p>
        <span className="mono text-xs text-muted">
          {session.src_ip} &rarr; {session.dst_ip} — the model forecasts this session staying Benign across all {chartData.length} steps, and it has no prior risk on record. Nothing to visualize.
        </span>
        <button className="btn btn-sm" onClick={onBack} style={{ marginTop: 'var(--sp-3)' }}>&larr; BACK TO DASHBOARD</button>
      </div>
    );
  }

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-3)', flexWrap: 'wrap' }}>
        <button className="btn btn-sm" onClick={onBack}>&larr; BACK</button>
        <span className="mono text-sm" style={{ color: 'var(--text-secondary)' }}>
          {session.src_ip} &rarr; {session.dst_ip}
        </span>
        <span className={`stage-badge ${stageClass(session.latest_stage)}`}>{session.latest_stage}</span>
        <DirBadge dir={session.direction}/>
        <SourceBadge src={session.source}/>
        <CompromiseIndicator stage={session.max_stage_reached || session.latest_stage} riskScore={session.latest_risk_score}/>
        {loading && (
          <span className="mono" style={{ fontSize: '0.62rem', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <span className="loading-spinner" style={{ width: 10, height: 10, borderWidth: 1.5, margin: 0 }}/>
            SYNCING
          </span>
        )}
        {error && (
          <span className="severity-badge high" title={error} style={{ fontSize: '0.6rem' }}>REFRESH FAILED</span>
        )}
        {forecast?.alert_triggered && (
          <span className="severity-badge critical">
            ALERT AT STEP +{forecast.alert_at_step}
            {formatEta(forecast.alert_at_step) && <> &middot; ETA {formatEta(forecast.alert_at_step)}</>}
          </span>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--sp-2)' }}>
          <button
            className="btn btn-sm"
            onClick={() => window.open(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/forecast/view/html?session_key=${encodeURIComponent(session.session_key)}`, '_blank')}
            title="Open printable forecast dossier in a new browser tab"
          >
            👁️ VIEW REPORT
          </button>
          <a
            className="btn btn-sm btn-primary"
            href={`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/forecast/export/html?session_key=${encodeURIComponent(session.session_key)}`}
            download
            style={{ textDecoration: 'none' }}
          >
            📄 EXPORT FORECAST HTML
          </a>
        </div>
      </div>

      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">KILL_CHAIN_PROGRESS</span>
          <span className="panel-meta">Stage labels are dataset proxies, not verified campaign stages</span>
        </div>
        <div className="panel-body">
          <KillChain currentStage={session.latest_stage} forecastStages={forecastStages}/>
        </div>
      </div>

      <div className="forecast-grid">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">K_STEP_FORECAST</span>
            <span className="panel-meta">MC n=20 &middot; EMA &alpha;=0.4</span>
          </div>
          <div className="panel-body chart-container" style={{ minHeight: 320 }}>
            <p className="mono text-xs text-muted" style={{ marginBottom: 'var(--sp-2)' }}>
              Projected probability this session is compromised, {chartData.length} steps into the future
              {avgStepMs ? ` (~${formatEta(1)?.replace('~', '')} per step, based on this session's own flow rate)` : ''}.
              The shaded band is model uncertainty (20 Monte Carlo rollouts) — wider band means less confidence.
            </p>
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={chartData} margin={{ top: 10, right: 20, bottom: 5, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d4c5b0"/>
                <XAxis
                  dataKey="step"
                  tick={{ fontSize: 11 }}
                  label={{ value: 'Forecast Steps Ahead', position: 'insideBottom', offset: -3, fontSize: 11, fill: '#8a7f72' }}
                />
                <YAxis
                  domain={[0, 1]}
                  ticks={[0, 0.25, 0.5, 0.75, 1.0]}
                  tick={{ fontSize: 11 }}
                  label={{ value: 'Infiltration Risk', angle: -90, position: 'insideLeft', fontSize: 11, fill: '#8a7f72' }}
                />
                <Tooltip
                  contentStyle={{ background: '#fffbf5', border: '1px solid #d4c5b0', borderRadius: 3, fontSize: 12 }}
                  labelStyle={{ color: '#5a5245' }}
                  formatter={(value, name) => [typeof value === 'number' ? value.toFixed(3) : value, name]}
                  labelFormatter={(label, payload) => {
                    const eta = payload?.[0]?.payload?.stepNum ? formatEta(payload[0].payload.stepNum) : null;
                    return `Step ${label}${eta ? ` (ETA ${eta})` : ''}`;
                  }}
                />
                <Legend verticalAlign="top" height={28} wrapperStyle={{ fontSize: 11 }}/>
                <Area type="monotone" dataKey="upper" stroke="none" fill="#e67e22" fillOpacity={0.08} stackId="band" isAnimationActive={false} name="Uncertainty band" legendType="none"/>
                <Area type="monotone" dataKey="lower" stroke="none" fill="#f5efe6" fillOpacity={1} stackId="band" isAnimationActive={false} legendType="none"/>
                <Area type="monotone" dataKey="mean" stroke="#e67e22" strokeWidth={2} fill="none" name="Risk (MC mean)" isAnimationActive={false}/>
                <Area type="monotone" dataKey="ema" stroke="#8a7f72" strokeWidth={1.5} strokeDasharray="4 3" fill="none" name="Smoothed trend (EMA)" isAnimationActive={false}/>
                <ReferenceLine y={forecast?.threshold || 0.5} stroke="#c0392b" strokeDasharray="6 4" strokeWidth={1}
                  label={{ value: 'Alert threshold', position: 'right', fill: '#c0392b', fontSize: 10 }}/>
              </AreaChart>
            </ResponsiveContainer>

            <div className="stage-track">
              {chartData.map((d, i) => (
                <div key={i} className="stage-track-item" style={{ background: stageColor(d.stage) + '18', color: stageColor(d.stage) }}>
                  {d.stage}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">FEATURE_ATTRIBUTION</span>
            <span className="panel-meta">
              {explanation?.method_used === 'shap' ? 'SHAP Values (KernelExplainer)' : 'Gradient × Input'}
            </span>
          </div>
          <div className="panel-body">
            {explanation && (
              <>
                <div style={{ marginBottom: 'var(--sp-3)', display: 'flex', gap: 'var(--sp-4)', alignItems: 'baseline' }}>
                  <div>
                    <span className="mono" style={{ fontSize: '1.1rem', fontWeight: 700 }}>{formatProb(explanation.infiltration_probability)}</span>
                    <span className="text-sm text-muted" style={{ marginLeft: 'var(--sp-2)' }}>P(INFIL)</span>
                  </div>
                  <span className={`stage-badge ${stageClass(explanation.predicted_stage)}`}>{explanation.predicted_stage}</span>
                </div>

                <div className="shap-bar-container">
                  {explanation.attributions.map((attr, i) => (
                    <div key={i} className="shap-row">
                      <span className="shap-feature">{attr.feature}</span>
                      <div className="shap-bar-track">
                        <div
                          className={`shap-bar ${attr.direction}`}
                          style={{ width: `${(Math.abs(attr.importance) / maxImportance) * 100}%` }}
                        />
                      </div>
                      <span className="shap-value">{attr.importance > 0 ? '+' : ''}{attr.importance.toFixed(4)}</span>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 'var(--sp-3)', display: 'flex', gap: 'var(--sp-4)', fontSize: '0.62rem' }}>
                  <span style={{ color: 'var(--severity-critical)' }}>&#9632; MALICIOUS</span>
                  <span style={{ color: 'var(--severity-low)' }}>&#9632; BENIGN</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">NETWORK_LOGS</span>
          <span className="panel-meta">{flows.length} flow records &middot; most recent first</span>
        </div>
        <div style={{ maxHeight: '380px', overflowY: 'auto' }}>
          {flows.length === 0 ? (
            <div className="empty-state"><p>No flow records.</p></div>
          ) : (
            <table className="data-table" style={{ fontSize: '0.65rem' }}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>TIMESTAMP</th>
                  <th>DURATION</th>
                  <th>FWD↑</th>
                  <th>BWD↓</th>
                  <th>BYTES/S</th>
                  <th>PKTS/S</th>
                  <th>SYN</th>
                  <th>ACK</th>
                  <th>RST</th>
                  <th>PSH</th>
                  <th>FIN</th>
                  <th>URG</th>
                  <th>TTL_VAR</th>
                  <th>WIN</th>
                  <th>RETX</th>
                  <th>P(INFIL)</th>
                  <th>STAGE</th>
                  <th>SRC</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((f, i) => {
                  const feat = f.features || {};
                  const prob = f.infiltration_prob || 0;
                  const isAlert = prob > 0.5;
                  return (
                    <tr key={f.id} style={{
                      cursor: 'default',
                      background: isAlert ? 'rgba(192,57,43,0.05)' : undefined,
                    }}>
                      <td style={{ color: 'var(--text-muted)' }}>{flows.length - i}</td>
                      <td>{formatTime(f.timestamp)}</td>
                      <td>{formatDuration(feat.flow_duration)}</td>
                      <td>{(feat.tot_fwd_pkts ?? 0).toFixed(0)}</td>
                      <td>{(feat.tot_bwd_pkts ?? 0).toFixed(0)}</td>
                      <td>{(feat.flow_bytes_s ?? 0).toFixed(0)}</td>
                      <td>{(feat.flow_pkts_s ?? 0).toFixed(1)}</td>
                      <td style={{ color: (feat.syn_flag_cnt ?? 0) > 3 ? 'var(--severity-high)' : undefined }}>{(feat.syn_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.ack_flag_cnt ?? 0).toFixed(0)}</td>
                      <td style={{ color: (feat.rst_flag_cnt ?? 0) > 0 ? 'var(--severity-medium)' : undefined }}>{(feat.rst_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.psh_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.fin_flag_cnt ?? 0).toFixed(0)}</td>
                      <td style={{ color: (feat.urg_flag_cnt ?? 0) > 0 ? 'var(--severity-critical)' : undefined }}>{(feat.urg_flag_cnt ?? 0).toFixed(0)}</td>
                      <td>{(feat.ttl_variance ?? 0).toFixed(1)}</td>
                      <td>{(feat.tcp_win_size ?? 0).toFixed(0)}</td>
                      <td style={{ color: (feat.retransmit_cnt ?? 0) > 2 ? 'var(--severity-high)' : undefined }}>{(feat.retransmit_cnt ?? 0).toFixed(0)}</td>
                      <td style={{ color: isAlert ? 'var(--severity-critical)' : 'var(--severity-low)', fontWeight: isAlert ? 700 : 400 }}>
                        {formatProb(prob)}
                      </td>
                      <td><span className={`stage-badge ${stageClass(f.predicted_stage || 'Benign')}`}>{f.predicted_stage || 'Benign'}</span></td>
                      <td><SourceBadge src={f.source}/></td>
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
