import { useState, useEffect, useMemo } from 'react';
import {
  ComposedChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ReferenceLine, ResponsiveContainer, Legend,
} from 'recharts';
import { Network, Loader2, AlertTriangle, ShieldCheck } from 'lucide-react';
import { apiFetch } from '../api';

const REFRESH_MS = 10000;
const STATE_LABELS = {
  n_flows: 'Flows / min',
  n_uniq_src_ip: 'Source hosts',
  n_uniq_dst_ip: 'Destination hosts',
  n_uniq_dst_port: 'Destination ports',
  n_new_conn_rate: 'New connections / s',
  f_syn_ratio: 'SYN share',
  f_rst_ratio: 'RST share',
  f_small_flow_frac: 'Flows of 2 packets or fewer',
  n_ent_dst_port: 'Port entropy (bits)',
  n_dport_per_src_max: 'Max ports per source',
  f_total_bytes: 'Bytes / min',
};

const hhmm = (iso) => (iso ? iso.slice(11, 16) : '');
const fmt = (v) => (v == null ? '-' : Math.abs(v) >= 1000 ? Math.round(v).toLocaleString() : Number(v).toFixed(v < 10 ? 2 : 0));

function NetworkForecastView() {
  const [sources, setSources] = useState([]);
  const [source, setSource] = useState(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const srcs = await apiFetch('/network/sources');
        if (!active) return;
        setSources(srcs);
        const chosen = source || srcs[0]?.source;
        if (!chosen) { setData({ status: 'no_data' }); return; }
        const res = await apiFetch(`/network/forecast?source=${encodeURIComponent(chosen)}`);
        if (active) { setData(res); setError(null); }
      } catch (e) {
        if (active) setError(e.message);
      }
    };
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => { active = false; clearInterval(t); };
  }, [source]);

  const chart = useMemo(() => {
    if (!data || data.status !== 'ok') return [];
    const hist = data.minutes.map((m, i) => ({
      minute: hhmm(m), observed: data.risk_score[i], alert: data.alert[i] ? data.risk_score[i] : null,
    }));
    const last = hist[hist.length - 1];
    const fc = data.forecast.map((s) => ({ minute: hhmm(s.minute), forecast: s.risk }));
    if (last) last.forecast = last.observed;
    return [...hist.slice(-40), ...fc];
  }, [data]);

  if (error) return <div className="panel"><div className="panel-body text-muted">Network model: {error}</div></div>;
  if (!data) return <div className="panel"><div className="panel-body"><Loader2 size={16} className="spin"/> Loading</div></div>;

  const header = (
    <div className="panel-header">
      <span className="panel-title"><Network size={14}/> NETWORK_STATE_WORLD_MODEL</span>
      <span className="panel-meta">
        source:&nbsp;
        <select value={source || data.source || ''} onChange={(e) => setSource(e.target.value)}>
          {sources.map((s) => <option key={s.source} value={s.source}>{s.source} ({s.flows} flows)</option>)}
        </select>
      </span>
    </div>
  );

  if (data.status === 'no_data') {
    return <div className="panel">{header}<div className="panel-body text-muted">No flows yet. Upload a PCAP or CSV, or start capture.</div></div>;
  }
  if (data.status === 'warming_up') {
    return (
      <div className="panel">{header}
        <div className="panel-body text-muted">
          Building network state: {data.minutes_available} of {data.minutes_needed} minutes of traffic recorded.
          The model needs {data.minutes_needed} consecutive minutes before it can forecast.
        </div>
      </div>
    );
  }

  const cur = data.current;
  const info = data.model;
  const tr = info.test_results;
  return (
    <div>
      <div className="panel mb-4">
        {header}
        <div className="panel-body" style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'center' }}>
          <div className="kpi" style={{ color: cur.alert ? 'var(--severity-critical)' : 'var(--severity-low)' }}>
            {cur.alert ? <AlertTriangle size={18}/> : <ShieldCheck size={18}/>}
            &nbsp;{cur.alert ? 'SUSTAINED ALERT' : 'NO SUSTAINED ALERT'}
          </div>
          <div>Minute {hhmm(cur.minute)} UTC &middot; risk over next 4 min: <b>{(cur.risk_score * 100).toFixed(1)}%</b></div>
          <div className="text-muted text-sm">
            Alert rule (frozen on validation data): risk &ge; {(cur.threshold * 100).toFixed(1)}% for {cur.consecutive_needed} consecutive minute(s)
          </div>
        </div>
      </div>

      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">RISK_TIMELINE</span>
          <span className="panel-meta">observed minutes, then the 4-minute forecast (dashed)</span>
        </div>
        <div className="panel-body chart-container" style={{ minHeight: 280 }}>
          <ResponsiveContainer width="100%" height={260}>
            <ComposedChart data={chart} margin={{ top: 10, right: 20, bottom: 5, left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color, #333)"/>
              <XAxis dataKey="minute" tick={{ fontSize: 10 }}/>
              <YAxis domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} tick={{ fontSize: 10 }}/>
              <Tooltip formatter={(v) => (v == null ? '-' : `${(v * 100).toFixed(1)}%`)}/>
              <Legend/>
              <ReferenceLine y={cur.threshold} stroke="#c0392b" strokeDasharray="6 4" label={{ value: 'alert threshold', fontSize: 10 }}/>
              <Line type="monotone" dataKey="observed" name="risk (per minute)" stroke="#2980b9" dot={false} isAnimationActive={false}/>
              <Line type="monotone" dataKey="alert" name="sustained alert" stroke="#c0392b" strokeWidth={3} dot={{ r: 2 }} connectNulls={false} isAnimationActive={false}/>
              <Line type="monotone" dataKey="forecast" name="forecast t+1..t+4" stroke="#e67e22" strokeDasharray="5 4" dot={{ r: 3 }} isAnimationActive={false}/>
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid-2 mb-4" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">PREDICTED_NETWORK_STATE</span>
            <span className="panel-meta">now vs model rollout</span>
          </div>
          <div className="panel-body" style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr><th>Feature</th><th>{hhmm(cur.minute)}</th>{data.forecast.map((s) => <th key={s.step}>+{s.step}</th>)}</tr>
              </thead>
              <tbody>
                {Object.keys(STATE_LABELS).filter((f) => data.state[f]).map((f) => (
                  <tr key={f}>
                    <td>{STATE_LABELS[f]}</td>
                    <td>{fmt(data.state[f][data.state[f].length - 1])}</td>
                    {data.forecast.map((s) => <td key={s.step}>{fmt(s.state[f])}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">FORECAST_BY_MINUTE</span>
            <span className="panel-meta">behaviour class; ATT&CK = analyst mapping</span>
          </div>
          <div className="panel-body">
            <table className="data-table">
              <thead><tr><th>Step</th><th>Risk</th><th>Most likely behaviour</th><th>ATT&CK (lookup)</th></tr></thead>
              <tbody>
                {data.forecast.map((s) => {
                  const b = s.behaviours[0];
                  return (
                    <tr key={s.step}>
                      <td>+{s.step} ({hhmm(s.minute)})</td>
                      <td>{(s.risk * 100).toFixed(1)}%</td>
                      <td>{b.behaviour} ({(b.probability * 100).toFixed(0)}%)</td>
                      <td>{b.techniques.length ? `${b.techniques.join(' / ')} (${b.tactics.join(', ')})` : '-'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="grid-2 mb-4" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">WHY_THIS_FORECAST</span>
            <span className="panel-meta">gradient &times; input of the forecast risk</span>
          </div>
          <div className="panel-body">
            {data.explanation.map((e) => (
              <div key={e.feature} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: '0.8rem', padding: '2px 0' }}>
                <span>{STATE_LABELS[e.feature] || e.feature}</span>
                <span style={{ color: e.contribution > 0 ? 'var(--severity-critical)' : 'var(--severity-low)' }}>
                  {e.contribution > 0 ? 'raises' : 'lowers'} risk ({e.contribution.toFixed(3)})
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">HOW_RELIABLE_IS_THIS</span>
            <span className="panel-meta">{info.version} &middot; {info.n_features} features</span>
          </div>
          <div className="panel-body text-sm">
            <div>Held-out test (last 25% of each CIC-IDS2017 day): detection ROC-AUC {tr.detection.roc_auc?.toFixed(2)},
              F1 {tr.detection.f1.toFixed(2)}; false alarms {tr.early_warning.false_alarms_per_quiet_hour.toFixed(2)} per quiet hour;
              {' '}{tr.early_warning.warned_within_20} of {tr.early_warning.episodes} attack episodes warned within 20 minutes.</div>
            <ul style={{ marginTop: 8, paddingLeft: 18 }}>
              {info.caveats.map((c) => <li key={c}>{c}</li>)}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

export default NetworkForecastView;
