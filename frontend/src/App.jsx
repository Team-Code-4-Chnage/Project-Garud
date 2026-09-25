import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Activity, AlertTriangle, Upload, Eye,
  MonitorDot, Settings, BarChart3, Terminal,
  Wifi, Laptop, RotateCcw, HeartPulse, Network,
} from 'lucide-react';
import { apiFetch, apiPost, createWebSocket } from './api';
import { formatTime, isAttackFlow } from './utils';
import { WellbeingModal } from './components/Badges';
import Dashboard from './components/Dashboard';
import ForecastView from './components/ForecastView';
import NetworkForecastView from './components/NetworkForecastView';
import { AlertsView } from './components/AlertPanel';
import LiveLogsView from './components/LiveLogsView';
import ExplainView from './components/ExplainView';
import ReportsView from './components/ReportsView';
import { SettingsView } from './components/SettingsPanel';
import { IngestPanel } from './components/UploadPanel';
import './index.css';

export default function App() {
  const [view, setView] = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [alertCount, setAlertCount] = useState(0);
  const [selectedSession, setSelectedSession] = useState(null);
  const [clock, setClock] = useState(new Date());
  const [featureList, setFeatureList] = useState(null);
  const [systemMode, setSystemMode] = useState('live');
  const [simulatorRunning, setSimulatorRunning] = useState(false);

  const [liveFlows, setLiveFlows] = useState([]);
  const attackFlows = useMemo(() => liveFlows.filter(isAttackFlow), [liveFlows]);
  const [wsConnected, setWsConnected] = useState(false);
  const [hostIdentity, setHostIdentity] = useState(null);
  const [currentCycle, setCurrentCycle] = useState(null);
  const [wellbeingOpen, setWellbeingOpen] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const ws = createWebSocket();
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'pong') return;
        setLiveFlows(prev => {
          const next = [{ ...data, _ts: new Date().toISOString() }, ...prev];
          return next.length > 500 ? next.slice(0, 500) : next;
        });
        if (data.alert) {
          setAlertCount(c => c + 1);
        }
      } catch {}
    };

    const pingIv = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 15000);

    return () => {
      clearInterval(pingIv);
      ws.close();
    };
  }, []);

  const fetchSystemMode = useCallback(() => {
    apiFetch('/system/mode')
      .then(m => {
        if (m?.mode) setSystemMode(m.mode);
        if (typeof m?.simulator_running === 'boolean') setSimulatorRunning(m.simulator_running);
      })
      .catch(() => {});
  }, []);

  const fetchHostAndCycle = useCallback(() => {
    apiFetch('/system/host-identity').then(setHostIdentity).catch(() => {});
    apiFetch('/system/cycle/current').then(setCurrentCycle).catch(() => {});
  }, []);

  useEffect(() => {
    const updateHealth = (h) => {
      setHealth(h);
      if (h?.features && Array.isArray(h.features)) {
        setFeatureList(prev => {
          if (prev && prev.length === h.features.length && prev.every((v, i) => v === h.features[i])) {
            return prev;
          }
          return h.features;
        });
      }
      if (h?.system_mode) setSystemMode(h.system_mode);
    };

    apiFetch('/health').then(updateHealth).catch(() => setHealth({ status: 'offline' }));
    apiFetch('/alerts/stats').then(s => setAlertCount(s.unacknowledged || 0)).catch(() => {});
    fetchSystemMode();
    fetchHostAndCycle();

    const iv = setInterval(() => {
      apiFetch('/health').then(updateHealth).catch(() => setHealth({ status: 'offline' }));
      apiFetch('/alerts/stats').then(s => setAlertCount(s.unacknowledged || 0)).catch(() => {});
      fetchSystemMode();
      fetchHostAndCycle();
    }, 5000);
    return () => clearInterval(iv);
  }, [fetchSystemMode, fetchHostAndCycle]);

  const handleStartNewCycle = async () => {
    if (!window.confirm('Start a fresh cycle? Active sessions and flows will be safely archived to disk.')) {
      return;
    }
    try {
      const res = await apiPost('/system/cycle/start', {});
      setLiveFlows([]);
      fetchHostAndCycle();
      alert(`Archived ${res.archived_flows} flows (${res.archived_sessions} sessions). Fresh cycle started!`);
    } catch (e) {
      alert(e.message || 'Failed to start new cycle');
    }
  };

  const handleToggleMode = async (newMode) => {
    try {
      const res = await apiPost('/system/mode', { mode: newMode });
      setSystemMode(res.mode);
      setSimulatorRunning(res.simulator_running);
    } catch (e) {
      console.error('Failed to change mode', e);
    }
  };

  const handleStartSimulator = async () => {
    try {
      const res = await apiPost('/system/simulator/start', {});
      if (res.status === 'started' || res.status === 'already_running') {
        setSimulatorRunning(true);
      }
    } catch (e) {
      alert(e.message || 'Failed to start simulator');
    }
  };

  const handleStopSimulator = async () => {
    try {
      await apiPost('/system/simulator/stop', {});
      setSimulatorRunning(false);
    } catch (e) {
      alert(e.message || 'Failed to stop simulator');
    }
  };

  const handlePurgeSimulated = async () => {
    if (!window.confirm('Are you sure? This will delete all simulated flows, sessions, and alerts from the database. Live capture data will NOT be touched.')) {
      return;
    }
    try {
      const res = await apiPost('/system/purge-simulated', {});
      alert(`Purged ${res.deleted_flows} simulated flows, ${res.deleted_sessions} sessions, and ${res.deleted_alerts} alerts.`);
    } catch (e) {
      alert(e.message || 'Failed to purge data');
    }
  };

  const onSelectSession = (session) => {
    setSelectedSession(session);
    setView('forecast');
  };

  const viewLabels = {
    dashboard: 'DASHBOARD',
    live_logs: 'LIVE_LOGS',
    alerts: 'ALERTS',
    forecast: 'FORECAST',
    explain: 'EXPLAINABILITY',
    reports: 'REPORTS',
    ingest: 'INGEST',
    settings: 'SETTINGS',
  };

  const systemStatus = health?.status === 'ok' ? 'nominal' : health?.status === 'offline' ? 'offline' : 'degraded';

  return (
    <div className="app-layout">
      <nav className="sidebar">
        <div className="sidebar-brand">
          <h1>Project Garud</h1>
          <span>NetForecast World Model Engine</span>
        </div>

        <div className="nav-section">
          <div className="nav-label">// SYSTEM_MODULES</div>
          <button className={`nav-item ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>
            <MonitorDot size={15}/> DASHBOARD
          </button>
          <button className={`nav-item ${view === 'live_logs' ? 'active' : ''}`} onClick={() => setView('live_logs')}>
            <Terminal size={15}/> LIVE_LOGS
            <span className="nav-live-dot"/>
          </button>
          <button className={`nav-item ${view === 'alerts' ? 'active' : ''}`} onClick={() => setView('alerts')}>
            <AlertTriangle size={15}/> ALERTS
            {alertCount > 0 && <span className="nav-badge">{alertCount}</span>}
          </button>
          <button className={`nav-item ${view === 'forecast' ? 'active' : ''}`} onClick={() => setView('forecast')}>
            <Activity size={15}/> FORECAST
          </button>
          <button className={`nav-item ${view === 'network' ? 'active' : ''}`} onClick={() => setView('network')}>
            <Network size={15}/> NETWORK_FORECAST
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-label">// ANALYSIS</div>
          <button className={`nav-item ${view === 'explain' ? 'active' : ''}`} onClick={() => setView('explain')}>
            <Eye size={15}/> EXPLAINABILITY
          </button>
          <button className={`nav-item ${view === 'reports' ? 'active' : ''}`} onClick={() => setView('reports')}>
            <BarChart3 size={15}/> REPORTS
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-label">// DATA</div>
          <button className={`nav-item ${view === 'ingest' ? 'active' : ''}`} onClick={() => setView('ingest')}>
            <Upload size={15}/> INGEST
          </button>
          <button className={`nav-item ${view === 'settings' ? 'active' : ''}`} onClick={() => setView('settings')}>
            <Settings size={15}/> SETTINGS
          </button>
        </div>

        <div className="sidebar-status">
          <div className="sidebar-status-label">// STATUS</div>
          <div className={`sidebar-status-value ${systemStatus}`}>
            <span className="status-block">&#9632;</span>
            {systemStatus === 'nominal' ? 'SYSTEM NOMINAL' : systemStatus === 'degraded' ? 'DEGRADED' : 'OFFLINE'}
          </div>
        </div>
      </nav>

      <header className="header">
        <span className="header-breadcrumb">
          SYS_VIEW // <span className="view-name">[{viewLabels[view] || view.toUpperCase()}]</span>
        </span>
        <div className="header-right">
          {hostIdentity && (
            <div className="host-badge-chip" title={`Adapters: ${hostIdentity.interfaces?.map(i => `${i.name} (${i.ip})`).join(', ')}`}>
              <Laptop size={11} color="#27ae60"/>
              <span>{hostIdentity.hostname || 'HOST'} [{hostIdentity.primary_ip || '127.0.0.1'}]</span>
            </div>
          )}

          {currentCycle && (
            <div className="cycle-chip" title={`Started at ${formatTime(currentCycle.started_at)}`}>
              <Activity size={11}/>
              <span>{currentCycle.cycle_id?.substring(0, 18)}</span>
            </div>
          )}

          <button
            className="btn btn-sm"
            onClick={handleStartNewCycle}
            title="Archive current cycle & start fresh"
            style={{ fontSize: '0.62rem', padding: '2px 8px' }}
          >
            <RotateCcw size={10}/> NEW_CYCLE
          </button>

          <button
            className="btn btn-sm"
            onClick={() => setWellbeingOpen(true)}
            title="View network wellbeing audit history"
            style={{ fontSize: '0.62rem', padding: '2px 8px' }}
          >
            <HeartPulse size={10} color="var(--severity-low)"/> WELLBEING
          </button>

          <div className="header-indicator">
            <span className={`dot ${systemStatus === 'nominal' ? '' : systemStatus}`}/>
            {health?.model_loaded ? `MODEL: ${health.device?.toUpperCase() || 'CPU'}` : 'MODEL: LOADING'}
          </div>
          <div className="header-indicator">
            <Wifi size={10}/>
            {alertCount > 0 ? `ALERTS: ${alertCount}` : 'ALERTS: 0'}
          </div>
          <span className="header-clock">
            {clock.toISOString().slice(0, 19).replace('T', ' ')} UTC
          </span>
        </div>
      </header>

      <main className="main-content">
        {view === 'dashboard' && (
          <Dashboard
            onSelectSession={onSelectSession}
            featureList={featureList}
            systemMode={systemMode}
            liveFlows={attackFlows}
            wsConnected={wsConnected}
          />
        )}
        {view === 'forecast' && <ForecastView session={selectedSession} onBack={() => setView('dashboard')} featureList={featureList}/>}
        {view === 'network' && <NetworkForecastView/>}
        {view === 'alerts' && <AlertsView/>}
        {view === 'live_logs' && <LiveLogsView lines={liveFlows} connected={wsConnected}/>}
        {view === 'explain' && <ExplainView featureList={featureList}/>}
        {view === 'reports' && <ReportsView/>}
        {view === 'ingest' && <IngestPanel/>}
        {view === 'settings' && (
          <SettingsView
            health={health}
            systemMode={systemMode}
            onToggleMode={handleToggleMode}
            simulatorRunning={simulatorRunning}
            onStartSimulator={handleStartSimulator}
            onStopSimulator={handleStopSimulator}
            onPurgeSimulated={handlePurgeSimulated}
          />
        )}
      </main>

      <WellbeingModal isOpen={wellbeingOpen} onClose={() => setWellbeingOpen(false)}/>

      <footer className="footer">
        <span>Project Garud v1.0 // SIH 2026 PS26153 (Team Code 4 Change)</span>
        <span>LSTM World Model // {health?.features_count || 22} Features // Window={health?.stages?.length || 6}</span>
      </footer>
    </div>
  );
}
