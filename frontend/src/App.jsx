import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Activity,
  AlertTriangle,
  Upload,
  Eye,
  MonitorDot,
  Settings,
  BarChart3,
  Terminal,
  Wifi,
  Laptop,
  RotateCcw,
  HeartPulse,
  Network,
  Menu,
  X,
  Shield,
} from "lucide-react";
import { apiFetch, apiPost, createWebSocket } from "./api";
import { formatTime, isAttackFlow } from "./utils";
import { WellbeingModal } from "./components/Badges";
import Dashboard from "./components/Dashboard";
import ForecastView from "./components/ForecastView";
import NetworkForecastView from "./components/NetworkForecastView";
import { AlertsView } from "./components/AlertPanel";
import LiveLogsView from "./components/LiveLogsView";
import ExplainView from "./components/ExplainView";
import ReportsView from "./components/ReportsView";
import { SettingsView } from "./components/SettingsPanel";
import { IngestPanel } from "./components/UploadPanel";
import "./index.css";

export default function App() {
  const [view, setView] = useState("dashboard");
  const [health, setHealth] = useState(null);
  const [alertCount, setAlertCount] = useState(0);
  const [selectedSession, setSelectedSession] = useState(null);
  const [clock, setClock] = useState(new Date());
  const [featureList, setFeatureList] = useState(null);
  const [systemMode, setSystemMode] = useState("live");
  const [simulatorRunning, setSimulatorRunning] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [liveFlows, setLiveFlows] = useState([]);
  const attackFlows = useMemo(
    () => liveFlows.filter(isAttackFlow),
    [liveFlows],
  );
  const [wsConnected, setWsConnected] = useState(false);
  const [hostIdentity, setHostIdentity] = useState(null);
  const [currentCycle, setCurrentCycle] = useState(null);
  const [wellbeingOpen, setWellbeingOpen] = useState(false);

  const handleNavClick = (newView) => {
    setView(newView);
    setMobileMenuOpen(false);
  };

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
        if (data.type === "pong") return;
        setLiveFlows((prev) => {
          const next = [{ ...data, _ts: new Date().toISOString() }, ...prev];
          return next.length > 500 ? next.slice(0, 500) : next;
        });
        if (data.alert) {
          setAlertCount((c) => c + 1);
        }
      } catch {}
    };

    const pingIv = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send("ping");
    }, 15000);

    return () => {
      clearInterval(pingIv);
      ws.close();
    };
  }, []);

  useEffect(() => {
    apiFetch("/flows/recent?limit=100")
      .then((recent) => {
        if (Array.isArray(recent) && recent.length > 0) {
          setLiveFlows((prev) => {
            if (prev.length === 0) return recent;
            const existingKeys = new Set(
              prev.map((p) => p.id || `${p.session_key}-${p.timestamp}`),
            );
            const toAdd = recent.filter(
              (r) =>
                !existingKeys.has(r.id || `${r.session_key}-${r.timestamp}`),
            );
            return [...prev, ...toAdd];
          });
        }
      })
      .catch(() => {});
  }, []);

  const fetchSystemMode = useCallback(() => {
    apiFetch("/system/mode")
      .then((m) => {
        if (m?.mode) setSystemMode(m.mode);
        if (typeof m?.simulator_running === "boolean")
          setSimulatorRunning(m.simulator_running);
      })
      .catch(() => {});
  }, []);

  const fetchHostAndCycle = useCallback(() => {
    apiFetch("/system/host-identity")
      .then(setHostIdentity)
      .catch(() => {});
    apiFetch("/system/cycle/current")
      .then(setCurrentCycle)
      .catch(() => {});
  }, []);

  useEffect(() => {
    const updateHealth = (h) => {
      setHealth(h);
      if (h?.features && Array.isArray(h.features)) {
        setFeatureList((prev) => {
          if (
            prev &&
            prev.length === h.features.length &&
            prev.every((v, i) => v === h.features[i])
          ) {
            return prev;
          }
          return h.features;
        });
      }
      if (h?.system_mode) setSystemMode(h.system_mode);
    };

    apiFetch("/health")
      .then(updateHealth)
      .catch(() => setHealth({ status: "offline" }));
    apiFetch("/alerts/stats")
      .then((s) => setAlertCount(s.unacknowledged || 0))
      .catch(() => {});
    fetchSystemMode();
    fetchHostAndCycle();

    const iv = setInterval(() => {
      apiFetch("/health")
        .then(updateHealth)
        .catch(() => setHealth({ status: "offline" }));
      apiFetch("/alerts/stats")
        .then((s) => setAlertCount(s.unacknowledged || 0))
        .catch(() => {});
      fetchSystemMode();
      fetchHostAndCycle();
    }, 5000);
    return () => clearInterval(iv);
  }, [fetchSystemMode, fetchHostAndCycle]);

  const handleStartNewCycle = async () => {
    if (
      !window.confirm(
        "Start a fresh cycle? Active sessions and flows will be safely archived to disk.",
      )
    ) {
      return;
    }
    try {
      const res = await apiPost("/system/cycle/start", {});
      setLiveFlows([]);
      fetchHostAndCycle();
      alert(
        `Archived ${res.archived_flows} flows (${res.archived_sessions} sessions). Fresh cycle started!`,
      );
    } catch (e) {
      alert(e.message || "Failed to start new cycle");
    }
  };

  const handleToggleMode = async (newMode) => {
    try {
      const res = await apiPost("/system/mode", { mode: newMode });
      setSystemMode(res.mode);
      setSimulatorRunning(res.simulator_running);
    } catch (e) {
      console.error("Failed to change mode", e);
    }
  };

  const handleStartSimulator = async (options = {}) => {
    try {
      const res = await apiPost("/system/simulator/start", options);
      if (res.status === "started" || res.status === "already_running") {
        setSimulatorRunning(true);
        if (res.mode) setSystemMode(res.mode);
      }
      return res;
    } catch (e) {
      alert(e.message || "Failed to start simulator");
      throw e;
    }
  };

  const handleStopSimulator = async () => {
    try {
      await apiPost("/system/simulator/stop", {});
      setSimulatorRunning(false);
    } catch (e) {
      alert(e.message || "Failed to stop simulator");
    }
  };

  const handlePurgeSimulated = async () => {
    if (
      !window.confirm(
        "Are you sure? This will delete all simulated flows, sessions, and alerts from the database. Live capture data will NOT be touched.",
      )
    ) {
      return;
    }
    try {
      const res = await apiPost("/system/purge-simulated", {});
      alert(
        `Purged ${res.deleted_flows} simulated flows, ${res.deleted_sessions} sessions, and ${res.deleted_alerts} alerts.`,
      );
    } catch (e) {
      alert(e.message || "Failed to purge data");
    }
  };

  const onSelectSession = (session) => {
    setSelectedSession(session);
    setView("forecast");
  };

  const viewLabels = {
    dashboard: "Dashboard",
    live_logs: "Live Event Stream",
    alerts: "Incident Alerts",
    forecast: "Attack Progression Forecast",
    network: "Macro Network Topology",
    explain: "Explainable AI (XAI)",
    reports: "Forensic Audit Reports",
    ingest: "Telemetry Ingestion",
    settings: "Settings & Simulation Lab",
  };

  const systemStatus =
    health?.status === "ok"
      ? "nominal"
      : health?.status === "offline"
        ? "offline"
        : "degraded";

  return (
    <div className="app-layout">
      {mobileMenuOpen && (
        <div
          className="sidebar-backdrop"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
      <nav className={`sidebar ${mobileMenuOpen ? "mobile-open" : ""}`}>
        <div className="sidebar-brand">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 4,
            }}
          >
            <Shield size={18} color="var(--c-gold)" />
            <h1>PROJECT GARUD</h1>
          </div>
          <span>GOVERNMENT OF INDIA &bull; PS26153</span>
          <span
            style={{
              color: "var(--c-gold)",
              fontSize: "0.72rem",
              fontWeight: 800,
              letterSpacing: "0.04em",
              marginTop: 2,
            }}
          >
            CYBER ATTACK WORLD MODEL &bull; EARLY WARNING SOC
          </span>
        </div>

        <div className="nav-section">
          <div className="nav-label">SYSTEM MODULES</div>
          <button
            className={`nav-item ${view === "dashboard" ? "active" : ""}`}
            onClick={() => handleNavClick("dashboard")}
          >
            <MonitorDot size={15} /> Dashboard
          </button>
          <button
            className={`nav-item ${view === "live_logs" ? "active" : ""}`}
            onClick={() => handleNavClick("live_logs")}
          >
            <Terminal size={15} /> Live Event Logs
            <span className="nav-live-dot" />
          </button>
          <button
            className={`nav-item ${view === "alerts" ? "active" : ""}`}
            onClick={() => handleNavClick("alerts")}
          >
            <AlertTriangle size={15} /> Incident Alerts
            {alertCount > 0 && <span className="nav-badge">{alertCount}</span>}
          </button>
          <button
            className={`nav-item ${view === "forecast" ? "active" : ""}`}
            onClick={() => handleNavClick("forecast")}
          >
            <Activity size={15} /> Attack Forecast
          </button>
          <button
            className={`nav-item ${view === "network" ? "active" : ""}`}
            onClick={() => handleNavClick("network")}
          >
            <Network size={15} /> Macro World Model
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-label">THREAT INTELLIGENCE</div>
          <button
            className={`nav-item ${view === "explain" ? "active" : ""}`}
            onClick={() => handleNavClick("explain")}
          >
            <Eye size={15} /> Explainability (XAI)
          </button>
          <button
            className={`nav-item ${view === "reports" ? "active" : ""}`}
            onClick={() => handleNavClick("reports")}
          >
            <BarChart3 size={15} /> Forensic Reports
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-label">DATA & TELEMETRY</div>
          <button
            className={`nav-item ${view === "ingest" ? "active" : ""}`}
            onClick={() => handleNavClick("ingest")}
          >
            <Upload size={15} /> Ingest Captures
          </button>
          <button
            className={`nav-item ${view === "settings" ? "active" : ""}`}
            onClick={() => handleNavClick("settings")}
          >
            <Settings size={15} /> Settings & Lab
          </button>
        </div>

        <div className="sidebar-status">
          <div className="sidebar-status-label">DEFENSE READINESS</div>
          <div className={`sidebar-status-value ${systemStatus}`}>
            <span className="status-block">&#9632;</span>
            {systemStatus === "nominal"
              ? "DEFENSE NOMINAL"
              : systemStatus === "degraded"
                ? "DEGRADED"
                : "OFFLINE"}
          </div>
        </div>
      </nav>

      <header className="header">
        <div className="header-left">
          <button
            className="mobile-menu-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
          <span className="header-breadcrumb">
            SYSTEM VIEW &rsaquo;{" "}
            <span className="view-name">
              {viewLabels[view] || view.toUpperCase()}
            </span>
          </span>
        </div>
        <div className="header-right">
          {hostIdentity && (
            <div
              className="host-badge-chip"
              title={`Protected Host Network Adapters: ${hostIdentity.interfaces?.map((i) => `${i.name} (${i.ip})`).join(", ")}`}
              style={{ cursor: "default", userSelect: "none" }}
            >
              <Laptop size={12} color="var(--severity-low)" />
              <span
                style={{
                  color: "var(--text-muted)",
                  fontSize: "0.68rem",
                  fontWeight: 700,
                }}
              >
                HOST:
              </span>
              <span style={{ fontWeight: 700 }}>
                {hostIdentity.hostname || "LOCAL"}
              </span>
              <span style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>
                [{hostIdentity.primary_ip || "127.0.0.1"}]
              </span>
            </div>
          )}

          {currentCycle && (
            <div
              className="cycle-chip"
              title={`Started at ${formatTime(currentCycle.started_at)}`}
            >
              <Activity size={11} />
              <span>{currentCycle.cycle_id?.substring(0, 18)}</span>
            </div>
          )}

          <button
            className="btn btn-sm"
            onClick={handleStartNewCycle}
            title="Archive current cycle & start fresh"
            style={{
              fontSize: "0.68rem",
              padding: "3px 10px",
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            <RotateCcw size={11} /> New Cycle
          </button>

          <button
            className="btn btn-sm"
            onClick={() => setWellbeingOpen(true)}
            title="View network wellbeing audit history"
            style={{
              fontSize: "0.68rem",
              padding: "3px 10px",
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            <HeartPulse size={11} color="var(--c-gold)" /> Wellbeing Audit
          </button>

          <div className="header-indicator">
            <span
              className={`dot ${systemStatus === "nominal" ? "" : systemStatus}`}
            />
            {health?.model_loaded
              ? `Model: ${health.device?.toUpperCase() || "CPU"}`
              : "Model: Loading"}
          </div>
          <div className="header-indicator">
            <Wifi size={10} />
            {alertCount > 0 ? `Alerts: ${alertCount}` : "Alerts: 0"}
          </div>
          <span className="header-clock">
            {clock.toISOString().slice(0, 19).replace("T", " ")} UTC
          </span>
        </div>
      </header>

      <main className="main-content">
        {view === "dashboard" && (
          <Dashboard
            onSelectSession={onSelectSession}
            featureList={featureList}
            systemMode={systemMode}
            liveFlows={attackFlows}
            wsConnected={wsConnected}
          />
        )}
        {view === "forecast" && (
          <ForecastView
            session={selectedSession}
            onBack={() => setView("dashboard")}
            featureList={featureList}
          />
        )}
        {view === "network" && (
          <NetworkForecastView hostIdentity={hostIdentity} />
        )}
        {view === "alerts" && <AlertsView />}
        {view === "live_logs" && (
          <LiveLogsView lines={liveFlows} connected={wsConnected} />
        )}
        {view === "explain" && <ExplainView featureList={featureList} />}
        {view === "reports" && <ReportsView />}
        {view === "ingest" && <IngestPanel />}
        {view === "settings" && (
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

      <WellbeingModal
        isOpen={wellbeingOpen}
        onClose={() => setWellbeingOpen(false)}
      />

      <footer className="footer">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Shield size={12} color="var(--c-gold)" />
          <span>
            Project Garud v1.0 &bull; SIH 2026 PS26153 (Team Code 4 Change)
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span>
            LSTM World Model &bull; {health?.features_count || 22} Features
            &bull; Temporal Window={health?.stages?.length || 6}
          </span>
          <span
            style={{
              color: "var(--c-gold)",
              fontWeight: 700,
              letterSpacing: "0.05em",
            }}
          >
            National Security Operational SOC
          </span>
        </div>
      </footer>
    </div>
  );
}
