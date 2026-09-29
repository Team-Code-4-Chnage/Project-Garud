import { useState, useEffect, useCallback, useRef } from "react";
import {
  AlertTriangle,
  Upload,
  MonitorDot,
  Settings,
  BarChart3,
  Terminal,
  Laptop,
  RotateCcw,
  HeartPulse,
  Network,
  Menu,
  X,
  HelpCircle,
} from "lucide-react";
import EagleIcon from "./components/EagleIcon";
import { apiFetch, apiPost, createWebSocket } from "./api";
import { flowKey } from "./utils";
import { WellbeingModal } from "./components/Badges";
import ConfirmModal from "./components/ConfirmModal";
import Dashboard from "./components/Dashboard";
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
  const [clock, setClock] = useState(new Date());
  const [featureList, setFeatureList] = useState(null);
  const [systemMode, setSystemMode] = useState("live");
  const [simulatorRunning, setSimulatorRunning] = useState(false);
  const [captureRunning, setCaptureRunning] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [_selectedSession, setSelectedSession] = useState(null);

  const [liveFlows, setLiveFlows] = useState([]);
  const seenFlowKeysRef = useRef(new Set());
  const [wsConnected, setWsConnected] = useState(false);
  const [hostIdentity, setHostIdentity] = useState(null);
  const [currentCycle, setCurrentCycle] = useState(null);
  const [wellbeingOpen, setWellbeingOpen] = useState(false);
  const [modalConfig, setModalConfig] = useState(null);

  const handleNavClick = (newView) => {
    setView(newView);
    setMobileMenuOpen(false);
  };

  const onSelectSession = (session) => {
    setSelectedSession(session);
    setView("network");
    setMobileMenuOpen(false);
  };

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let ws = null;
    let reconnectTimer = null;
    let pingInterval = null;
    let delay = 1000;
    let isUnmounted = false;

    function connect() {
      if (isUnmounted) return;
      try {
        ws = createWebSocket();

        ws.onopen = () => {
          if (isUnmounted) return;
          setWsConnected(true);
          delay = 1000;
        };

        ws.onclose = () => {
          if (isUnmounted) return;
          setWsConnected(false);
          scheduleReconnect();
        };

        ws.onerror = () => {
          if (isUnmounted) return;
          setWsConnected(false);
          try {
            ws.close();
          } catch {}
        };

        ws.onmessage = (evt) => {
          if (isUnmounted) return;
          try {
            const data = JSON.parse(evt.data);
            if (data.type === "pong") return;
            const key = flowKey(data);
            if (seenFlowKeysRef.current.has(key)) return;
            setLiveFlows((prev) => {
              const next = [{ ...data, _ts: new Date().toISOString() }, ...prev];
              const trimmed = next.length > 500 ? next.slice(0, 500) : next;
              seenFlowKeysRef.current = new Set(trimmed.map(flowKey));
              return trimmed;
            });
            if (data.alert || data.is_alert) {
              setAlertCount((c) => c + 1);
            }
          } catch {}
        };
      } catch {
        scheduleReconnect();
      }
    }

    function scheduleReconnect() {
      if (isUnmounted || reconnectTimer) return;
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        delay = Math.min(delay * 1.5, 8000);
        connect();
      }, delay);
    }

    connect();

    pingInterval = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send("ping");
      }
    }, 10000);

    return () => {
      isUnmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (pingInterval) clearInterval(pingInterval);
      if (ws) {
        try {
          ws.close();
        } catch {}
      }
    };
  }, []);

  const handleClearLiveLogs = useCallback(() => {
    setLiveFlows([]);
    seenFlowKeysRef.current = new Set();
  }, []);

  const handleReloadRecentLogs = useCallback(async () => {
    try {
      const recent = await apiFetch("/flows/recent?limit=100");
      if (Array.isArray(recent) && recent.length > 0) {
        setLiveFlows(recent);
        seenFlowKeysRef.current = new Set(recent.map(flowKey));
      }
    } catch (e) {
      console.error("Failed to reload recent flows:", e);
    }
  }, []);

  useEffect(() => {
    apiFetch("/flows/recent?limit=100")
      .then((recent) => {
        if (Array.isArray(recent) && recent.length > 0) {
          setLiveFlows((prev) => {
            if (prev.length === 0) {
              seenFlowKeysRef.current = new Set(recent.map(flowKey));
              return recent;
            }
            const existingKeys = new Set(prev.map(flowKey));
            const toAdd = recent.filter((r) => !existingKeys.has(flowKey(r)));
            const merged = [...prev, ...toAdd];
            seenFlowKeysRef.current = new Set(merged.map(flowKey));
            return merged;
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
        if (typeof m?.capture_running === "boolean")
          setCaptureRunning(m.capture_running);
        // Automatically ensure live packet capture is running by default in live mode
        if (m?.mode === "live" && !m?.capture_running) {
          apiPost("/system/capture/start", {})
            .then(() => setCaptureRunning(true))
            .catch(() => {});
        }
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

  const handleStartNewCycle = () => {
    setModalConfig({
      title: "START FRESH CYCLE",
      message: "Start a fresh cycle? Active sessions and flows will be safely archived to disk.",
      confirmLabel: "ARCHIVE & START",
      isDestructive: false,
      onConfirm: async () => {
        try {
          const res = await apiPost("/system/cycle/start", {});
          setLiveFlows([]);
          fetchHostAndCycle();
          setModalConfig({
            title: "CYCLE STARTED",
            message: `Archived ${res.archived_flows} flows (${res.archived_sessions} sessions). Fresh cycle started!`,
            confirmLabel: "CLOSE",
            isAlert: true,
          });
        } catch (e) {
          setModalConfig({
            title: "CYCLE ERROR",
            message: e.message || "Failed to start new cycle",
            confirmLabel: "CLOSE",
            isAlert: true,
            isDestructive: true,
          });
        }
      },
    });
  };

  const handleToggleMode = async (newMode) => {
    setSystemMode(newMode);
    try {
      const res = await apiPost("/system/mode", { mode: newMode });
      setSystemMode(res.mode);
      setSimulatorRunning(Boolean(res.simulator_running));
      setCaptureRunning(Boolean(res.capture_running));
      if (newMode === "live") {
        apiPost("/system/capture/start", {})
          .then(() => setCaptureRunning(true))
          .catch(() => {});
      }
    } catch (e) {
      console.error("Failed to change mode", e);
    }
  };

  const handleStartLiveCapture = async (options = {}) => {
    try {
      const res = await apiPost("/system/capture/start", options);
      if (res.status === "started" || res.status === "already_running") {
        setCaptureRunning(true);
        if (res.mode) setSystemMode(res.mode);
      }
      return res;
    } catch (e) {
      setModalConfig({
        title: "CAPTURE NOTICE",
        message: e.message || "Failed to start live capture",
        confirmLabel: "CLOSE",
        isAlert: true,
        isDestructive: true,
      });
      throw e;
    }
  };

  const handleStopLiveCapture = async () => {
    try {
      await apiPost("/system/capture/stop", {});
      setCaptureRunning(false);
    } catch (e) {
      setModalConfig({
        title: "CAPTURE NOTICE",
        message: e.message || "Failed to stop live capture",
        confirmLabel: "CLOSE",
        isAlert: true,
        isDestructive: true,
      });
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
      setModalConfig({
        title: "SIMULATOR NOTICE",
        message: e.message || "Failed to start simulator",
        confirmLabel: "CLOSE",
        isAlert: true,
        isDestructive: true,
      });
      throw e;
    }
  };

  const handleStopSimulator = async () => {
    try {
      await apiPost("/system/simulator/stop", {});
      setSimulatorRunning(false);
    } catch (e) {
      setModalConfig({
        title: "SIMULATOR NOTICE",
        message: e.message || "Failed to stop simulator",
        confirmLabel: "CLOSE",
        isAlert: true,
        isDestructive: true,
      });
    }
  };

  const handlePurgeSimulated = () => {
    setModalConfig({
      title: "PURGE SIMULATION DATA",
      message: "Are you sure? This will delete all simulated flows, sessions, and alerts from the database. Live capture data will NOT be touched.",
      confirmLabel: "PURGE SIMULATION",
      isDestructive: true,
      onConfirm: async () => {
        try {
          const res = await apiPost("/system/purge-simulated", {});
          setModalConfig({
            title: "PURGE COMPLETE",
            message: `Purged ${res.deleted_flows} simulated flows, ${res.deleted_sessions} sessions, and ${res.deleted_alerts} alerts.`,
            confirmLabel: "CLOSE",
            isAlert: true,
          });
        } catch (e) {
          setModalConfig({
            title: "PURGE FAILED",
            message: e.message || "Failed to purge data",
            confirmLabel: "CLOSE",
            isAlert: true,
            isDestructive: true,
          });
        }
      },
    });
  };



  return (
    <div className="garud-app">
      {mobileMenuOpen && (
        <div
          className="garud-drawer-backdrop"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <nav className={`garud-sidebar ${mobileMenuOpen ? "mobile-open" : ""}`}>
        <div>
          <div className="garud-sidebar-brand">
            <div className="garud-brand-title">
              <EagleIcon size={20} color="var(--accent)" />
              <span>PROJECT GARUD</span>
            </div>
            <span className="garud-brand-sub">PS26153 &bull; INDIA</span>
            <span className="garud-brand-desc">AI ATTACK FORECASTING SOC</span>
          </div>

          <div className="garud-nav-scroll">
            <div>
              <div className="garud-nav-group-label">SYSTEM MODULES</div>
              <div className="garud-nav-list">
                <button
                  className={`garud-nav-item ${view === "dashboard" ? "active" : ""}`}
                  onClick={() => handleNavClick("dashboard")}
                >
                  <span className="garud-nav-item-left">
                    <MonitorDot size={15} /> Dashboard
                  </span>
                </button>
                <button
                  className={`garud-nav-item ${view === "live_logs" ? "active" : ""}`}
                  onClick={() => handleNavClick("live_logs")}
                >
                  <span className="garud-nav-item-left">
                    <Terminal size={15} /> Live Event Logs
                  </span>
                  <span className="garud-status-indicator live" style={{ width: 5, height: 5 }} />
                </button>
                <button
                  className={`garud-nav-item ${view === "alerts" ? "active" : ""}`}
                  onClick={() => handleNavClick("alerts")}
                >
                  <span className="garud-nav-item-left">
                    <AlertTriangle size={15} /> Incident Alerts
                  </span>
                  {alertCount > 0 && <span className="garud-nav-badge">{alertCount}</span>}
                </button>
                <button
                  className={`garud-nav-item ${view === "network" ? "active" : ""}`}
                  onClick={() => handleNavClick("network")}
                >
                  <span className="garud-nav-item-left">
                    <Network size={15} /> Network Forecast
                  </span>
                </button>
              </div>
            </div>

            <div>
              <div className="garud-nav-group-label">THREAT INTELLIGENCE</div>
              <div className="garud-nav-list">
                <button
                  className={`garud-nav-item ${view === "explain" ? "active" : ""}`}
                  onClick={() => handleNavClick("explain")}
                >
                  <span className="garud-nav-item-left">
                    <HelpCircle size={15} /> Explain
                  </span>
                </button>
                <button
                  className={`garud-nav-item ${view === "reports" ? "active" : ""}`}
                  onClick={() => handleNavClick("reports")}
                >
                  <span className="garud-nav-item-left">
                    <BarChart3 size={15} /> Forensic Reports
                  </span>
                </button>
              </div>
            </div>

            <div>
              <div className="garud-nav-group-label">DATA & TELEMETRY</div>
              <div className="garud-nav-list">
                <button
                  className={`garud-nav-item ${view === "ingest" ? "active" : ""}`}
                  onClick={() => handleNavClick("ingest")}
                >
                  <span className="garud-nav-item-left">
                    <Upload size={15} /> Ingest Captures
                  </span>
                </button>
                <button
                  className={`garud-nav-item ${view === "settings" ? "active" : ""}`}
                  onClick={() => handleNavClick("settings")}
                >
                  <span className="garud-nav-item-left">
                    <Settings size={15} /> Settings & Lab
                  </span>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar Footer with Live System Status */}
        <div className="garud-sidebar-footer">
          <div className="garud-system-status-title">SYSTEM STATUS</div>
          <div className="garud-status-row">
            <span className="garud-status-name">
              <span className={`garud-status-indicator ${captureRunning ? "live" : "idle"}`} />
              Packet Capture
            </span>
            <span className="garud-status-val" style={{ color: captureRunning ? "var(--success)" : "var(--text-muted)" }}>
              {captureRunning ? "LIVE" : "IDLE"}
            </span>
          </div>
          <div className="garud-status-row">
            <span className="garud-status-name">
              <span className={`garud-status-indicator ${health?.model_loaded ? "online" : "offline"}`} />
              Model (LSTM)
            </span>
            <span className="garud-status-val" style={{ color: health?.model_loaded ? "var(--success)" : "var(--danger)" }}>
              {health?.model_loaded ? "ONLINE" : "OFFLINE"}
            </span>
          </div>
          <div className="garud-status-row">
            <span className="garud-status-name">
              <span className={`garud-status-indicator ${health?.db_connected ? "connected" : "offline"}`} />
              Database
            </span>
            <span className="garud-status-val" style={{ color: health?.db_connected ? "var(--success)" : "var(--danger)" }}>
              {health?.db_connected ? "CONNECTED" : "OFFLINE"}
            </span>
          </div>
          <div className="garud-status-row">
            <span className="garud-status-name">
              <span className="garud-status-indicator ready" />
              MITRE Mapping
            </span>
            <span className="garud-status-val" style={{ color: "var(--success)" }}>
              READY
            </span>
          </div>
          <div className="garud-status-row">
            <span className="garud-status-name">
              <span className={`garud-status-indicator ${simulatorRunning ? "live" : "idle"}`} />
              Simulation
            </span>
            <span className="garud-status-val" style={{ color: simulatorRunning ? "var(--accent)" : "var(--text-muted)" }}>
              {simulatorRunning ? "RUNNING" : "IDLE"}
            </span>
          </div>

          <div className="garud-sidebar-bottom-meta">
            <div>GARUD v1.0 &bull; SIH 2026 | PS26153</div>
            <div>National Security Operational SOC</div>
          </div>
        </div>
      </nav>

      {/* Main Shell (Header + Viewport) */}
      <div className="garud-main-shell">
        <header className="garud-header">
          <div className="garud-header-left">
            <button
              className="garud-mobile-menu-btn"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X size={16} /> : <Menu size={16} />}
            </button>
            <div className="garud-search-box">
              <input
                type="text"
                placeholder="Search IP, application, stage..."
                aria-label="Search telemetry"
              />
              <span className="garud-kbd-chip">Ctrl + K</span>
            </div>
          </div>

          <div className="garud-header-right">
            <span className="garud-header-chip live-chip">
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', display: 'inline-block' }} />
              LIVE
            </span>

            {hostIdentity && (
              <span className="garud-header-chip" title="Protected Host Network">
                <Laptop size={12} color="var(--success)" />
                <span>Host: {hostIdentity.hostname || "LOCAL"}</span>
                <span style={{ color: "var(--text-muted)" }}>[{hostIdentity.primary_ip || "127.0.0.1"}]</span>
              </span>
            )}

            {currentCycle && (
              <span className="garud-header-chip" title={`Current Cycle: ${currentCycle.cycle_id}`}>
                Cycle: #{String(currentCycle.cycle_id || '1').replace(/^cycle_/, '')}
              </span>
            )}

            <span className="garud-header-chip">
              Model: LSTM World Model
            </span>

            {alertCount > 0 && (
              <span
                className="garud-header-chip"
                style={{ color: "var(--danger)", borderColor: "var(--danger-border)", cursor: "pointer" }}
                onClick={() => handleNavClick("alerts")}
              >
                Alerts: {alertCount}
              </span>
            )}

            <button
              className="garud-btn garud-btn-sm"
              onClick={handleStartNewCycle}
              title="Archive current cycle & start fresh"
              style={{ fontSize: 11, padding: "3px 8px" }}
            >
              <RotateCcw size={11} /> New Cycle
            </button>

            <button
              className="garud-btn garud-btn-sm"
              onClick={() => setWellbeingOpen(true)}
              title="View network wellbeing audit history"
              style={{ fontSize: 11, padding: "3px 8px" }}
            >
              <HeartPulse size={11} color="var(--accent)" /> Wellbeing
            </button>

            <span className="garud-header-clock">
              {clock.toLocaleString([], {
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}
            </span>

            <button
              className="garud-btn garud-btn-sm"
              onClick={() => handleNavClick("settings")}
              title="Open Settings & Appearance"
              style={{ padding: "4px 8px" }}
            >
              <Settings size={13} />
            </button>
          </div>
        </header>

        <main className="garud-content-viewport">
          {view === "dashboard" && (
            <Dashboard
              systemMode={systemMode}
              onSelectSession={onSelectSession}
              onNavigate={handleNavClick}
            />
          )}
          {(view === "network" || view === "forecast") && <NetworkForecastView />}
          {view === "alerts" && <AlertsView />}
          {view === "live_logs" && (
            <LiveLogsView
              lines={liveFlows}
              connected={wsConnected}
              onClear={handleClearLiveLogs}
              onReloadRecent={handleReloadRecentLogs}
              systemMode={systemMode}
              captureRunning={captureRunning}
            />
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
              captureRunning={captureRunning}
              onStartLiveCapture={handleStartLiveCapture}
              onStopLiveCapture={handleStopLiveCapture}
              onPurgeSimulated={handlePurgeSimulated}
            />
          )}
        </main>
      </div>

      {modalConfig && (
        <ConfirmModal
          isOpen={Boolean(modalConfig)}
          title={modalConfig.title}
          message={modalConfig.message}
          confirmLabel={modalConfig.confirmLabel}
          cancelLabel={modalConfig.cancelLabel}
          isDestructive={modalConfig.isDestructive}
          isAlert={modalConfig.isAlert}
          onConfirm={() => {
            if (modalConfig.onConfirm) modalConfig.onConfirm();
            else setModalConfig(null);
          }}
          onCancel={() => setModalConfig(null)}
        />
      )}

      <WellbeingModal
        isOpen={wellbeingOpen}
        onClose={() => setWellbeingOpen(false)}
      />
    </div>
  );
}
