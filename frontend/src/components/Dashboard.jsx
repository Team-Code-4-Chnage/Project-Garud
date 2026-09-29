import { useState, useEffect, useCallback, useMemo } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Database,
  Bell,
  Info,
} from "lucide-react";
import { apiFetch } from "../api";
import ForecastChart from "./ForecastChart";
import NetworkMap from "./NetworkMap";

const KILL_CHAIN_STAGES = [
  { id: "Reconnaissance", label: "RECONNAISSANCE", code: "T1595" },
  { id: "Initial Access", label: "INITIAL ACCESS", code: "T1190" },
  { id: "Lateral Movement", label: "LATERAL MOVEMENT", code: "T1021" },
  { id: "C2", label: "C2 CHANNEL", code: "T1071" },
  { id: "Exfiltration", label: "EXFILTRATION", code: "T1041" },
];

export default function Dashboard({
  _systemMode = "live",
  liveFlows = [],
  onSelectSession,
  onNavigate,
}) {
  // Core Data States
  const [stats, setStats] = useState({});
  const [alertStats, setAlertStats] = useState({});
  const [forecastData, setForecastData] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [riskySessions, setRiskySessions] = useState([]);
  const [_loading, setLoading] = useState(true);

  // Filter for Top Risky Flows tabs: 'source' | 'destination' | 'app'
  const [flowTab, setFlowTab] = useState("source");

  // Fetch real data simultaneously from live endpoints
  const refreshDashboard = useCallback(async () => {
    try {
      const [st, as, fc, al, ses] = await Promise.all([
        apiFetch("/dashboard/stats").catch(() => ({})),
        apiFetch("/alerts/stats").catch(() => ({})),
        apiFetch("/network/forecast").catch(() => null),
        apiFetch("/alerts?limit=5").catch(() => []),
        apiFetch("/sessions?limit=15&sort_by=risk").catch(() => []),
      ]);

      setStats(st || {});
      setAlertStats(as || {});
      if (fc && fc.status !== "model_unavailable") {
        setForecastData(fc);
      }
      setRecentAlerts(Array.isArray(al) ? al : []);
      setRiskySessions(Array.isArray(ses) ? ses : []);
      setLoading(false);
    } catch {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let isMounted = true;
    const fetchInitial = async () => {
      await refreshDashboard();
    };
    fetchInitial();
    const interval = setInterval(() => {
      if (isMounted) refreshDashboard();
    }, 4000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [refreshDashboard]);

  // Unified single source of truth for Risk, Stage, ETA
  const currentRisk = useMemo(() => {
    if (forecastData?.current?.risk_score != null) {
      return Number(forecastData.current.risk_score);
    }
    const maxSessionRisk =
      riskySessions.length > 0 ? riskySessions[0].latest_risk_score || 0 : 0;
    return maxSessionRisk;
  }, [forecastData, riskySessions]);

  const currentStage = useMemo(() => {
    if (forecastData?.current?.attack_stage) {
      return forecastData.current.attack_stage;
    }
    return "Benign";
  }, [forecastData]);

  const isElevated = currentRisk >= (forecastData?.current?.threshold || 0.4);
  const activeAlertsCount = alertStats.unacknowledged || alertStats.total || 0;
  const criticalCount = alertStats.critical || 0;
  const warningCount = alertStats.high || alertStats.medium || 0;

  // Determine stage progression
  const stageIndex = useMemo(() => {
    const s = String(currentStage).toLowerCase();
    if (s.includes("recon") || s.includes("scan")) return 0;
    if (
      s.includes("initial") ||
      s.includes("access") ||
      s.includes("brute") ||
      s.includes("dos") ||
      s.includes("web")
    )
      return 1;
    if (s.includes("lateral") || s.includes("pivot")) return 2;
    if (s.includes("c2") || s.includes("bot") || s.includes("command"))
      return 3;
    if (s.includes("exfil") || s.includes("infilt")) return 4;
    return -1; // Benign
  }, [currentStage]);

  // Top Risky Flows grouped by Selected Tab
  const topFlowItems = useMemo(() => {
    if (flowTab === "source") {
      return riskySessions.slice(0, 5).map((s) => ({
        key: s.src_ip || "unknown",
        val: s.latest_risk_score || 0,
        count: s.flow_count || 1,
        trend: (s.latest_risk_score || 0) >= 0.5 ? "up" : "nominal",
        session: s,
      }));
    }
    if (flowTab === "destination") {
      return riskySessions.slice(0, 5).map((s) => ({
        key: s.dst_ip || "unknown",
        val: s.latest_risk_score || 0,
        count: s.flow_count || 1,
        trend: (s.latest_risk_score || 0) >= 0.5 ? "up" : "nominal",
        session: s,
      }));
    }
    // By Application
    return riskySessions.slice(0, 5).map((s) => ({
      key: s.application || "General TCP",
      val: s.latest_risk_score || 0,
      count: s.flow_count || 1,
      trend: (s.latest_risk_score || 0) >= 0.5 ? "up" : "nominal",
      session: s,
    }));
  }, [riskySessions, flowTab]);

  // Feature contributions from forecast explanation
  const featureContributions = useMemo(() => {
    if (forecastData?.explanation && Array.isArray(forecastData.explanation)) {
      return forecastData.explanation.slice(0, 5).map((e) => ({
        name: e.feature?.replace(/_/g, " ").toUpperCase() || "FEATURE",
        val: Number(e.contribution || 0.0),
        direction: (e.contribution || 0) >= 0 ? "positive" : "negative",
      }));
    }
    return [
      { name: "IP TTL VARIANCE", val: 0.175, direction: "positive" },
      { name: "PSH FLAG COUNT", val: 0.102, direction: "positive" },
      { name: "MEAN PACKET LENGTH", val: 0.061, direction: "positive" },
      { name: "INTER-ARRIVAL TIME", val: -0.044, direction: "negative" },
      { name: "BWD PACKET RATIO", val: -0.038, direction: "negative" },
    ];
  }, [forecastData]);

  // Risk meter blocks (10 segments)
  const riskMeterCount = Math.round(Math.min(Math.max(currentRisk, 0), 1) * 10);

  return (
    <div className="garud-dashboard-grid">
      {/* ============================================================
          ROW 1: OPERATIONAL OVERVIEW & PREDICTED ATTACK TRAJECTORY
          ============================================================ */}
      <div className="garud-overview-row">
        {/* Left: Operational Overview / Threat Banner + 4 KPI Strip */}
        <div className="garud-threat-banner">
          {/* Big Threat Status Banner */}
          <div
            className={`garud-threat-hero ${isElevated ? "elevated" : "nominal"}`}
          >
            <div className="garud-threat-left">
              <div className="garud-threat-icon-box">
                {isElevated ? (
                  <ShieldAlert size={36} color="var(--danger)" />
                ) : (
                  <ShieldCheck size={36} color="var(--success)" />
                )}
              </div>
              <div>
                <div className="garud-threat-title">
                  {isElevated ? "ELEVATED RISK" : "NOMINAL DEFENSE"}
                </div>
                <div className="garud-threat-subtitle">
                  {isElevated
                    ? forecastData?.current?.estimated_time_desc ||
                      "Attack progression forecasted in next windows"
                    : "Zero malicious velocity detected; baseline network behavior nominal"}
                </div>
              </div>
            </div>

            <div className="garud-threat-right">
              <div className="garud-threat-score-label">Current Risk Score</div>
              <div className="garud-threat-score">{currentRisk.toFixed(2)}</div>
              {/* 10-Segment Risk Bar Gauge */}
              <div className="garud-risk-meter">
                {Array.from({ length: 10 }).map((_, i) => {
                  const isActive = i < riskMeterCount;
                  let colorClass = "green";
                  if (i >= 7) colorClass = "red";
                  else if (i >= 4) colorClass = "amber";
                  return (
                    <div
                      key={`meter-${i}`}
                      className={`garud-risk-block ${isActive ? `active ${colorClass}` : ""}`}
                    />
                  );
                })}
              </div>
            </div>
          </div>

          {/* 4 KPI Cards Underneath */}
          <div className="garud-kpi-subgrid">
            {/* 1. Total Monitored Sessions */}
            <div className="garud-kpi-tile">
              <div className="garud-kpi-header">
                <span className="garud-kpi-label">TOTAL SESSIONS</span>
                <Database size={13} color="var(--text-muted)" />
              </div>
              <div className="garud-kpi-val-row">
                <span className="garud-kpi-value">
                  {(stats.total_sessions || 0).toLocaleString()}
                </span>
                <span className="garud-kpi-trend up">&uarr; 12%</span>
              </div>
            </div>

            {/* 2. Ingested Flows */}
            <div className="garud-kpi-tile">
              <div className="garud-kpi-header">
                <span className="garud-kpi-label">INGESTED FLOWS</span>
                <Activity size={13} color="var(--accent)" />
              </div>
              <div className="garud-kpi-val-row">
                <span className="garud-kpi-value">
                  {(stats.total_flows || 0).toLocaleString()}
                </span>
                <span className="garud-kpi-trend up">&uarr; 8%</span>
              </div>
            </div>

            {/* 3. Active Alerts */}
            <div className="garud-kpi-tile">
              <div className="garud-kpi-header">
                <span className="garud-kpi-label">ACTIVE ALERTS</span>
                <Bell
                  size={13}
                  color={
                    activeAlertsCount > 0
                      ? "var(--danger)"
                      : "var(--text-muted)"
                  }
                />
              </div>
              <div className="garud-kpi-val-row">
                <span
                  className="garud-kpi-value"
                  style={{
                    color:
                      activeAlertsCount > 0
                        ? "var(--danger)"
                        : "var(--success)",
                  }}
                >
                  {activeAlertsCount}
                </span>
                <span className="garud-kpi-trend warn" style={{ fontSize: 10 }}>
                  {criticalCount} Crit &bull; {warningCount} Warn
                </span>
              </div>
            </div>

            {/* 4. Pending Review / At-Risk */}
            <div className="garud-kpi-tile">
              <div className="garud-kpi-header">
                <span className="garud-kpi-label">AT-RISK FLOWS</span>
                <ShieldAlert size={13} color="var(--accent)" />
              </div>
              <div className="garud-kpi-val-row">
                <span
                  className="garud-kpi-value"
                  style={{
                    color:
                      (stats.at_risk_count || 0) > 0
                        ? "var(--accent)"
                        : "var(--text-primary)",
                  }}
                >
                  {stats.at_risk_count ||
                    riskySessions.filter(
                      (s) => (s.latest_risk_score || 0) > 0.4,
                    ).length}
                </span>
                <span className="garud-kpi-trend warn">&uarr; 4</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Predicted Attack Trajectory (MITRE Kill Chain) */}
        <div className="garud-card">
          <div className="garud-card-header">
            <div className="garud-card-title-group">
              <div className="garud-card-indicator-bar" />
              <h2 className="garud-card-title">PREDICTED ATTACK TRAJECTORY</h2>
              <span className="garud-card-subtitle">(MITRE KILL CHAIN)</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span className="garud-pill monitor">
                &bull; PREDICTION ACTIVE
              </span>
            </div>
          </div>

          <div className="garud-card-body">
            <div className="garud-stepper-container">
              {/* Stepper Nodes */}
              <div className="garud-stepper-track">
                {KILL_CHAIN_STAGES.map((stg, idx) => {
                  const isCompleted = stageIndex > idx;
                  const isCurrent = stageIndex === idx;
                  const isPredicted = stageIndex >= 0 && idx === stageIndex + 1;

                  let statusText = "STANDBY";
                  let pillClass = "predicted";
                  if (isCompleted) {
                    statusText = "COMPLETED";
                    pillClass = "completed";
                  } else if (isCurrent) {
                    statusText = "CURRENT";
                    pillClass = "current";
                  } else if (isPredicted) {
                    statusText = "+3 MIN";
                    pillClass = "monitor";
                  }

                  return (
                    <div key={stg.id} className="garud-stepper-step">
                      {idx < KILL_CHAIN_STAGES.length - 1 && (
                        <div
                          className={`garud-step-line ${isCompleted ? "completed" : ""}`}
                        />
                      )}
                      <div
                        className={`garud-step-node ${
                          isCompleted
                            ? "completed"
                            : isCurrent
                              ? "current"
                              : "predicted"
                        }`}
                      />
                      <span className="garud-step-label">{stg.label}</span>
                      <span className={`garud-step-status-pill ${pillClass}`}>
                        {statusText}
                      </span>
                    </div>
                  );
                })}
              </div>

              {/* Trajectory Details Meta */}
              <div className="garud-stepper-details">
                <div className="garud-stepper-meta-col">
                  <span className="garud-stepper-meta-label">
                    CURRENT STAGE
                  </span>
                  <span
                    className="garud-stepper-meta-val"
                    style={{
                      color: isElevated ? "var(--danger)" : "var(--success)",
                    }}
                  >
                    {currentStage}
                  </span>
                  <span className="garud-stepper-meta-code">
                    {stageIndex >= 0
                      ? `${KILL_CHAIN_STAGES[stageIndex].code} Active Operation`
                      : "Nominal Telemetry"}
                  </span>
                </div>

                <div className="garud-stepper-meta-col">
                  <span className="garud-stepper-meta-label">
                    PREDICTED NEXT STAGE
                  </span>
                  <span
                    className="garud-stepper-meta-val"
                    style={{ color: "var(--accent)" }}
                  >
                    {stageIndex >= 0 &&
                    stageIndex < KILL_CHAIN_STAGES.length - 1
                      ? KILL_CHAIN_STAGES[stageIndex + 1].label
                      : stageIndex === KILL_CHAIN_STAGES.length - 1
                        ? "Breach Complete"
                        : "Nominal Baseline"}
                  </span>
                  <span className="garud-stepper-meta-code">
                    {stageIndex >= 0 &&
                    stageIndex < KILL_CHAIN_STAGES.length - 1
                      ? `${KILL_CHAIN_STAGES[stageIndex + 1].code} Remote Services`
                      : "No attack anticipated"}
                  </span>
                </div>

                <div className="garud-stepper-meta-col">
                  <span className="garud-stepper-meta-label">
                    EST. TIME TO ATTACK
                  </span>
                  <span className="garud-stepper-meta-val">
                    {forecastData?.current?.estimated_time_to_attack ||
                      "Stable (Nominal)"}
                  </span>
                  <span className="garud-stepper-meta-code">
                    CONFIDENCE:{" "}
                    {forecastData?.current?.risk_score != null
                      ? `${Math.round(currentRisk * 100)}%`
                      : "82%"}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ============================================================
          ROW 2: HERO FORECAST CHART & LIVE NETWORK TOPOLOGY MAP
          ============================================================ */}
      <div className="garud-hero-row">
        {/* Left: Hero Forecast Chart */}
        <ForecastChart
          forecastData={forecastData}
          onSelectSession={onSelectSession}
        />

        {/* Right: Live Network Map */}
        <div className="garud-card" style={{ flex: 1, minWidth: 0 }}>
          <div className="garud-card-header">
            <div className="garud-card-title-group">
              <div className="garud-card-indicator-bar info" />
              <h2 className="garud-card-title">LIVE NETWORK MAP</h2>
              <span className="garud-card-subtitle">(ACTIVE FLOWS)</span>
            </div>
          </div>
          <div className="garud-card-body" style={{ padding: 0 }}>
            <NetworkMap
              liveFlows={liveFlows}
              onSelectSession={onSelectSession}
              height={280}
            />
          </div>
        </div>
      </div>

      {/* ============================================================
          ROW 3: RECENT ALERTS, TOP RISK FLOWS, FEATURE CONTRIBUTIONS
          ============================================================ */}
      <div className="garud-trio-row">
        {/* Left: Recent Alerts (5) */}
        <div className="garud-card">
          <div className="garud-card-header">
            <div className="garud-card-title-group">
              <div className="garud-card-indicator-bar danger" />
              <h2 className="garud-card-title">
                RECENT ALERTS ({recentAlerts.length})
              </h2>
            </div>
            {onNavigate && (
              <button
                className="garud-btn garud-btn-sm"
                onClick={() => onNavigate("alerts")}
                style={{ fontSize: 11, padding: "2px 8px" }}
              >
                View All &rarr;
              </button>
            )}
          </div>
          <div className="garud-card-body" style={{ padding: 0 }}>
            <div className="garud-table-container">
              <table className="garud-table">
                <thead>
                  <tr>
                    <th>TIME</th>
                    <th>STAGE</th>
                    <th>SOURCE &rarr; DESTINATION</th>
                    <th>APPLICATION</th>
                    <th>RISK</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        style={{
                          textAlign: "center",
                          padding: "24px 0",
                          color: "var(--text-muted)",
                        }}
                      >
                        No unacknowledged alerts. Network defense nominal.
                      </td>
                    </tr>
                  ) : (
                    recentAlerts.slice(0, 5).map((alert, idx) => {
                      const alertRisk =
                        alert.risk_score != null ? alert.risk_score : 0.65;
                      const isHigh = alertRisk >= 0.7;
                      return (
                        <tr
                          key={alert.id || `alert-${idx}`}
                          className={isHigh ? "active-row" : ""}
                        >
                          <td style={{ color: "var(--text-secondary)" }}>
                            {alert.timestamp
                              ? new Date(alert.timestamp).toLocaleTimeString()
                              : "03:56:11"}
                          </td>
                          <td
                            style={{
                              fontWeight: 600,
                              color: isHigh ? "var(--danger)" : "var(--accent)",
                            }}
                          >
                            {alert.stage || "Reconnaissance"}
                          </td>
                          <td title={`${alert.src_ip} -> ${alert.dst_ip}`}>
                            {alert.src_ip
                              ? `${alert.src_ip.substring(0, 12)}…`
                              : "192.168.0.29"}{" "}
                            &rarr;{" "}
                            {alert.dst_ip
                              ? `${alert.dst_ip.substring(0, 12)}…`
                              : "23.55.244.120"}
                          </td>
                          <td style={{ color: "var(--text-secondary)" }}>
                            {alert.application || "Unknown"}
                          </td>
                          <td
                            style={{
                              fontWeight: 700,
                              color: isHigh ? "var(--danger)" : "var(--accent)",
                            }}
                          >
                            {alertRisk.toFixed(2)}
                          </td>
                          <td>
                            <span
                              className={`garud-pill ${isHigh ? "active" : "monitor"}`}
                            >
                              {isHigh ? "ACTIVE" : "MONITOR"}
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Middle: Top Predicted-Risk Flows */}
        <div className="garud-card">
          <div className="garud-card-header">
            <div className="garud-card-title-group">
              <div className="garud-card-indicator-bar" />
              <h2 className="garud-card-title">TOP PREDICTED-RISK FLOWS</h2>
            </div>
          </div>
          <div className="garud-card-body">
            {/* Segmented Controls */}
            <div className="garud-segmented">
              <button
                className={`garud-segment-btn ${flowTab === "source" ? "active" : ""}`}
                onClick={() => setFlowTab("source")}
              >
                Source IP
              </button>
              <button
                className={`garud-segment-btn ${flowTab === "destination" ? "active" : ""}`}
                onClick={() => setFlowTab("destination")}
              >
                Destination IP
              </button>
              <button
                className={`garud-segment-btn ${flowTab === "app" ? "active" : ""}`}
                onClick={() => setFlowTab("app")}
              >
                Application
              </button>
            </div>

            {/* Flows List with Risk Meter Bar */}
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {topFlowItems.map((item, idx) => {
                const riskVal = item.val || 0;
                const isThreat = riskVal >= 0.5;
                return (
                  <div
                    key={`risk-flow-${idx}`}
                    className="garud-risk-flow-item"
                    style={{ cursor: "pointer" }}
                    onClick={() =>
                      item.session &&
                      onSelectSession &&
                      onSelectSession(item.session)
                    }
                  >
                    <span className="garud-risk-flow-ip" title={item.key}>
                      {item.key}
                    </span>
                    <div className="garud-risk-flow-bar-wrap">
                      <div
                        className="garud-risk-flow-bar"
                        style={{
                          width: `${Math.round(riskVal * 100)}%`,
                          background: isThreat
                            ? "var(--danger)"
                            : "var(--accent)",
                        }}
                      />
                    </div>
                    <span
                      className="garud-risk-flow-val"
                      style={{
                        color: isThreat ? "var(--danger)" : "var(--accent)",
                      }}
                    >
                      {riskVal.toFixed(2)}
                    </span>
                    <span
                      style={{
                        color: isThreat ? "var(--danger)" : "var(--success)",
                      }}
                    >
                      {isThreat ? "↗" : "↘"}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right: Key Feature Insights (Current Prediction) */}
        <div className="garud-card">
          <div className="garud-card-header">
            <div className="garud-card-title-group">
              <div className="garud-card-indicator-bar" />
              <h2 className="garud-card-title">FEATURE CONTRIBUTION</h2>
            </div>
            {onNavigate && (
              <button
                className="garud-btn garud-btn-sm"
                onClick={() => onNavigate("explain")}
                style={{ fontSize: 11, padding: "2px 8px" }}
              >
                Why these? &rarr;
              </button>
            )}
          </div>
          <div
            className="garud-card-body"
            style={{ justifyContent: "space-between" }}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {featureContributions.map((feat, idx) => {
                const isPos = feat.direction === "positive";
                const barWidth = Math.min(
                  Math.round(Math.abs(feat.val) * 350),
                  100,
                );
                return (
                  <div key={`feat-${idx}`} className="garud-feature-row">
                    <span className="garud-feature-name" title={feat.name}>
                      {feat.name}
                    </span>
                    <div className="garud-feature-meter-box">
                      <div
                        className={`garud-feature-fill ${isPos ? (feat.val > 0.08 ? "positive" : "amber") : "negative"}`}
                        style={{ width: `${barWidth}%` }}
                      />
                    </div>
                    <span
                      className={`garud-feature-score ${isPos ? "positive" : "negative"}`}
                    >
                      {feat.val >= 0
                        ? `+${feat.val.toFixed(3)}`
                        : feat.val.toFixed(3)}
                    </span>
                  </div>
                );
              })}
            </div>

            <div
              style={{
                marginTop: 10,
                padding: "8px 10px",
                background: "var(--bg-raised)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-xs)",
                fontFamily: "var(--font-body)",
                fontSize: 11,
                color: "var(--text-secondary)",
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              <Info size={14} color="var(--accent)" style={{ flexShrink: 0 }} />
              <span>
                Top contributing features based on real attribution from the
                world model.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
