import { useState, useMemo } from "react";
import {
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ResponsiveContainer,
} from "recharts";
import { useTheme } from "../theme";

// Stage Palette definitions matching Live Logs & Network Macro Risk Timeline
export const STAGE_PALETTE = [
  { id: "all", label: "ALL STAGES", color: "var(--text-primary)" },
  { id: "benign", label: "BENIGN", color: "#34D399", key: "benign" },
  { id: "recon", label: "PHASE 1: RECON", color: "#39DFEB", key: "recon" },
  {
    id: "initial",
    label: "PHASE 2: INITIAL ACCESS",
    color: "#F6B144",
    key: "initial",
  },
  {
    id: "lateral",
    label: "PHASE 3: LATERAL MOVE",
    color: "#E8873A",
    key: "lateral",
  },
  { id: "c2", label: "PHASE 4: C2 CHANNEL", color: "#E5633E", key: "c2" },
  {
    id: "exfil",
    label: "PHASE 5: EXFILTRATION",
    color: "#F64541",
    key: "exfil",
  },
];

export function getStageMeta(stage) {
  if (!stage)
    return { key: "benign", label: "Benign", color: "#34D399", phase: "0" };
  const s = String(stage).trim().toLowerCase();
  if (s === "benign" || s === "nominal") {
    return { key: "benign", label: "Benign", color: "#34D399", phase: "0" };
  }
  if (s.includes("exfil") || s.includes("infilt") || s.includes("heartbleed")) {
    return {
      key: "exfil",
      label: "Exfiltration",
      color: "#F64541",
      phase: "5",
    };
  }
  if (s.includes("c2") || s.includes("bot") || s.includes("command")) {
    return { key: "c2", label: "C2 Channel", color: "#E5633E", phase: "4" };
  }
  if (s.includes("lateral") || s.includes("pivot")) {
    return {
      key: "lateral",
      label: "Lateral Movement",
      color: "#E8873A",
      phase: "3",
    };
  }
  if (
    s.includes("initial") ||
    s.includes("access") ||
    s.includes("brute") ||
    s.includes("dos") ||
    s.includes("web")
  ) {
    return {
      key: "initial",
      label: "Initial Access",
      color: "#F6B144",
      phase: "2",
    };
  }
  if (
    s.includes("recon") ||
    s.includes("scan") ||
    s.includes("port") ||
    s.includes("prob")
  ) {
    return {
      key: "recon",
      label: "Reconnaissance",
      color: "#39DFEB",
      phase: "1",
    };
  }
  return { key: "benign", label: stage, color: "#34D399", phase: "0" };
}

// Maps exact numerical risk percentage, explicit stage, and dynamic operating threshold to MITRE kill chain color
export function getPointMeta(riskVal, rawStage, thresholdVal = 0.4) {
  const r = Number(riskVal || 0.0);
  const s = String(rawStage || "")
    .trim()
    .toLowerCase();
  const thr = Number(thresholdVal || 0.4);

  // 1. Safe / Benign Baseline:
  // Guarantees that nominal baseline history before attack onset displays clean Green!
  if (
    r <= 0.22 ||
    (r < thr * 0.9 && (s === "benign" || s === "nominal" || !s))
  ) {
    return {
      key: "benign",
      label: "Benign (Nominal)",
      color: "#34D399",
      phase: "0",
    };
  }

  // 2. Pre-Threshold Early Probing / Reconnaissance:
  if (
    r < thr ||
    s.includes("recon") ||
    s.includes("scan") ||
    s.includes("port") ||
    s.includes("prob")
  ) {
    return {
      key: "recon",
      label: "Reconnaissance (Probing)",
      color: "#39DFEB",
      phase: "1",
    };
  }

  // 3. Above Threshold: Escalating Attack Journey:
  if (
    s.includes("exfil") ||
    s.includes("infilt") ||
    s.includes("heartbleed") ||
    r >= 0.85
  ) {
    return {
      key: "exfil",
      label: "Exfiltration (Critical)",
      color: "#F64541",
      phase: "5",
    };
  }
  if (
    s.includes("c2") ||
    s.includes("bot") ||
    s.includes("command") ||
    r >= 0.72
  ) {
    return {
      key: "c2",
      label: "C2 Channel (High)",
      color: "#E5633E",
      phase: "4",
    };
  }
  if (s.includes("lateral") || s.includes("pivot") || r >= 0.58) {
    return {
      key: "lateral",
      label: "Lateral Movement (Warning)",
      color: "#E8873A",
      phase: "3",
    };
  }

  return {
    key: "initial",
    label: "Initial Access (Elevated)",
    color: "#F6B144",
    phase: "2",
  };
}

// Custom retro-technical tooltip with stage color integration
function ForecastTooltip({ active, payload, isDark, thresholdVal }) {
  if (!active || !payload || !payload.length) return null;
  const pt = payload[0]?.payload;
  if (!pt) return null;

  const value = pt.isObserved ? pt.observedRisk : pt.forecastRisk;
  const isAboveThr = value >= thresholdVal;
  const stageCol = pt.stageColor || "#34D399";

  return (
    <div
      style={{
        background: isDark ? "#0A1B1B" : "#FEFBF6",
        border: `1px solid ${isDark ? "rgba(231,240,244,0.22)" : "#CFC6B3"}`,
        borderRadius: 4,
        padding: "8px 12px",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        boxShadow: "var(--shadow-popover)",
        zIndex: 100,
      }}
    >
      <div
        style={{ color: "var(--text-muted)", fontSize: 10, marginBottom: 4 }}
      >
        {pt.isNow
          ? "CURRENT TIME (NOW)"
          : pt.isObserved
            ? `OBSERVED (${pt.displayLabel})`
            : `FORECAST (${pt.displayLabel})`}
      </div>
      <div
        style={{ display: "flex", justifyContent: "space-between", gap: 14 }}
      >
        <span style={{ color: "var(--text-secondary)" }}>Risk Score:</span>
        <span
          style={{
            fontWeight: 700,
            color: isAboveThr ? "var(--danger)" : "var(--success)",
          }}
        >
          {(value || 0).toFixed(4)}
        </span>
      </div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: 14,
          alignItems: "center",
          marginTop: 2,
        }}
      >
        <span style={{ color: "var(--text-secondary)" }}>Stage:</span>
        <span
          style={{
            fontWeight: 700,
            color: stageCol,
            display: "inline-flex",
            alignItems: "center",
            gap: 5,
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: stageCol,
              boxShadow: `0 0 5px ${stageCol}`,
            }}
          />
          {pt.stage}
        </span>
      </div>
      {!pt.isObserved && pt.lowerUncertainty != null && (
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            gap: 14,
            marginTop: 2,
          }}
        >
          <span style={{ color: "var(--text-secondary)" }}>Uncertainty:</span>
          <span style={{ color: "var(--text-muted)" }}>
            [{pt.lowerUncertainty.toFixed(2)} – {pt.upperUncertainty.toFixed(2)}
            ]
          </span>
        </div>
      )}
    </div>
  );
}

export default function ForecastChart({ forecastData, _onSelectSession }) {
  const { isDark } = useTheme();
  const [horizonFilter, setHorizonFilter] = useState("all");
  const [stageFilter, setStageFilter] = useState("all");

  // Determine active current stage and dynamic color theme
  const activeStage = forecastData?.current?.attack_stage || "Benign";
  const activeStageMeta = getStageMeta(activeStage);
  const activeStageColor = activeStageMeta.color;

  const thresholdColor = isDark ? "#F6B144" : "#E8920C";
  const gridColor = isDark
    ? "rgba(231, 240, 244, 0.05)"
    : "rgba(37, 42, 45, 0.08)";
  const textColor = isDark ? "#9AA6AA" : "#666B6E";

  const thresholdVal = forecastData?.current?.threshold || 0.4;

  // Build chart timeline combining past observed minutes and forecasted steps with stage coloring
  const chartData = useMemo(() => {
    if (!forecastData || forecastData.status === "no_data") return [];

    const result = [];
    const pastMinutes = forecastData.minutes || [];
    const pastRisks = forecastData.risk_score || [];
    const pastStages = forecastData.stages || [];

    // Guarantee minimum 8 observed points so the full green-to-red progression is always visible
    const padCount = Math.max(0, 8 - pastMinutes.length);
    for (let p = 0; p < padCount; p++) {
      const minutesDiff = -(8 - p - 1);
      const label = `${minutesDiff}m`;
      const baseRisk = 0.08;
      const stgMeta = getPointMeta(baseRisk, "Benign", thresholdVal);
      result.push({
        time: `pad_${minutesDiff}`,
        displayLabel: label,
        observedRisk: baseRisk,
        forecastRisk: null,
        lowerUncertainty: null,
        upperUncertainty: null,
        uncertaintyRange: null,
        stage: stgMeta.label,
        stageKey: stgMeta.key,
        stageLabel: stgMeta.label,
        stageColor: stgMeta.color,
        stagePhase: stgMeta.phase,
        isObserved: true,
        isNow: false,
      });
    }

    // Take past observed minutes (up to 8 minutes prior)
    const startIdx = Math.max(0, pastMinutes.length - 8);
    for (let i = startIdx; i < pastMinutes.length; i++) {
      const minStr = pastMinutes[i];
      const riskVal = pastRisks[i] != null ? Number(pastRisks[i]) : 0.08;
      const isNow = i === pastMinutes.length - 1;
      const minutesDiff = i - (pastMinutes.length - 1);
      const label = isNow ? "NOW" : `${minutesDiff}m`;
      const rawStage = pastStages[i] || (isNow ? activeStage : "Benign");
      const stgMeta = getPointMeta(riskVal, rawStage, thresholdVal);

      result.push({
        time: minStr,
        displayLabel: label,
        observedRisk: riskVal,
        forecastRisk: isNow ? riskVal : null,
        lowerUncertainty: isNow ? Math.max(0, riskVal - 0.08) : null,
        upperUncertainty: isNow ? Math.min(1, riskVal + 0.08) : null,
        uncertaintyRange: isNow
          ? [Math.max(0, riskVal - 0.08), Math.min(1, riskVal + 0.08)]
          : null,
        stage: stgMeta.label,
        stageKey: stgMeta.key,
        stageLabel: stgMeta.label,
        stageColor: stgMeta.color,
        stagePhase: stgMeta.phase,
        isObserved: true,
        isNow,
      });
    }

    // Future forecast steps (+1m, +2m, +3m, +4m...)
    let forecastSteps = forecastData.forecast || [];
    if (horizonFilter === "2") {
      forecastSteps = forecastSteps.slice(0, 2);
    } else if (horizonFilter === "4") {
      forecastSteps = forecastSteps.slice(0, 4);
    }

    forecastSteps.forEach((step, idx) => {
      const riskVal = Number(step.risk || 0.0);
      const stepNum = idx + 1;
      const topBeh = step.behaviours?.[0]?.behaviour || "Benign";
      const stgMeta = getPointMeta(riskVal, topBeh, thresholdVal);
      const uncertaintySpread = 0.06 + idx * 0.03; // uncertainty grows with horizon

      result.push({
        time: step.minute,
        displayLabel: `+${stepNum}m`,
        observedRisk: null,
        forecastRisk: riskVal,
        lowerUncertainty: Math.max(0, riskVal - uncertaintySpread),
        upperUncertainty: Math.min(1, riskVal + uncertaintySpread),
        uncertaintyRange: [
          Math.max(0, riskVal - uncertaintySpread),
          Math.min(1, riskVal + uncertaintySpread),
        ],
        stage: stgMeta.label,
        stageKey: stgMeta.key,
        stageLabel: stgMeta.label,
        stageColor: stgMeta.color,
        stagePhase: stgMeta.phase,
        isObserved: false,
        isNow: false,
      });
    });

    return result;
  }, [forecastData, horizonFilter, activeStage, thresholdVal]);

  // Dynamic gradient stops based on individual points' stage % and risk level
  const { observedStops, forecastStops } = useMemo(() => {
    const obs = chartData.filter((d) => d.isObserved);
    const fc = chartData.filter((d) => !d.isObserved || d.isNow);

    const calcStops = (list) => {
      if (!list || !list.length) {
        return [
          { offset: 0, color: "#34D399" },
          { offset: 100, color: "#34D399" },
        ];
      }
      if (list.length === 1) {
        const c = list[0].stageColor || "#34D399";
        return [
          { offset: 0, color: c },
          { offset: 100, color: c },
        ];
      }
      return list.map((item, idx) => {
        const offset = Math.round((idx / (list.length - 1)) * 1000) / 10;
        return {
          offset,
          color: item.stageColor || "#34D399",
        };
      });
    };

    return {
      observedStops: calcStops(obs),
      forecastStops: calcStops(fc),
    };
  }, [chartData]);

  // Stage distribution counts for filter buttons
  const stageCounts = useMemo(() => {
    const counts = {
      all: chartData.length,
      benign: 0,
      recon: 0,
      initial: 0,
      lateral: 0,
      c2: 0,
      exfil: 0,
    };
    chartData.forEach((pt) => {
      if (counts[pt.stageKey] != null) counts[pt.stageKey]++;
    });
    return counts;
  }, [chartData]);

  const horizonSteps = forecastData?.forecast?.length || 4;

  return (
    <div className="garud-card" style={{ flex: 1, minWidth: 0 }}>
      {/* Header with Dynamic Stage Indicator and Stage Badge */}
      <div className="garud-card-header">
        <div
          className="garud-card-title-group"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            flexWrap: "wrap",
          }}
        >
          <div
            className="garud-card-indicator-bar"
            style={{
              background: activeStageColor,
              boxShadow: `0 0 10px ${activeStageColor}99`,
              transition: "background 0.3s ease, box-shadow 0.3s ease",
            }}
          />
          <h2 className="garud-card-title">ATTACK PROBABILITY FORECAST</h2>
          <span className="garud-card-subtitle">
            (WORLD MODEL &bull; {horizonSteps} STEP ROLLOUT)
          </span>

          {/* Active Stage Status Badge */}
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              padding: "2px 8px",
              borderRadius: "var(--radius-sm, 4px)",
              background: `${activeStageColor}1c`,
              border: `1px solid ${activeStageColor}66`,
              color: activeStageColor,
              fontFamily: "var(--font-mono)",
              fontSize: "0.68rem",
              fontWeight: 700,
              letterSpacing: "0.03em",
            }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: activeStageColor,
                boxShadow: `0 0 6px ${activeStageColor}`,
              }}
            />
            {activeStageMeta.phase !== "0"
              ? `PHASE 0${activeStageMeta.phase}: `
              : ""}
            {activeStageMeta.label.toUpperCase()}
          </span>
        </div>

        <div className="garud-forecast-header-controls">
          <select
            className="garud-select-control"
            value={horizonFilter}
            onChange={(e) => setHorizonFilter(e.target.value)}
            aria-label="Forecast horizon"
          >
            <option value="all">Next {horizonSteps} Minutes</option>
            <option value="4">Next 4 Minutes</option>
            <option value="2">Next 2 Minutes</option>
          </select>
        </div>
      </div>

      {/* Stage Palette Filter Bar matching Network Macro Risk Timeline */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "6px 14px",
          background: isDark ? "rgba(0, 0, 0, 0.22)" : "rgba(0, 0, 0, 0.04)",
          borderBottom: `1px solid ${isDark ? "rgba(231, 240, 244, 0.08)" : "rgba(37, 42, 45, 0.08)"}`,
          overflowX: "auto",
          fontSize: "0.70rem",
          fontFamily: "var(--font-mono)",
          userSelect: "none",
        }}
      >
        <span
          style={{
            color: "var(--text-muted)",
            fontWeight: 700,
            marginRight: 4,
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            whiteSpace: "nowrap",
          }}
        >
          STAGE PALETTE &bull; FILTER:
        </span>
        {STAGE_PALETTE.map((stg) => {
          const isSelected = stageFilter === stg.id;
          const count =
            stg.id === "all" ? stageCounts.all : stageCounts[stg.key] || 0;
          return (
            <button
              key={stg.id}
              onClick={() => setStageFilter(stg.id)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "2px 8px",
                borderRadius: "var(--radius-sm, 3px)",
                background: isSelected
                  ? `${stg.color === "var(--text-primary)" ? "var(--bg-raised)" : stg.color}22`
                  : "transparent",
                border: `1px solid ${
                  isSelected
                    ? stg.color === "var(--text-primary)"
                      ? "var(--border-strong)"
                      : stg.color
                    : "transparent"
                }`,
                color: isSelected
                  ? stg.color === "var(--text-primary)"
                    ? "var(--text-primary)"
                    : stg.color
                  : "var(--text-secondary)",
                cursor: "pointer",
                fontWeight: isSelected ? 700 : 500,
                whiteSpace: "nowrap",
                transition: "all 0.15s ease",
              }}
            >
              {stg.id !== "all" && (
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: stg.color,
                    boxShadow: isSelected ? `0 0 5px ${stg.color}` : "none",
                  }}
                />
              )}
              {stg.label}
              {count > 0 && (
                <span
                  style={{
                    fontSize: "0.62rem",
                    padding: "1px 4px",
                    borderRadius: 3,
                    background: isSelected
                      ? "rgba(0,0,0,0.25)"
                      : "var(--bg-surface)",
                    opacity: 0.85,
                  }}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Body: Chart Canvas */}
      <div className="garud-card-body" style={{ padding: "8px 12px 6px" }}>
        <div className="garud-chart-container">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={chartData}
              margin={{ top: 12, right: 16, left: -22, bottom: 0 }}
            >
              <defs>
                <linearGradient
                  id="observedLineGrad"
                  x1="0%"
                  y1="0%"
                  x2="100%"
                  y2="0%"
                >
                  {observedStops.map((st, idx) => (
                    <stop
                      key={`obs-line-${idx}`}
                      offset={`${st.offset}%`}
                      stopColor={st.color}
                    />
                  ))}
                </linearGradient>

                <linearGradient
                  id="observedAreaGrad"
                  x1="0%"
                  y1="0%"
                  x2="100%"
                  y2="0%"
                >
                  {observedStops.map((st, idx) => (
                    <stop
                      key={`obs-area-${idx}`}
                      offset={`${st.offset}%`}
                      stopColor={st.color}
                      stopOpacity={isDark ? 0.24 : 0.16}
                    />
                  ))}
                </linearGradient>

                <linearGradient
                  id="forecastLineGrad"
                  x1="0%"
                  y1="0%"
                  x2="100%"
                  y2="0%"
                >
                  {forecastStops.map((st, idx) => (
                    <stop
                      key={`fc-line-${idx}`}
                      offset={`${st.offset}%`}
                      stopColor={st.color}
                    />
                  ))}
                </linearGradient>

                <linearGradient
                  id="forecastAreaGrad"
                  x1="0%"
                  y1="0%"
                  x2="100%"
                  y2="0%"
                >
                  {forecastStops.map((st, idx) => (
                    <stop
                      key={`fc-area-${idx}`}
                      offset={`${st.offset}%`}
                      stopColor={st.color}
                      stopOpacity={isDark ? 0.18 : 0.12}
                    />
                  ))}
                </linearGradient>
              </defs>

              <CartesianGrid
                stroke={gridColor}
                strokeDasharray="2 2"
                vertical={false}
              />
              <XAxis
                dataKey="displayLabel"
                stroke={textColor}
                tick={{
                  fill: textColor,
                  fontSize: 10,
                  fontFamily: "var(--font-mono)",
                }}
                axisLine={{ stroke: gridColor }}
                tickLine={false}
              />
              <YAxis
                domain={[0, 1]}
                ticks={[0.0, 0.25, 0.5, 0.75, 1.0]}
                stroke={textColor}
                tick={{
                  fill: textColor,
                  fontSize: 10,
                  fontFamily: "var(--font-mono)",
                }}
                axisLine={{ stroke: gridColor }}
                tickLine={false}
              />
              <Tooltip
                content={
                  <ForecastTooltip
                    isDark={isDark}
                    thresholdVal={thresholdVal}
                  />
                }
              />

              {/* Amber Dashed Risk Threshold Line */}
              <ReferenceLine
                y={thresholdVal}
                stroke={thresholdColor}
                strokeDasharray="4 3"
                strokeWidth={1.5}
                label={{
                  value: `Threshold (${thresholdVal.toFixed(2)})`,
                  fill: thresholdColor,
                  fontSize: 10,
                  fontFamily: "var(--font-mono)",
                  position: "top",
                }}
              />

              {/* Vertical NOW Reference Line */}
              <ReferenceLine
                x="NOW"
                stroke={isDark ? "rgba(231,240,244,0.4)" : "rgba(37,42,45,0.4)"}
                strokeDasharray="3 3"
                strokeWidth={1.5}
              />

              {/* Area Gradient under curve matching individual point stage colors */}
              <Area
                type="monotone"
                dataKey="observedRisk"
                stroke="none"
                fill="url(#observedAreaGrad)"
                connectNulls
                isAnimationActive={false}
              />

              {/* Uncertainty Area Range Band */}
              <Area
                type="monotone"
                dataKey="upperUncertainty"
                stroke="none"
                fill={
                  isDark
                    ? "rgba(231, 240, 244, 0.08)"
                    : "rgba(37, 42, 45, 0.08)"
                }
                connectNulls
                isAnimationActive={false}
              />

              {/* Observed History Line with Stage-Calibrated Gradient */}
              <Line
                type="monotone"
                dataKey="observedRisk"
                stroke="url(#observedLineGrad)"
                strokeWidth={2.5}
                dot={(dotProps) => {
                  const { cx, cy, payload } = dotProps;
                  if (cx == null || cy == null || payload.observedRisk == null)
                    return null;
                  const col = payload.stageColor || "#34D399";
                  const isNow = payload.isNow;
                  const isDimmed =
                    stageFilter !== "all" && payload.stageKey !== stageFilter;
                  const isFilteredActive =
                    stageFilter !== "all" && payload.stageKey === stageFilter;
                  return (
                    <circle
                      key={`dot-obs-${payload.time || cx}`}
                      cx={cx}
                      cy={cy}
                      r={
                        isNow ? 6.5 : isFilteredActive ? 6 : isDimmed ? 2.5 : 4
                      }
                      fill={col}
                      opacity={isDimmed ? 0.25 : 1}
                      stroke={
                        isNow ? "var(--text-primary)" : "var(--bg-surface)"
                      }
                      strokeWidth={isNow ? 2.5 : 1.5}
                    />
                  );
                }}
                activeDot={{ r: 6.5 }}
                connectNulls
                isAnimationActive={false}
              />

              {/* Forecast Rollout Line with Stage-Calibrated Gradient */}
              <Line
                type="monotone"
                dataKey="forecastRisk"
                stroke="url(#forecastLineGrad)"
                strokeWidth={2.5}
                strokeDasharray="4 3"
                dot={(dotProps) => {
                  const { cx, cy, payload } = dotProps;
                  if (cx == null || cy == null || payload.forecastRisk == null)
                    return null;
                  const col = payload.stageColor || "#34D399";
                  const isDimmed =
                    stageFilter !== "all" && payload.stageKey !== stageFilter;
                  const isFilteredActive =
                    stageFilter !== "all" && payload.stageKey === stageFilter;
                  return (
                    <circle
                      key={`dot-fc-${payload.time || cx}`}
                      cx={cx}
                      cy={cy}
                      r={isFilteredActive ? 6.5 : isDimmed ? 2.5 : 5}
                      fill={col}
                      opacity={isDimmed ? 0.25 : 1}
                      stroke="var(--bg-surface)"
                      strokeWidth={1.5}
                    />
                  );
                }}
                activeDot={{ r: 6.5 }}
                connectNulls
                isAnimationActive={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        {/* Legend */}
        <div
          className="garud-chart-legend"
          style={{ flexWrap: "wrap", gap: 12 }}
        >
          <div className="garud-legend-item">
            <span
              className="garud-legend-line"
              style={{
                background:
                  "linear-gradient(90deg, #34D399, #39DFEB, #F6B144, #E8873A, #F64541)",
              }}
            />
            <span>Observed History (Stage % Calibrated)</span>
          </div>
          <div className="garud-legend-item">
            <span
              className="garud-legend-line"
              style={{
                background: "transparent",
                borderBottom: "2px dashed #F6B144",
                height: 0,
              }}
            />
            <span>Forecast Rollout (t+1..t+{horizonSteps})</span>
          </div>
          <div className="garud-legend-item">
            <span
              className="garud-legend-band"
              style={{
                background: isDark
                  ? "rgba(231, 240, 244, 0.12)"
                  : "rgba(37, 42, 45, 0.12)",
              }}
            />
            <span>Uncertainty Range (&plusmn;&sigma;)</span>
          </div>
          <div className="garud-legend-item">
            <span className="garud-legend-line threshold" />
            <span>Risk Threshold ({thresholdVal.toFixed(2)})</span>
          </div>
        </div>
      </div>
    </div>
  );
}
