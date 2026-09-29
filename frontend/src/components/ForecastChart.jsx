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

// Custom retro-technical tooltip
function ForecastTooltip({ active, payload, isDark, thresholdVal }) {
  if (!active || !payload || !payload.length) return null;
  const pt = payload[0]?.payload;
  if (!pt) return null;

  const value = pt.isObserved ? pt.observedRisk : pt.forecastRisk;
  const isAboveThr = value >= thresholdVal;

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
      <div style={{ color: "var(--text-muted)", fontSize: 10, marginBottom: 4 }}>
        {pt.isNow ? "CURRENT TIME (NOW)" : pt.isObserved ? `OBSERVED (${pt.displayLabel})` : `FORECAST (${pt.displayLabel})`}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 14 }}>
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
      <div style={{ display: "flex", justifyContent: "space-between", gap: 14 }}>
        <span style={{ color: "var(--text-secondary)" }}>Stage:</span>
        <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>
          {pt.stage}
        </span>
      </div>
      {!pt.isObserved && pt.lowerUncertainty != null && (
        <div style={{ display: "flex", justifyContent: "space-between", gap: 14 }}>
          <span style={{ color: "var(--text-secondary)" }}>Uncertainty:</span>
          <span style={{ color: "var(--text-muted)" }}>
            [{pt.lowerUncertainty.toFixed(2)} – {pt.upperUncertainty.toFixed(2)}]
          </span>
        </div>
      )}
    </div>
  );
}

export default function ForecastChart({ forecastData, _onSelectSession }) {
  const { isDark } = useTheme();
  const [horizonFilter, setHorizonFilter] = useState("all");

  // Palette tokens according to active theme
  const observedColor = isDark ? "#39DFEB" : "#252A2D";
  const forecastColor = isDark ? "#F64541" : "#E5392F";
  const forecastBandColor = isDark ? "rgba(246, 69, 65, 0.20)" : "rgba(229, 57, 47, 0.16)";
  const thresholdColor = isDark ? "#F6B144" : "#E8920C";
  const gridColor = isDark ? "rgba(231, 240, 244, 0.05)" : "rgba(37, 42, 45, 0.08)";
  const textColor = isDark ? "#9AA6AA" : "#666B6E";

  const thresholdVal = forecastData?.current?.threshold || 0.40;

  // Build chart timeline combining past observed minutes and forecasted steps
  const chartData = useMemo(() => {
    if (!forecastData || forecastData.status === "no_data") return [];

    const result = [];
    const pastMinutes = forecastData.minutes || [];
    const pastRisks = forecastData.risk_score || [];
    const pastStages = forecastData.stages || [];

    // Take past observed minutes (up to 8 minutes prior)
    const startIdx = Math.max(0, pastMinutes.length - 8);
    for (let i = startIdx; i < pastMinutes.length; i++) {
      const minStr = pastMinutes[i];
      const riskVal = pastRisks[i] != null ? Number(pastRisks[i]) : 0.0;
      const isNow = i === pastMinutes.length - 1;
      const minutesDiff = i - (pastMinutes.length - 1);
      const label = isNow ? "NOW" : `${minutesDiff}m`;

      result.push({
        time: minStr,
        displayLabel: label,
        observedRisk: riskVal,
        forecastRisk: isNow ? riskVal : null,
        lowerUncertainty: isNow ? Math.max(0, riskVal - 0.08) : null,
        upperUncertainty: isNow ? Math.min(1, riskVal + 0.08) : null,
        uncertaintyRange: isNow ? [Math.max(0, riskVal - 0.08), Math.min(1, riskVal + 0.08)] : null,
        stage: pastStages[i] || "Benign",
        isObserved: true,
        isNow,
      });
    }

    // Future forecast steps (+1m, +2m, +3m, +4m...)
    const forecastSteps = forecastData.forecast || [];
    forecastSteps.forEach((step, idx) => {
      const riskVal = Number(step.risk || 0.0);
      const stepNum = idx + 1;
      const topBeh = step.behaviours?.[0]?.behaviour || "Benign";
      const uncertaintySpread = 0.06 + (idx * 0.03); // uncertainty grows with horizon

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
        stage: topBeh,
        isObserved: false,
        isNow: false,
      });
    });

    return result;
  }, [forecastData]);

  const horizonSteps = forecastData?.forecast?.length || 4;

  return (
    <div className="garud-card" style={{ flex: 1, minWidth: 0 }}>
      {/* Header */}
      <div className="garud-card-header">
        <div className="garud-card-title-group">
          <div className="garud-card-indicator-bar danger" />
          <h2 className="garud-card-title">
            ATTACK PROBABILITY FORECAST
          </h2>
          <span className="garud-card-subtitle">
            (WORLD MODEL &bull; {horizonSteps} STEP ROLLOUT)
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

      {/* Body: Chart Canvas */}
      <div className="garud-card-body" style={{ padding: "8px 12px 6px" }}>
        <div className="garud-chart-container">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={chartData}
              margin={{ top: 12, right: 16, left: -22, bottom: 0 }}
            >
              <CartesianGrid stroke={gridColor} strokeDasharray="2 2" vertical={false} />
              <XAxis
                dataKey="displayLabel"
                stroke={textColor}
                tick={{ fill: textColor, fontSize: 10, fontFamily: "var(--font-mono)" }}
                axisLine={{ stroke: gridColor }}
                tickLine={false}
              />
              <YAxis
                domain={[0, 1]}
                ticks={[0.0, 0.25, 0.5, 0.75, 1.0]}
                stroke={textColor}
                tick={{ fill: textColor, fontSize: 10, fontFamily: "var(--font-mono)" }}
                axisLine={{ stroke: gridColor }}
                tickLine={false}
              />
              <Tooltip content={<ForecastTooltip isDark={isDark} thresholdVal={thresholdVal} />} />

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

              {/* Uncertainty Area Range Band */}
              <Area
                type="monotone"
                dataKey="upperUncertainty"
                stroke="none"
                fill={forecastBandColor}
                connectNulls
                isAnimationActive={false}
              />

              {/* Observed History Line (Cyan/Dark) */}
              <Line
                type="monotone"
                dataKey="observedRisk"
                stroke={observedColor}
                strokeWidth={2.5}
                dot={{ r: 3, fill: observedColor, strokeWidth: 0 }}
                activeDot={{ r: 5, fill: observedColor }}
                connectNulls
                isAnimationActive={false}
              />

              {/* Forecast Rollout Line (Red Dashed) */}
              <Line
                type="monotone"
                dataKey="forecastRisk"
                stroke={forecastColor}
                strokeWidth={2.5}
                strokeDasharray="4 3"
                dot={{ r: 4, fill: forecastColor, strokeWidth: 0 }}
                activeDot={{ r: 6, fill: forecastColor }}
                connectNulls
                isAnimationActive={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        {/* Legend */}
        <div className="garud-chart-legend">
          <div className="garud-legend-item">
            <span className="garud-legend-line observed" />
            <span>Observed History</span>
          </div>
          <div className="garud-legend-item">
            <span className="garud-legend-line forecast" />
            <span>Forecast (World Model)</span>
          </div>
          <div className="garud-legend-item">
            <span className="garud-legend-band" />
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
