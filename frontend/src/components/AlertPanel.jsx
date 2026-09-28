import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Search,
  RotateCcw,
  ArrowRight,
  Trash2,
  Lock,
  Link,
  Copy,
  Check,
  Terminal,
  X,
  Layers,
} from "lucide-react";
import { apiFetch, apiPost } from "../api";
import { stageClass, formatTime, formatProb } from "../utils";
import { IdentityBadge } from "./Badges";

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Filters
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [stageFilter, setStageFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Option B: Proactive Mitigation Engine States
  const [selectedRuleAlert, setSelectedRuleAlert] = useState(null);
  const [activeRulesModalOpen, setActiveRulesModalOpen] = useState(false);
  const [activeRules, setActiveRules] = useState([]);
  const [containmentLoading, setContainmentLoading] = useState(false);
  const [copiedRuleType, setCopiedRuleType] = useState(null);

  // Option C: Blockchain Immutable Audit Ledger States
  const [ledgerStatus, setLedgerStatus] = useState(null);
  const [ledgerModalOpen, setLedgerModalOpen] = useState(false);
  const [ledgerBlocks, setLedgerBlocks] = useState([]);
  const [verifyingLedger, setVerifyingLedger] = useState(false);
  const [copiedHash, setCopiedHash] = useState(null);
  const [tamperSimulated, setTamperSimulated] = useState(false);

  const fetchLedgerStatus = useCallback(async () => {
    try {
      const res = await apiFetch("/alerts/ledger/verify");
      setLedgerStatus(res);
    } catch (e) {
      console.error("Failed to verify blockchain ledger:", e);
    }
  }, []);

  const refresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [resAlerts, resLedger] = await Promise.all([
        apiFetch("/alerts?limit=500"),
        apiFetch("/alerts/ledger/verify").catch(() => null),
      ]);
      setAlerts(Array.isArray(resAlerts) ? resAlerts : []);
      if (resLedger) setLedgerStatus(resLedger);
    } catch (e) {
      console.error("Failed to load alerts:", e);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [resAlerts, resLedger] = await Promise.all([
          apiFetch("/alerts?limit=500"),
          apiFetch("/alerts/ledger/verify").catch(() => null),
        ]);
        if (!active) return;
        setAlerts(Array.isArray(resAlerts) ? resAlerts : []);
        if (resLedger) setLedgerStatus(resLedger);
      } catch (e) {
        console.error("Failed to load alerts:", e);
      } finally {
        if (active) {
          setLoading(false);
          setIsRefreshing(false);
        }
      }
    };
    load();
    const iv = setInterval(load, 5000);
    return () => {
      active = false;
      clearInterval(iv);
    };
  }, []);

  // Compute live category and severity counts from current alerts in memory
  const counts = useMemo(() => {
    const c = {
      total: alerts.length,
      unack: 0,
      ack: 0,
      mitigated: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      recon: 0,
      initial: 0,
      lateral: 0,
      c2: 0,
      exfil: 0,
    };
    alerts.forEach((a) => {
      if (a.mitigated) c.mitigated++;
      if (a.acknowledged) c.ack++;
      else c.unack++;
      const sev = (a.severity || "").toLowerCase();
      if (sev === "critical") c.critical++;
      else if (sev === "high") c.high++;
      else if (sev === "medium") c.medium++;
      else if (sev === "low") c.low++;

      const stg = (a.predicted_stage || "").toLowerCase();
      if (stg.includes("recon")) c.recon++;
      else if (stg.includes("initial")) c.initial++;
      else if (stg.includes("lateral")) c.lateral++;
      else if (stg.includes("c2")) c.c2++;
      else if (stg.includes("exfil")) c.exfil++;
    });
    return c;
  }, [alerts]);

  const handleClearAll = async () => {
    if (!window.confirm("Purge all incident alerts from database?")) return;
    try {
      await apiPost("/alerts/clear", {});
      setAlerts([]);
      fetchLedgerStatus();
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  };

  const handleResetFilters = () => {
    setSeverityFilter("all");
    setStatusFilter("all");
    setStageFilter("all");
    setSearchQuery("");
  };

  // Instant zero-latency responsive filtering in memory
  const filteredAlerts = useMemo(() => {
    let list = alerts;
    if (severityFilter !== "all") {
      list = list.filter(
        (a) =>
          (a.severity || "").toLowerCase() === severityFilter.toLowerCase(),
      );
    }
    if (statusFilter === "unack") {
      list = list.filter((a) => !a.acknowledged && !a.mitigated);
    } else if (statusFilter === "ack") {
      list = list.filter((a) => a.acknowledged);
    } else if (statusFilter === "mitigated") {
      list = list.filter((a) => a.mitigated);
    }
    if (stageFilter !== "all") {
      list = list.filter((a) =>
        (a.predicted_stage || "")
          .toLowerCase()
          .includes(stageFilter.toLowerCase()),
      );
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (a) =>
          (a.session_key && a.session_key.toLowerCase().includes(q)) ||
          (a.predicted_stage && a.predicted_stage.toLowerCase().includes(q)) ||
          (a.recommended_action &&
            a.recommended_action.toLowerCase().includes(q)) ||
          (a.severity && a.severity.toLowerCase().includes(q)) ||
          (a.block_hash && a.block_hash.toLowerCase().includes(q)),
      );
    }
    return list;
  }, [alerts, severityFilter, statusFilter, stageFilter, searchQuery]);

  const parseSessionKey = (key) => {
    if (!key) return { src: "unknown", dst: "unknown" };
    const [ips] = key.split("@");
    const [src, dst] = (ips || "").split("->");
    return { src: src || "unknown", dst: dst || "unknown" };
  };

  // ---------------------------------------------------------
  // Option B: Proactive Mitigation Actions
  // ---------------------------------------------------------
  const handleContainThreat = async (alertItem) => {
    setContainmentLoading(true);
    try {
      const res = await apiPost(`/alerts/${alertItem.id}/contain`, {});
      // Update in local state immediately
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === alertItem.id
            ? {
                ...a,
                mitigated: true,
                mitigation_action: res.action,
                mitigation_rule: res.rule_command,
                mitigated_at: res.mitigated_at,
                acknowledged: true,
              }
            : a,
        ),
      );
      // Open rule modal
      setSelectedRuleAlert({
        ...alertItem,
        mitigated: true,
        mitigation_action: res.action,
        mitigation_rule: res.rule_command,
        mitigated_at: res.mitigated_at,
      });
      fetchLedgerStatus();
    } catch (e) {
      alert(e.message || "Failed to enforce proactive containment");
    } finally {
      setContainmentLoading(false);
    }
  };

  const handleRevokeContainment = async (alertId) => {
    if (!window.confirm("Revoke this proactive containment rule? Traffic will be re-allowed.")) return;
    try {
      await apiPost(`/alerts/${alertId}/revoke`, {});
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === alertId
            ? { ...a, mitigated: false, mitigated_at: null }
            : a,
        ),
      );
      if (selectedRuleAlert && selectedRuleAlert.id === alertId) {
        setSelectedRuleAlert(null);
      }
      if (activeRulesModalOpen) {
        loadActiveRules();
      }
    } catch (e) {
      alert(e.message || "Failed to revoke containment");
    }
  };

  const loadActiveRules = async () => {
    try {
      const rules = await apiFetch("/alerts/containment/rules");
      setActiveRules(Array.isArray(rules) ? rules : []);
      setActiveRulesModalOpen(true);
    } catch (e) {
      console.error("Failed to load active rules:", e);
    }
  };

  // ---------------------------------------------------------
  // Option C: Blockchain Immutable Audit Ledger Actions
  // ---------------------------------------------------------
  const handleVerifyLedgerLive = async () => {
    setVerifyingLedger(true);
    try {
      const res = await apiFetch("/alerts/ledger/verify");
      setLedgerStatus(res);
      setTamperSimulated(false);
    } catch (e) {
      console.error("Verification failed:", e);
    } finally {
      setTimeout(() => setVerifyingLedger(false), 500);
    }
  };

  const handleOpenLedgerModal = async () => {
    try {
      const [blocks, status] = await Promise.all([
        apiFetch("/alerts/ledger/blocks?limit=100"),
        apiFetch("/alerts/ledger/verify"),
      ]);
      setLedgerBlocks(Array.isArray(blocks) ? blocks : []);
      setLedgerStatus(status);
      setTamperSimulated(false);
      setLedgerModalOpen(true);
    } catch (e) {
      console.error("Failed to open ledger modal:", e);
    }
  };

  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    if (type === "hash") {
      setCopiedHash(text);
      setTimeout(() => setCopiedHash(null), 2000);
    } else {
      setCopiedRuleType(type);
      setTimeout(() => setCopiedRuleType(null), 2000);
    }
  };

  // Extract Linux & Windows commands from generated rule
  const extractCommands = (ruleStr) => {
    if (!ruleStr) return { iptables: "", defender: "" };
    const parts = ruleStr.split("||");
    return {
      iptables: (parts[0] || "").trim(),
      defender: (parts[1] || "").trim(),
    };
  };

  return (
    <div className="alerts-container">
      {/* Overview Metric Cards Bar */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "var(--sp-3)",
          marginBottom: "var(--sp-4)",
        }}
      >
        <div className="card" style={{ padding: "12px 16px" }}>
          <div className="stat-card-label">TOTAL INCIDENTS</div>
          <div
            className="stat-card-value mono"
            style={{ fontSize: "1.6rem", color: "var(--text-primary)" }}
          >
            {counts.total}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            Sealed in Blockchain Ledger
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div
            className="stat-card-label"
            style={{
              color: counts.unack > 0 ? "var(--c-red)" : "var(--severity-low)",
              display: "flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            {counts.unack > 0 && (
              <span
                className="live-pulse-blip"
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--c-red)",
                }}
              />
            )}
            PENDING REVIEW
          </div>
          <div
            className="stat-card-value mono"
            style={{
              fontSize: "1.6rem",
              color: counts.unack > 0 ? "var(--c-red)" : "var(--severity-low)",
            }}
          >
            {counts.unack}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            {counts.unack > 0
              ? "Actionable incidents requiring acknowledgment"
              : "Perimeter nominal — all clear"}
          </div>
        </div>

        {/* Option B: Mitigated / Contained KPI Card */}
        <div className="card" style={{ padding: "12px 16px", borderColor: counts.mitigated > 0 ? "rgba(88, 166, 104, 0.4)" : undefined }}>
          <div
            className="stat-card-label"
            style={{
              color: "var(--severity-low)",
              display: "flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            <ShieldCheck size={13} color="var(--severity-low)" />
            PROACTIVE CONTAINED
          </div>
          <div
            className="stat-card-value mono"
            style={{
              fontSize: "1.6rem",
              color: "var(--severity-low)",
            }}
          >
            {counts.mitigated}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            Host isolation rules enforced
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div className="stat-card-label" style={{ color: "var(--c-red)" }}>
            CRITICAL SEVERITY
          </div>
          <div
            className="stat-card-value mono"
            style={{
              fontSize: "1.6rem",
              color: counts.critical > 0 ? "var(--c-red)" : "var(--text-muted)",
            }}
          >
            {counts.critical}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            High-urgency breach indicators
          </div>
        </div>

        <div className="card" style={{ padding: "12px 16px" }}>
          <div className="stat-card-label" style={{ color: "var(--c-gold)" }}>
            HIGH SEVERITY
          </div>
          <div
            className="stat-card-value mono"
            style={{
              fontSize: "1.6rem",
              color: counts.high > 0 ? "var(--c-gold)" : "var(--text-muted)",
            }}
          >
            {counts.high}
          </div>
          <div className="stat-card-sub" style={{ fontSize: "0.72rem" }}>
            Elevated threat signatures
          </div>
        </div>
      </div>

      {/* Option C: Blockchain Immutable Audit Ledger Status Banner */}
      <div className="blockchain-status-banner">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: "var(--radius-sm)",
              background: "rgba(214, 179, 106, 0.15)",
              border: "1px solid rgba(214, 179, 106, 0.35)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Lock size={18} color="var(--c-gold)" />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span
                style={{
                  fontFamily: "var(--font-mono)",
                  fontWeight: 700,
                  fontSize: "0.82rem",
                  color: "var(--text-primary)",
                  letterSpacing: "0.04em",
                }}
              >
                BLOCKCHAIN IMMUTABLE AUDIT LEDGER
              </span>
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                  fontSize: "0.68rem",
                  fontWeight: 700,
                  fontFamily: "var(--font-mono)",
                  background:
                    ledgerStatus?.chain_intact && !tamperSimulated
                      ? "rgba(88, 166, 104, 0.18)"
                      : "rgba(201, 74, 69, 0.2)",
                  color:
                    ledgerStatus?.chain_intact && !tamperSimulated
                      ? "var(--severity-low)"
                      : "var(--c-red)",
                  padding: "2px 7px",
                  borderRadius: "var(--radius-sm)",
                  border: `1px solid ${
                    ledgerStatus?.chain_intact && !tamperSimulated
                      ? "rgba(88, 166, 104, 0.4)"
                      : "rgba(201, 74, 69, 0.5)"
                  }`,
                }}
              >
                {ledgerStatus?.chain_intact && !tamperSimulated ? (
                  <>
                    <CheckCircle2 size={10} /> CRYPTOGRAPHICALLY INTACT (SHA-256)
                  </>
                ) : (
                  <>
                    <AlertTriangle size={10} /> TAMPER DETECTED
                  </>
                )}
              </span>
            </div>
            <div
              style={{
                fontSize: "0.72rem",
                color: "var(--text-secondary)",
                marginTop: 2,
                fontFamily: "var(--font-mono)",
              }}
            >
              NTRO PS:26153 Forensic Evidentiary Standard &bull; Total Blocks:{" "}
              <strong style={{ color: "var(--text-primary)" }}>
                {ledgerStatus?.total_blocks ?? counts.total}
              </strong>{" "}
              &bull; Head Hash:{" "}
              <span className="mono" style={{ color: "var(--c-gold)" }}>
                {ledgerStatus?.head_hash
                  ? `${ledgerStatus.head_hash.substring(0, 14)}...`
                  : "000000000000..."}
              </span>
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            className="btn btn-sm btn-outline"
            onClick={handleVerifyLedgerLive}
            disabled={verifyingLedger}
            title="Recalculate SHA-256 forward hash sequence across all database alerts"
            style={{
              fontSize: "0.7rem",
              padding: "4px 10px",
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            <RotateCcw
              size={11}
              className={verifyingLedger ? "spin-animation" : ""}
            />
            {verifyingLedger ? "VERIFYING..." : "VERIFY CHAIN"}
          </button>
          <button
            className="btn btn-sm btn-primary"
            onClick={handleOpenLedgerModal}
            title="Inspect block chain details and forensic proofs"
            style={{
              fontSize: "0.7rem",
              padding: "4px 12px",
              fontWeight: 700,
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
            }}
          >
            <Layers size={12} /> INSPECT LEDGER
          </button>
        </div>
      </div>

      {/* Main Filter & Action Controls Bar */}
      <div
        className="card"
        style={{
          padding: "14px 16px",
          marginBottom: "var(--sp-4)",
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 10,
          }}
        >
          {/* Instant Search Box */}
          <div style={{ position: "relative", minWidth: 260, flex: 1 }}>
            <Search
              size={13}
              style={{
                position: "absolute",
                left: 10,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--text-muted)",
              }}
            />
            <input
              type="text"
              placeholder="Search target IP, MITRE stage, playbook action, severity, or block hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                background: "var(--c-dark-base)",
                border: "1px solid var(--border-dark)",
                borderRadius: "var(--radius-sm)",
                padding: "6px 10px 6px 30px",
                color: "var(--text-primary)",
                fontFamily: "var(--font-mono)",
                fontSize: "0.76rem",
                outline: "none",
              }}
            />
          </div>

          {/* Action Toolbar */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            {/* View Enforced Rules button */}
            <button
              className="btn btn-sm btn-outline"
              onClick={loadActiveRules}
              title="View all currently enforced firewall containment rules"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                borderColor: counts.mitigated > 0 ? "rgba(88, 166, 104, 0.4)" : undefined,
                color: counts.mitigated > 0 ? "var(--severity-low)" : undefined,
              }}
            >
              <ShieldCheck size={12} />
              ACTIVE FIREWALL RULES ({counts.mitigated})
            </button>

            <button
              className="btn btn-sm btn-outline"
              onClick={refresh}
              disabled={isRefreshing}
              title="Force reload latest alerts from backend"
              style={{ display: "inline-flex", alignItems: "center", gap: 5 }}
            >
              <RotateCcw
                size={11}
                className={isRefreshing ? "spin-animation" : ""}
              />
              REFRESH
            </button>

            {counts.total > 0 && (
              <button
                className="btn btn-sm btn-outline"
                onClick={handleClearAll}
                title="Clear all alerts from database"
                style={{ display: "inline-flex", alignItems: "center", gap: 5 }}
              >
                <Trash2 size={11} />
                CLEAR ALL
              </button>
            )}
          </div>
        </div>

        {/* Severity & Status & Stage Filter Buttons */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
            flexWrap: "wrap",
            paddingTop: 8,
            borderTop: "1px solid var(--border-dark)",
            fontSize: "0.74rem",
          }}
        >
          {/* Status Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                color: "var(--text-muted)",
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
              }}
            >
              STATUS:
            </span>
            <div className="tab-group" style={{ margin: 0 }}>
              {[
                { id: "all", label: "ALL", count: counts.total },
                {
                  id: "unack",
                  label: "PENDING",
                  count: counts.unack,
                  highlight: counts.unack > 0,
                },
                {
                  id: "mitigated",
                  label: "CONTAINED",
                  count: counts.mitigated,
                  color: "var(--severity-low)",
                },
                { id: "ack", label: "ACKNOWLEDGED", count: counts.ack },
              ].map((f) => (
                <button
                  key={f.id}
                  className={`tab-btn ${statusFilter === f.id ? "active" : ""}`}
                  onClick={() => setStatusFilter(f.id)}
                  style={{
                    padding: "3px 9px",
                    fontSize: "0.72rem",
                    color:
                      f.color && statusFilter !== f.id
                        ? f.color
                        : f.highlight && statusFilter !== f.id
                          ? "var(--c-red)"
                          : undefined,
                  }}
                >
                  {f.label} ({f.count})
                </button>
              ))}
            </div>
          </div>

          {/* Severity Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                color: "var(--text-muted)",
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
              }}
            >
              SEVERITY:
            </span>
            <div className="tab-group" style={{ margin: 0 }}>
              {[
                { id: "all", label: "ALL", count: counts.total },
                {
                  id: "critical",
                  label: "CRITICAL",
                  color: "var(--c-red)",
                  count: counts.critical,
                },
                {
                  id: "high",
                  label: "HIGH",
                  color: "#E67E22",
                  count: counts.high,
                },
                {
                  id: "medium",
                  label: "MEDIUM",
                  color: "var(--c-gold)",
                  count: counts.medium,
                },
                {
                  id: "low",
                  label: "LOW",
                  color: "var(--severity-low)",
                  count: counts.low,
                },
              ].map((f) => (
                <button
                  key={f.id}
                  className={`tab-btn ${severityFilter === f.id ? "active" : ""}`}
                  onClick={() => setSeverityFilter(f.id)}
                  style={{
                    padding: "3px 9px",
                    fontSize: "0.72rem",
                    color:
                      f.color && severityFilter !== f.id ? f.color : undefined,
                  }}
                >
                  {f.label} ({f.count})
                </button>
              ))}
            </div>
          </div>

          {/* MITRE Stage Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              style={{
                color: "var(--text-muted)",
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
              }}
            >
              STAGE:
            </span>
            <div className="tab-group" style={{ margin: 0 }}>
              {[
                { id: "all", label: "ALL" },
                { id: "recon", label: `RECON (${counts.recon})` },
                { id: "initial", label: `INITIAL (${counts.initial})` },
                { id: "lateral", label: `LATERAL (${counts.lateral})` },
                { id: "c2", label: `C2 (${counts.c2})` },
                { id: "exfil", label: `EXFIL (${counts.exfil})` },
              ].map((f) => (
                <button
                  key={f.id}
                  className={`tab-btn ${stageFilter === f.id ? "active" : ""}`}
                  onClick={() => setStageFilter(f.id)}
                  style={{ padding: "3px 9px", fontSize: "0.72rem" }}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          {/* Clear Filters Reset */}
          {(severityFilter !== "all" ||
            statusFilter !== "all" ||
            stageFilter !== "all" ||
            searchQuery.trim()) && (
            <button
              className="btn btn-sm btn-outline"
              onClick={handleResetFilters}
              style={{
                padding: "2px 8px",
                fontSize: "0.68rem",
                color: "var(--c-gold)",
                borderColor: "rgba(214, 179, 106, 0.4)",
              }}
            >
              RESET FILTERS
            </button>
          )}
        </div>
      </div>

      {/* Incidents Table Wrap */}
      <div className="data-table-wrap">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            <p
              style={{
                marginTop: 12,
                fontFamily: "var(--font-mono)",
                fontSize: "0.85rem",
              }}
            >
              Loading security incident telemetry...
            </p>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon-shield">
              <Shield size={32} color="var(--severity-low)" strokeWidth={2.2} />
            </div>
            <div className="empty-title">
              <span
                className="live-pulse-blip"
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: "var(--severity-low)",
                }}
              />
              PERIMETER SECURE &bull; ZERO ACTIVE THREAT BREACHES
            </div>
            <div className="empty-subtitle">
              {alerts.length === 0
                ? "All network ingress and egress telemetry flows are operating within authorized baseline thresholds. No high-risk security incidents or MITRE ATT&CK patterns detected."
                : "No security incident alerts match your active filter settings. Reset filters to inspect all recorded events."}
            </div>
            <div className="empty-actions">
              {(severityFilter !== "all" ||
                statusFilter !== "all" ||
                stageFilter !== "all" ||
                searchQuery.trim()) && (
                <button
                  className="btn btn-sm btn-outline"
                  onClick={handleResetFilters}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                  }}
                >
                  <RotateCcw size={11} /> RESET ACTIVE FILTERS
                </button>
              )}
            </div>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: "95px" }}>Severity</th>
                <th style={{ minWidth: "200px" }}>Session / Host Endpoint</th>
                <th style={{ width: "150px" }}>MITRE ATT&CK Stage</th>
                <th style={{ width: "115px" }}>Infiltration Risk</th>
                <th>Recommended Mitigation Playbook</th>
                <th style={{ width: "130px" }}>Incident Time</th>
                <th style={{ width: "180px", textAlign: "right" }}>Proactive Defense Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((a) => {
                const { src, dst } = parseSessionKey(a.session_key);
                const sev = (a.severity || "medium").toLowerCase();
                const prob = a.infiltration_prob || 0.0;
                const isHighRisk = prob >= 0.5;

                return (
                  <tr
                    key={a.id}
                    style={{
                      cursor: "default",
                      background: a.mitigated
                        ? "rgba(88, 166, 104, 0.04)"
                        : a.acknowledged
                          ? undefined
                          : "rgba(201, 74, 69, 0.03)",
                    }}
                  >
                    {/* Severity */}
                    <td>
                      <span className={`severity-badge ${sev}`}>
                        {sev.toUpperCase()}
                      </span>
                    </td>

                    {/* Session Host Endpoints with Straight Column Symmetry */}
                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          fontFamily: "var(--font-mono)",
                          fontSize: "0.78rem",
                        }}
                      >
                        <span className="ip-symmetric-cell">
                          <span className="ip-digits">{src}</span>
                          <IdentityBadge ip={src} />
                        </span>
                        <ArrowRight
                          size={11}
                          color="var(--c-gold)"
                          style={{ flexShrink: 0 }}
                        />
                        <span className="ip-symmetric-cell">
                          <span className="ip-digits">{dst}</span>
                          <IdentityBadge ip={dst} />
                        </span>
                      </div>
                    </td>

                    {/* MITRE Stage with Radar Blip */}
                    <td>
                      <span
                        className={`stage-badge ${stageClass(a.predicted_stage)}`}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 5,
                        }}
                      >
                        {!a.acknowledged && !a.mitigated && (
                          <span
                            className="live-pulse-blip"
                            style={{
                              width: 6,
                              height: 6,
                              borderRadius: "50%",
                              background: "currentColor",
                            }}
                          />
                        )}
                        {a.predicted_stage || "General Threat"}
                      </span>
                    </td>

                    {/* Infiltration Risk */}
                    <td>
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 3,
                        }}
                      >
                        <span
                          className="mono"
                          style={{
                            fontWeight: 700,
                            color: isHighRisk
                              ? "var(--c-red)"
                              : "var(--c-gold)",
                            fontSize: "0.82rem",
                          }}
                        >
                          {formatProb(prob)}
                        </span>
                        <div
                          style={{
                            width: "100%",
                            height: 3,
                            background: "rgba(255, 255, 255, 0.08)",
                            borderRadius: 2,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${Math.min(100, Math.max(0, prob * 100))}%`,
                              height: "100%",
                              background: isHighRisk
                                ? "var(--c-red)"
                                : "var(--c-gold)",
                            }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Recommended Mitigation Playbook */}
                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "flex-start",
                          gap: 6,
                        }}
                      >
                        <AlertTriangle
                          size={13}
                          color={a.mitigated ? "var(--severity-low)" : "var(--c-gold)"}
                          style={{ marginTop: 2, flexShrink: 0 }}
                        />
                        <span
                          className="alert-action"
                          style={{ fontSize: "0.76rem", lineHeight: 1.35 }}
                        >
                          {a.recommended_action ||
                            "Inspect flow signature, check firewall logs, and isolate host."}
                        </span>
                      </div>
                    </td>

                    {/* Incident Time */}
                    <td
                      className="mono text-sm"
                      style={{
                        color: "var(--text-muted)",
                        fontSize: "0.74rem",
                      }}
                    >
                      {formatTime(a.created_at)}
                    </td>

                    {/* Status & Option B Proactive Action Buttons */}
                    <td style={{ textAlign: "right" }}>
                      <div
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          justifyContent: "flex-end",
                        }}
                      >
                        {a.mitigated ? (
                          <>
                            <span
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 4,
                                color: "var(--severity-low)",
                                fontSize: "0.72rem",
                                fontWeight: 700,
                                background: "rgba(88, 166, 104, 0.12)",
                                padding: "3px 7px",
                                borderRadius: "var(--radius-sm)",
                                border: "1px solid rgba(88, 166, 104, 0.35)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              <ShieldCheck size={11} /> MITIGATED
                            </span>
                            <button
                              className="proactive-btn proactive-btn-mitigated"
                              onClick={() => setSelectedRuleAlert(a)}
                              title="Inspect enforced firewall rule commands"
                            >
                              <Terminal size={11} /> RULE
                            </button>
                          </>
                        ) : (
                          <>
                            <span
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 4,
                                color: a.acknowledged ? "var(--text-muted)" : "var(--c-red)",
                                fontSize: "0.7rem",
                                fontWeight: 700,
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {a.acknowledged ? "Triaged" : "Active"}
                            </span>
                            <button
                              className="proactive-btn proactive-btn-contain"
                              onClick={() => handleContainThreat(a)}
                              disabled={containmentLoading}
                              title="Proactively generate firewall isolation rules to neutralize attacker progression"
                            >
                              <Shield size={11} /> CONTAIN
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* ================================================================= */}
      {/* Option B: Containment Rule Modal (Firewall Rule Inspection)       */}
      {/* ================================================================= */}
      {selectedRuleAlert && (
        <div className="modal-overlay" onClick={() => setSelectedRuleAlert(null)}>
          <div className="garud-modal" onClick={(e) => e.stopPropagation()}>
            <div className="garud-modal-header">
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <ShieldCheck size={18} color="var(--severity-low)" />
                <span style={{ fontWeight: 700, fontSize: "0.92rem", color: "var(--text-primary)" }}>
                  PROACTIVE THREAT CONTAINMENT RULE &bull; INCIDENT #{selectedRuleAlert.id}
                </span>
              </div>
              <button
                className="btn btn-sm btn-outline"
                onClick={() => setSelectedRuleAlert(null)}
                aria-label="Close modal"
              >
                <X size={14} /> Close
              </button>
            </div>

            <div className="garud-modal-body">
              {/* Alert Details Strip */}
              <div
                style={{
                  background: "var(--c-dark-base)",
                  border: "1px solid var(--border-dark)",
                  borderRadius: "var(--radius-sm)",
                  padding: "10px 14px",
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
                  gap: 12,
                  fontSize: "0.76rem",
                }}
              >
                <div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>FORECASTED ATTACK STAGE</div>
                  <div style={{ fontWeight: 700, color: "var(--c-gold)", marginTop: 2 }}>
                    {selectedRuleAlert.predicted_stage}
                  </div>
                </div>
                <div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>INFILTRATION PROBABILITY</div>
                  <div style={{ fontWeight: 700, color: "var(--c-red)", marginTop: 2 }}>
                    {formatProb(selectedRuleAlert.infiltration_prob || 0)}
                  </div>
                </div>
                <div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>TARGET SESSION ENDPOINT</div>
                  <div className="mono" style={{ color: "var(--text-primary)", marginTop: 2, fontSize: "0.72rem" }}>
                    {selectedRuleAlert.session_key}
                  </div>
                </div>
                <div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>ENFORCEMENT STATUS</div>
                  <div style={{ color: "var(--severity-low)", fontWeight: 700, marginTop: 2 }}>
                    ACTIVE &bull; ENFORCED
                  </div>
                </div>
              </div>

              {/* Rationale description */}
              <div style={{ fontSize: "0.76rem", color: "var(--text-secondary)", lineHeight: 1.4 }}>
                <strong>SIH 2026 PS:26153 Proactive Defense Protocol:</strong> Based on the LSTM World Model's multi-stage attack trajectory forecast, this target endpoint is preemptively isolated before escalating to unauthorized lateral movement or C2 exfiltration.
              </div>

              {/* Linux iptables command */}
              <div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 6,
                  }}
                >
                  <span style={{ fontSize: "0.74rem", fontWeight: 700, color: "var(--text-primary)", display: "flex", alignItems: "center", gap: 5 }}>
                    <Terminal size={12} color="var(--c-gold)" /> LINUX GATEWAY ENFORCEMENT (iptables)
                  </span>
                  <button
                    className="btn btn-sm btn-outline"
                    onClick={() =>
                      copyToClipboard(
                        extractCommands(selectedRuleAlert.mitigation_rule).iptables,
                        "iptables",
                      )
                    }
                    style={{ fontSize: "0.68rem", padding: "2px 8px", display: "inline-flex", alignItems: "center", gap: 4 }}
                  >
                    {copiedRuleType === "iptables" ? (
                      <>
                        <Check size={11} color="var(--severity-low)" /> COPIED!
                      </>
                    ) : (
                      <>
                        <Copy size={11} /> COPY COMMAND
                      </>
                    )}
                  </button>
                </div>
                <div className="containment-code-block">
                  <code>
                    {extractCommands(selectedRuleAlert.mitigation_rule).iptables ||
                      "iptables -I FORWARD -j DROP"}
                  </code>
                </div>
              </div>

              {/* Windows Defender Firewall command */}
              <div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 6,
                  }}
                >
                  <span style={{ fontSize: "0.74rem", fontWeight: 700, color: "var(--text-primary)", display: "flex", alignItems: "center", gap: 5 }}>
                    <Terminal size={12} color="var(--c-gold)" /> WINDOWS DEFENDER HOST FIREWALL (PowerShell)
                  </span>
                  <button
                    className="btn btn-sm btn-outline"
                    onClick={() =>
                      copyToClipboard(
                        extractCommands(selectedRuleAlert.mitigation_rule).defender,
                        "defender",
                      )
                    }
                    style={{ fontSize: "0.68rem", padding: "2px 8px", display: "inline-flex", alignItems: "center", gap: 4 }}
                  >
                    {copiedRuleType === "defender" ? (
                      <>
                        <Check size={11} color="var(--severity-low)" /> COPIED!
                      </>
                    ) : (
                      <>
                        <Copy size={11} /> COPY COMMAND
                      </>
                    )}
                  </button>
                </div>
                <div className="containment-code-block">
                  <code>
                    {extractCommands(selectedRuleAlert.mitigation_rule).defender ||
                      "New-NetFirewallRule -Action Block"}
                  </code>
                </div>
              </div>
            </div>

            <div className="garud-modal-footer">
              <button
                className="btn btn-sm btn-outline"
                style={{ color: "var(--c-red)", borderColor: "rgba(201, 74, 69, 0.4)" }}
                onClick={() => handleRevokeContainment(selectedRuleAlert.id)}
              >
                REVOKE CONTAINMENT
              </button>
              <button
                className="btn btn-sm btn-primary"
                onClick={() => setSelectedRuleAlert(null)}
              >
                ACKNOWLEDGE & CLOSE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ================================================================= */}
      {/* Option B: Active Rules Drawer Modal                               */}
      {/* ================================================================= */}
      {activeRulesModalOpen && (
        <div className="modal-overlay" onClick={() => setActiveRulesModalOpen(false)}>
          <div className="garud-modal modal-lg" onClick={(e) => e.stopPropagation()}>
            <div className="garud-modal-header">
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <ShieldCheck size={18} color="var(--severity-low)" />
                <span style={{ fontWeight: 700, fontSize: "0.92rem", color: "var(--text-primary)" }}>
                  ACTIVE FIREWALL CONTAINMENT RULES &bull; PERIMETER ENFORCEMENT
                </span>
              </div>
              <button
                className="btn btn-sm btn-outline"
                onClick={() => setActiveRulesModalOpen(false)}
              >
                <X size={14} /> Close
              </button>
            </div>

            <div className="garud-modal-body">
              {activeRules.length === 0 ? (
                <div className="empty-state">
                  <Shield size={32} color="var(--severity-low)" />
                  <div className="empty-title" style={{ marginTop: 10 }}>ZERO FIREWALL BLOCKS ACTIVE</div>
                  <div className="empty-subtitle">
                    All network nodes are currently operating in unrestricted authorized baseline routing.
                  </div>
                </div>
              ) : (
                <table className="data-table" style={{ fontSize: "0.72rem" }}>
                  <thead>
                    <tr>
                      <th>Alert</th>
                      <th>Target Endpoint</th>
                      <th>MITRE Stage</th>
                      <th>Enforced Firewall Command</th>
                      <th>Enforced At</th>
                      <th style={{ textAlign: "right" }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeRules.map((r) => (
                      <tr key={r.alert_id}>
                        <td className="mono" style={{ fontWeight: 700 }}>
                          #{r.alert_id}
                        </td>
                        <td className="mono">{r.session_key}</td>
                        <td>
                          <span className={`stage-badge ${stageClass(r.predicted_stage)}`}>
                            {r.predicted_stage}
                          </span>
                        </td>
                        <td>
                          <code style={{ fontSize: "0.65rem", color: "#a8d5ba" }}>
                            {extractCommands(r.rule_command).iptables || r.rule_command}
                          </code>
                        </td>
                        <td className="mono text-muted">
                          {r.enforced_at ? formatTime(r.enforced_at) : "Active"}
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <button
                            className="btn btn-sm btn-outline"
                            style={{ fontSize: "0.65rem", padding: "2px 6px", color: "var(--c-red)" }}
                            onClick={() => handleRevokeContainment(r.alert_id)}
                          >
                            REVOKE
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            <div className="garud-modal-footer">
              <button
                className="btn btn-sm btn-outline"
                onClick={() => setActiveRulesModalOpen(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ================================================================= */}
      {/* Option C: Blockchain Immutable Audit Ledger Explorer Modal        */}
      {/* ================================================================= */}
      {ledgerModalOpen && (
        <div className="modal-overlay" onClick={() => setLedgerModalOpen(false)}>
          <div className="garud-modal modal-lg" onClick={(e) => e.stopPropagation()}>
            <div className="garud-modal-header">
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Lock size={18} color="var(--c-gold)" />
                <div>
                  <span style={{ fontWeight: 700, fontSize: "0.92rem", color: "var(--text-primary)" }}>
                    BLOCKCHAIN AUDIT LEDGER EXPLORER &bull; SHA-256 HASH CHAIN
                  </span>
                  <span style={{ display: "block", fontSize: "0.68rem", color: "var(--c-gold)", fontWeight: 600 }}>
                    NTRO PS:26153 &bull; Cryptographic Anti-Tamper Chain-of-Custody
                  </span>
                </div>
              </div>
              <button
                className="btn btn-sm btn-outline"
                onClick={() => setLedgerModalOpen(false)}
              >
                <X size={14} /> Close
              </button>
            </div>

            <div className="garud-modal-body">
              {/* Summary Stats Row */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: 12,
                }}
              >
                <div className="card" style={{ padding: "10px 14px", background: "var(--c-dark-base)" }}>
                  <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>CHAIN INTEGRITY STATUS</div>
                  <div
                    style={{
                      fontSize: "0.95rem",
                      fontWeight: 700,
                      color:
                        ledgerStatus?.chain_intact && !tamperSimulated
                          ? "var(--severity-low)"
                          : "var(--c-red)",
                      marginTop: 4,
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                    }}
                  >
                    {ledgerStatus?.chain_intact && !tamperSimulated ? (
                      <>
                        <CheckCircle2 size={14} /> 100% VALID &bull; UNBROKEN
                      </>
                    ) : (
                      <>
                        <AlertTriangle size={14} /> TAMPER DETECTED
                      </>
                    )}
                  </div>
                </div>

                <div className="card" style={{ padding: "10px 14px", background: "var(--c-dark-base)" }}>
                  <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>TOTAL SEALED BLOCKS</div>
                  <div className="mono" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                    {ledgerStatus?.total_blocks || ledgerBlocks.length}
                  </div>
                </div>

                <div className="card" style={{ padding: "10px 14px", background: "var(--c-dark-base)" }}>
                  <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>GENESIS BLOCK HASH</div>
                  <div
                    className="mono"
                    style={{ fontSize: "0.72rem", color: "var(--c-gold)", marginTop: 6, wordBreak: "break-all" }}
                  >
                    {ledgerStatus?.genesis_hash
                      ? `${ledgerStatus.genesis_hash.substring(0, 16)}...`
                      : "0000000000000000..."}
                  </div>
                </div>

                <div className="card" style={{ padding: "10px 14px", background: "var(--c-dark-base)" }}>
                  <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>LATEST HEAD HASH</div>
                  <div
                    className="mono"
                    style={{ fontSize: "0.72rem", color: "var(--c-gold)", marginTop: 6, wordBreak: "break-all" }}
                  >
                    {ledgerStatus?.head_hash
                      ? `${ledgerStatus.head_hash.substring(0, 16)}...`
                      : "0000000000000000..."}
                  </div>
                </div>
              </div>

              {/* Explanatory Callout */}
              <div
                style={{
                  background: "rgba(214, 179, 106, 0.06)",
                  border: "1px solid rgba(214, 179, 106, 0.2)",
                  borderRadius: "var(--radius-sm)",
                  padding: "10px 14px",
                  fontSize: "0.74rem",
                  color: "var(--text-secondary)",
                  lineHeight: 1.4,
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 10,
                }}
              >
                <Lock size={16} color="var(--c-gold)" style={{ flexShrink: 0, marginTop: 2 }} />
                <div>
                  <strong>How Garud Anti-Tamper Ledger Works:</strong> Every security alert generated by the forecasting model is hashed using SHA-256 with the previous block's digest:
                  <div className="mono" style={{ color: "var(--c-gold)", marginTop: 4 }}>
                    H<sub>i</sub> = SHA256(SessionKey || Severity || RiskScore || MITREStage || Timestamp || H<sub>i-1</sub>)
                  </div>
                  This guarantees that no adversary, rogue insider, or malicious actor can alter historical incident logs without invalidating every subsequent block in the chain.
                </div>
              </div>

              {/* Block Chain Cards Sequence */}
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {ledgerBlocks.map((b, idx) => (
                  <div key={b.block_id}>
                    <div className="blockchain-block-card">
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span
                            style={{
                              background: "rgba(214, 179, 106, 0.2)",
                              color: "var(--c-gold)",
                              padding: "2px 7px",
                              borderRadius: "var(--radius-sm)",
                              fontFamily: "var(--font-mono)",
                              fontWeight: 700,
                              fontSize: "0.74rem",
                            }}
                          >
                            BLOCK #{b.block_id}
                          </span>
                          <span className={`stage-badge ${stageClass(b.predicted_stage)}`}>
                            {b.predicted_stage}
                          </span>
                          {b.mitigated && (
                            <span
                              style={{
                                color: "var(--severity-low)",
                                fontSize: "0.68rem",
                                fontWeight: 700,
                                fontFamily: "var(--font-mono)",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 4,
                              }}
                            >
                              <ShieldCheck size={11} /> CONTAINED
                            </span>
                          )}
                        </div>
                        <span className="mono text-muted" style={{ fontSize: "0.7rem" }}>
                          {b.created_at ? formatTime(b.created_at) : "Genesis"}
                        </span>
                      </div>

                      <div style={{ fontSize: "0.74rem", fontFamily: "var(--font-mono)" }}>
                        <span style={{ color: "var(--text-muted)" }}>Target Session:</span>{" "}
                        <span style={{ color: "var(--text-primary)" }}>{b.session_key}</span>
                      </div>

                      {/* Cryptographic Linkage Info */}
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "1fr 1fr",
                          gap: 10,
                          fontSize: "0.7rem",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        <div>
                          <div style={{ color: "var(--text-muted)", marginBottom: 3 }}>
                            PREVIOUS HASH (H<sub>i-1</sub>):
                          </div>
                          <div className="blockchain-hash-pill" style={{ width: "100%" }}>
                            <Link size={10} color="var(--c-gold)" />
                            <span>{b.prev_hash || "0000000000000000000000000000000000000000000000000000000000000000"}</span>
                          </div>
                        </div>

                        <div>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                            <span style={{ color: "var(--text-muted)" }}>
                              BLOCK HASH (H<sub>i</sub>):
                            </span>
                            <button
                              onClick={() => copyToClipboard(b.block_hash, "hash")}
                              style={{
                                background: "none",
                                border: "none",
                                color: "var(--c-gold)",
                                cursor: "pointer",
                                fontSize: "0.65rem",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 3,
                              }}
                            >
                              {copiedHash === b.block_hash ? (
                                <>
                                  <Check size={9} color="var(--severity-low)" /> Copied
                                </>
                              ) : (
                                <>
                                  <Copy size={9} /> Copy
                                </>
                              )}
                            </button>
                          </div>
                          <div className="blockchain-hash-pill" style={{ width: "100%", borderColor: "rgba(88, 166, 104, 0.3)" }}>
                            <CheckCircle2 size={10} color="var(--severity-low)" />
                            <span>{b.block_hash}</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Chain link icon between blocks */}
                    {idx < ledgerBlocks.length - 1 && (
                      <div className="blockchain-link-arrow">
                        <Link size={14} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="garud-modal-footer" style={{ justifyContent: "space-between" }}>
              <button
                className="btn btn-sm btn-outline"
                style={{
                  color: tamperSimulated ? "var(--severity-low)" : "var(--c-red)",
                  borderColor: tamperSimulated ? "rgba(88, 166, 104, 0.4)" : "rgba(201, 74, 69, 0.4)",
                  fontSize: "0.72rem",
                }}
                onClick={() => setTamperSimulated(!tamperSimulated)}
              >
                {tamperSimulated ? "RESET TAMPER SIMULATION" : "SIMULATE DATABASE TAMPER ATTACK"}
              </button>

              <button
                className="btn btn-sm btn-primary"
                onClick={() => setLedgerModalOpen(false)}
              >
                CLOSE AUDIT EXPLORER
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export { AlertPanel as AlertsView };
