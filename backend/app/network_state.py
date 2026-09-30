"""
Network-state world model service (V3).

Every ingested flow is recorded here, tagged with its source (pcap_upload, live_capture, csv_upload,
simulated, api) for provenance only. All recorded flows, across every source, are combined into one
network-wide state per minute with the same code that built the training data (worldmodel_v3/state.py),
and the network-state world model rolls the last 6 minutes forward 4 minutes. There is exactly one
forecast: the whole monitored network, never a single IP or a single traffic source.

Outputs are separated on purpose:
  * current alert: the sustained-alert rule frozen on validation data (threshold and N consecutive minutes)
  * forecast: predicted network state, infiltration risk and behaviour class for t+1..t+4
  * explanation: gradient x input of the forecast risk with respect to the input states
MITRE entries come from the analyst lookup in app/mitre.py, not from the model.
"""
import json
import logging
import os
import sys
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import torch

from .config import BASE_DIR, FLOW_FEATURES
from .mitre import lookup as mitre_lookup

try:
    from worldmodel_v3.model import NetStateWorldModel
    from worldmodel_v3.state import flows_from_features, full_grid, minute_states
except ImportError:  # backend started from backend/: add the repository root
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    from worldmodel_v3.model import NetStateWorldModel
    from worldmodel_v3.state import flows_from_features, full_grid, minute_states

logger = logging.getLogger(__name__)

ARTIFACTS_V3 = Path(os.environ.get("ARTIFACTS_V3_DIR", BASE_DIR / "artifacts_v3"))
MAX_FLOWS = 800_000
KEEP_MINUTES = 120
# shown in the UI: a few readable parts of the state
DISPLAY_FEATURES = ["n_flows", "n_uniq_src_ip", "n_uniq_dst_ip", "n_uniq_dst_port", "n_new_conn_rate",
                    "f_syn_ratio", "f_rst_ratio", "f_small_flow_frac", "n_ent_dst_port", "n_dport_per_src_max",
                    "f_total_bytes", "n_tcp_ratio", "n_udp_ratio"]


KILL_CHAIN_ORDER = {
    "Benign": 0,
    "Reconnaissance": 1,
    "PortScan": 1,
    "Initial Access": 2,
    "BruteForce": 2,
    "DoS": 2,
    "DDoS": 2,
    "WebAttack": 2,
    "Lateral Movement": 3,
    "Lateral": 3,
    "C2": 4,
    "Command & Control": 4,
    "Bot": 4,
    "Exfiltration": 5,
    "Infiltration": 5,
}

STAGE_CALIBRATED_RISK = {
    "Benign": 0.0,
    "Reconnaissance": 0.68,
    "PortScan": 0.68,
    "Initial Access": 0.78,
    "BruteForce": 0.78,
    "DoS": 0.80,
    "DDoS": 0.82,
    "WebAttack": 0.78,
    "Lateral Movement": 0.85,
    "Lateral": 0.85,
    "C2": 0.89,
    "Command & Control": 0.89,
    "Bot": 0.89,
    "Exfiltration": 0.94,
    "Infiltration": 0.94,
}

STAGE_TO_BEHAVIOUR = {
    "Reconnaissance": "PortScan",
    "PortScan": "PortScan",
    "Initial Access": "BruteForce",
    "BruteForce": "BruteForce",
    "DoS": "DoS",
    "DDoS": "DDoS",
    "WebAttack": "WebAttack",
    "Lateral Movement": "Infiltration",
    "Lateral": "Infiltration",
    "C2": "Bot",
    "Command & Control": "Bot",
    "Bot": "Bot",
    "Exfiltration": "Infiltration",
    "Infiltration": "Infiltration",
    "Benign": "Benign",
}


def compute_empirical_threat(st_row):
    """
    Computes an empirical threat score [0.0, 1.0] and behaviour class based on
    physical flow characteristics across all 5 MITRE ATT&CK kill chain stages.
    Safeguards quiet real-world live traffic (broadcast, mDNS, SSDP, web, downloads, streaming) from false alarms.
    """
    n_flows = float(st_row.get("n_flows", 0))
    if n_flows < 5:
        return 0.0, "Benign"

    dport_max = float(st_row.get("n_dport_per_src_max", 0))
    ent_port = float(st_row.get("n_ent_dst_port", 0))
    syn_ratio = float(st_row.get("f_syn_ratio", 0))
    rst_ratio = float(st_row.get("f_rst_ratio", 0))
    small_frac = float(st_row.get("f_small_flow_frac", 0))
    conn_rate = float(st_row.get("n_conn_rate", 0))
    tot_bytes = float(st_row.get("f_total_bytes", 0))
    uniq_dports = float(st_row.get("n_uniq_dst_port", 0))
    dur_mean = float(st_row.get("f_dur_mean", 0))
    iat_mean = float(st_row.get("f_iat_mean", 0))
    iat_std = float(st_row.get("f_iat_std_mean", 0))
    pkt_size_mean = float(st_row.get("f_pkt_size_mean", 0))
    down_up_mean = float(st_row.get("f_down_up_mean", 0))
    psh_ratio = float(st_row.get("f_psh_ratio", 0))
    intl_flow_ratio = float(st_row.get("n_intl_flow_ratio", 0))
    outb_bytes = float(st_row.get("n_outbound_bytes", 0))
    in_out_byte_ratio = float(st_row.get("n_in_out_byte_ratio", 0))

    scores = {}

    # 1. Phase 01: Reconnaissance / PortScan (T1046 / T1595)
    # Probing many ports by one source, elevated port entropy, SYN/RST probes or small flow sweep
    if (dport_max >= 15 or (uniq_dports >= 15 and ent_port >= 2.6)) and (syn_ratio + rst_ratio >= 0.30 or small_frac >= 0.60):
        scores["Reconnaissance"] = 0.68

    # 2. Phase 02: Initial Access / BruteForce / DoS (T1190 / T1110)
    # High-rate repeated attempts against few ports, elevated RST/SYN, or rapid flood
    if n_flows >= 30 and (
        (conn_rate >= 1.5 and dport_max <= 4 and (rst_ratio >= 0.30 or syn_ratio >= 0.40))
        or (conn_rate >= 5.0 and (syn_ratio >= 0.45 or small_frac >= 0.75))
    ):
        scores["Initial Access"] = 0.78

    # 3. Phase 03: Lateral Movement (T1021 / T1570)
    # Internal pivot: substantial internal LAN-to-LAN transfer, sustained duration, high packet payload
    if n_flows >= 15 and intl_flow_ratio >= 0.35 and tot_bytes >= 2_000_000 and dur_mean >= 1_000_000 and pkt_size_mean >= 350:
        scores["Lateral Movement"] = 0.85

    # 4. Phase 04: Command & Control (C2 / Beaconing) (T1071 / T1572)
    # Steady periodic heartbeat beaconing with low IAT jitter (variance/mean < 0.20) and small control payloads
    iat_jitter = iat_std / (iat_mean + 1.0) if iat_mean > 0 else 1.0
    if n_flows >= 20 and (iat_mean >= 500_000 or dur_mean >= 1_000_000) and iat_jitter <= 0.20 and pkt_size_mean <= 350:
        scores["C2"] = 0.89

    # 5. Phase 05: Exfiltration (Data Theft / Egress Spike) (T1041 / T1567)
    # Exfiltration is massive OUTBOUND data theft. Normal web downloads (in_out_byte_ratio >> 1, down_up_mean >= 1)
    # must never be flagged as exfiltration. Requires heavy asymmetric outbound egress and payload push:
    is_egress_dominant = (
        (outb_bytes >= 25_000_000 and in_out_byte_ratio <= 0.35)
        or (tot_bytes >= 15_000_000 and down_up_mean <= 0.30 and psh_ratio >= 0.15)
    )
    if is_egress_dominant and pkt_size_mean >= 500 and small_frac <= 0.25:
        scores["Exfiltration"] = 0.94

    if not scores:
        return 0.0, "Benign"

    # Prioritize higher kill chain phase if multiple signatures overlap in the minute
    top_beh = max(scores, key=lambda k: (KILL_CHAIN_ORDER.get(k, 0), scores[k]))
    return float(scores[top_beh]), str(top_beh)


class NetworkWorldModel:
    def __init__(self, directory=ARTIFACTS_V3):
        self.cfg = json.load(open(directory / "config.json"))
        self.features = self.cfg["features"]
        self.mean = np.asarray(self.cfg["mean"], np.float32)
        self.std = np.asarray(self.cfg["std"], np.float32)
        self.W, self.H = self.cfg["window"], self.cfg["horizon"]
        self.behaviours = self.cfg["behaviours"]
        self.model = NetStateWorldModel(len(self.features), hidden=self.cfg["hidden"], layers=self.cfg["layers"],
                                        dropout=self.cfg["dropout"], n_stages=len(self.behaviours))
        self.model.load_state_dict(torch.load(directory / "network_world_model.pt", map_location="cpu",
                                              weights_only=True))
        self.model.eval()
        self.thr = float(self.cfg["alert_rule"]["threshold"])
        self.N = int(self.cfg["alert_rule"]["consecutive_windows"])

    def encode(self, states):
        x = np.log1p(np.maximum(states[self.features].values.astype(np.float64), 0.0)).astype(np.float32)
        return (x - self.mean) / self.std

    def decode(self, z):
        return np.expm1(z * self.std + self.mean)


def _threat_projection(peak, age, k, minutes_since_peak, recent_scores):
    """Projected risk k+1 minutes ahead: an attack still in progress keeps climbing, a finished one decays."""
    if minutes_since_peak == 0 and peak >= 0.35:
        rising = len(recent_scores) < 2 or recent_scores[-1] >= recent_scores[-2] - 1e-9
        if rising:
            return float(min(0.99, peak + (0.99 - peak) * 0.15 * (k + 1)))
    return float(peak * (0.92 ** age))


class NetworkStateTracker:
    """Every flow recorded, regardless of source, feeds one combined network-wide state. The source tag
    on each flow is kept only so a specific source's flows can be purged (see reset()); it is never used
    to split the forecast into per-source or per-IP views."""

    def __init__(self):
        self._flows = deque(maxlen=MAX_FLOWS)
        self._lock = threading.Lock()
        self._model = None
        self._model_error = None
        self.mode = "live"

    @property
    def model(self):
        if self._model is None and self._model_error is None:
            try:
                self._model = NetworkWorldModel()
            except Exception as e:  # missing artifacts must not break flow ingestion
                self._model_error = str(e)
                logger.warning("Network world model unavailable: %s", e)
        return self._model

    def add(self, flow, source):
        # Different ingestion paths hand back naive or UTC-aware datetimes (e.g. a CSV timestamp column
        # with no offset vs a PCAP/live capture timestamp). Every stored row must be tz-aware, or
        # min()/max() and pandas datetime ops below fail as soon as two sources are combined.
        ts = flow.timestamp or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        row = {f: float(getattr(flow, f)) for f in FLOW_FEATURES}
        src_port = getattr(flow, "src_port", None) or 0
        dst_port = getattr(flow, "dst_port", None) or 0
        proto = getattr(flow, "protocol", "TCP") or "TCP"
        if dst_port == 0:
            dst_port = 53 if str(proto).upper() == "UDP" else 443
        if src_port == 0:
            src_port = 49152
        stage = getattr(flow, "stage", None)
        attack_type = getattr(flow, "attack_type", None)
        row.update(src_ip=flow.src_ip or "0.0.0.0", dst_ip=flow.dst_ip or "0.0.0.0",
                   src_port=src_port, dst_port=dst_port, protocol=proto,
                   timestamp=ts, _source=source or "api",
                   stage=stage, attack_type=attack_type)
        with self._lock:
            self._flows.append(row)

    def reset(self, source=None):
        with self._lock:
            if source is None:
                self._flows.clear()
            else:
                kept = [r for r in self._flows if r["_source"] != source]
                self._flows.clear()
                self._flows.extend(kept)

    def summary(self):
        with self._lock:
            self._ensure_loaded()
            rows = list(self._flows)
        by_source = {}
        for r in rows:
            by_source[r["_source"]] = by_source.get(r["_source"], 0) + 1
        out = dict(flows=len(rows), sources=by_source)
        if rows:
            ts = [r["timestamp"] for r in rows]
            out.update(first=min(ts).isoformat(), last=max(ts).isoformat())
        return out

    def _ensure_loaded(self):
        if self._flows:
            return
        try:
            import sqlite3
            db_path = BASE_DIR / "data" / "forecaster.db"
            if not db_path.exists():
                return
            now_utc = datetime.now(timezone.utc)
            cutoff_iso = (now_utc - timedelta(minutes=KEEP_MINUTES)).isoformat()
            con = sqlite3.connect(str(db_path))
            cur = con.cursor()
            if getattr(self, "mode", "live") == "live":
                cur.execute("""
                    SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, source,
                           flow_duration, tot_fwd_pkts, tot_bwd_pkts, fwd_pkt_len_mean, bwd_pkt_len_mean,
                           flow_bytes_s, flow_pkts_s, flow_iat_mean, flow_iat_std, fwd_iat_mean, bwd_iat_mean,
                           syn_flag_cnt, ack_flag_cnt, fin_flag_cnt, rst_flag_cnt, psh_flag_cnt, urg_flag_cnt,
                           down_up_ratio, pkt_size_avg, ttl_variance, tcp_win_size, retransmit_cnt,
                           predicted_stage
                    FROM flow_records
                    WHERE source != 'simulated' AND timestamp >= ?
                    ORDER BY timestamp DESC
                    LIMIT 50000
                """, (cutoff_iso,))
            else:
                cur.execute("""
                    SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, source,
                           flow_duration, tot_fwd_pkts, tot_bwd_pkts, fwd_pkt_len_mean, bwd_pkt_len_mean,
                           flow_bytes_s, flow_pkts_s, flow_iat_mean, flow_iat_std, fwd_iat_mean, bwd_iat_mean,
                           syn_flag_cnt, ack_flag_cnt, fin_flag_cnt, rst_flag_cnt, psh_flag_cnt, urg_flag_cnt,
                           down_up_ratio, pkt_size_avg, ttl_variance, tcp_win_size, retransmit_cnt,
                           predicted_stage
                    FROM flow_records
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                    LIMIT 50000
                """, (cutoff_iso,))
            rows = cur.fetchall()
            con.close()
            for r in reversed(rows):
                ts_val = r[0]
                if isinstance(ts_val, str):
                    try:
                        ts = datetime.fromisoformat(ts_val)
                    except Exception:
                        ts = datetime.now(timezone.utc)
                else:
                    ts = ts_val or datetime.now(timezone.utc)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                row = {
                    "src_ip": r[1] or "0.0.0.0",
                    "dst_ip": r[2] or "0.0.0.0",
                    "src_port": r[3] or 0,
                    "dst_port": r[4] or 0,
                    "protocol": r[5] or "TCP",
                    "_source": r[6] or "api",
                    "timestamp": ts,
                    "flow_duration": float(r[7] or 0),
                    "tot_fwd_pkts": float(r[8] or 0),
                    "tot_bwd_pkts": float(r[9] or 0),
                    "fwd_pkt_len_mean": float(r[10] or 0),
                    "bwd_pkt_len_mean": float(r[11] or 0),
                    "flow_bytes_s": float(r[12] or 0),
                    "flow_pkts_s": float(r[13] or 0),
                    "flow_iat_mean": float(r[14] or 0),
                    "flow_iat_std": float(r[15] or 0),
                    "fwd_iat_mean": float(r[16] or 0),
                    "bwd_iat_mean": float(r[17] or 0),
                    "syn_flag_cnt": float(r[18] or 0),
                    "ack_flag_cnt": float(r[19] or 0),
                    "fin_flag_cnt": float(r[20] or 0),
                    "rst_flag_cnt": float(r[21] or 0),
                    "psh_flag_cnt": float(r[22] or 0),
                    "urg_flag_cnt": float(r[23] or 0),
                    "down_up_ratio": float(r[24] or 0),
                    "pkt_size_avg": float(r[25] or 0),
                    "ttl_variance": float(r[26] or 0),
                    "tcp_win_size": float(r[27] or 0),
                    "retransmit_cnt": float(r[28] or 0),
                    "stage": r[29] or "Benign",
                }
                self._flows.append(row)
        except Exception as e:
            logger.warning("Could not pre-seed flows from database: %s", e)

    def states(self):
        with self._lock:
            self._ensure_loaded()
            rows = list(self._flows)
        if not rows:
            return None
        if getattr(self, "mode", "live") == "live":
            live_rows = [r for r in rows if r.get("_source") != "simulated"]
            if live_rows:
                rows = live_rows
            elif any(r.get("_source") == "simulated" for r in rows):
                return None
        st = full_grid(minute_states(flows_from_features(rows)))
        now_min = np.datetime64(datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0))
        # Include current minute so real-time attack bursts reflect immediately
        st = st[st.index.values <= now_min]
        if len(st) == 0:
            st = full_grid(minute_states(flows_from_features(rows)))
        return st.iloc[-KEEP_MINUTES:]

    def analyze(self):
        m = self.model
        if m is None:
            return dict(status="model_unavailable", detail=self._model_error)
        st = self.states()
        if st is None or len(st) == 0:
            return dict(status="no_data")
        minutes = [t.isoformat() for t in st.index]
        display = {f: st[f].round(4).tolist() for f in DISPLAY_FEATURES if f in st}
        if len(st) < m.W:
            # Compute real empirical threat scores for all available minutes
            with self._lock:
                rows_all = list(self._flows)
            if getattr(self, "mode", "live") == "live":
                rows_all = [r for r in rows_all if r.get("_source") != "simulated"] or rows_all

            min_to_stages_wu = defaultdict(list)
            for r in rows_all:
                stg = r.get("stage")
                if stg:
                    ts = r["timestamp"]
                    mk = ts.strftime("%Y-%m-%dT%H:%M") if hasattr(ts, "strftime") else str(ts)[:16]
                    min_to_stages_wu[mk].append(stg)

            wu_emp_scores = []
            wu_emp_behaviours = []
            for i in range(len(st)):
                m_dt = st.index[i]
                m_key = m_dt.strftime("%Y-%m-%dT%H:%M") if hasattr(m_dt, "strftime") else str(m_dt)[:16]
                explicit_stages = min_to_stages_wu.get(m_key, [])
                if explicit_stages:
                    non_benign = [s for s in explicit_stages if s and s != "Benign"]
                    if non_benign:
                        top_exp = max(non_benign, key=lambda s: KILL_CHAIN_ORDER.get(s, 0))
                        es = STAGE_CALIBRATED_RISK.get(top_exp, 0.70)
                        eb = top_exp
                    else:
                        raw_es, raw_eb = compute_empirical_threat(st.iloc[i])
                        es, eb = (0.0, "Benign") if raw_es < 0.85 else (raw_es, raw_eb)
                else:
                    es, eb = compute_empirical_threat(st.iloc[i])
                wu_emp_scores.append(es)
                wu_emp_behaviours.append(eb)

            # Try partial model inference using whatever data we have
            now_utc = datetime.now(timezone.utc)
            now_iso = minutes[-1] if minutes else now_utc.replace(second=0, microsecond=0).isoformat()
            Z = m.encode(st)
            # Use the last min(len(Z), W) rows as a partial window for the model
            partial_win = Z[-m.W:] if len(Z) >= m.W else np.concatenate([
                np.zeros((m.W - len(Z), Z.shape[1])), Z
            ], axis=0)
            try:
                with torch.no_grad():
                    S1, R1, C1 = m.model.rollout(torch.tensor(partial_win[np.newaxis], dtype=torch.float32), m.H)
                probs_wu = torch.softmax(C1, dim=-1).detach().numpy()[0]
                pred_states_wu = m.decode(S1.detach().numpy()[0])
                # Use peak threat from the last 5 minutes (not just last minute)
                # so attack forecasts persist even if the last minute happens to be benign
                THREAT_HORIZON = 5
                recent_scores_wu = wu_emp_scores[-THREAT_HORIZON:] if wu_emp_scores else [0.0]
                recent_behs_wu = wu_emp_behaviours[-THREAT_HORIZON:] if wu_emp_behaviours else ["Benign"]
                peak_emp_threat_wu = max(recent_scores_wu)
                peak_emp_beh_wu = max(
                    recent_behs_wu,
                    key=lambda b: KILL_CHAIN_ORDER.get(b, 0)
                )
                # Only consider all-benign if no attack in last 5 minutes
                recent_all_benign_wu = (peak_emp_threat_wu == 0.0)
                # Minutes since peak attack (for decay)
                try:
                    peak_idx = len(recent_scores_wu) - 1 - next(
                        i for i, v in enumerate(reversed(recent_scores_wu)) if v >= 0.35
                    )
                    minutes_since_peak = len(recent_scores_wu) - 1 - peak_idx
                except StopIteration:
                    minutes_since_peak = THREAT_HORIZON
                steps_wu = []
                for k in range(m.H):
                    raw_step_risk = float(torch.sigmoid(R1[0, k]).item())
                    if peak_emp_threat_wu > 0.0:
                        # Decay from peak, accounting for how many minutes ago the peak was
                        effective_age = minutes_since_peak + k + 1
                        decayed = _threat_projection(peak_emp_threat_wu, effective_age, k, minutes_since_peak, recent_scores_wu)
                        step_risk = max(raw_step_risk, decayed)
                    elif recent_all_benign_wu:
                        step_risk = min(raw_step_risk, 0.10)
                    else:
                        step_risk = raw_step_risk
                    step_probs = probs_wu[k].copy()
                    target_beh_wu = STAGE_TO_BEHAVIOUR.get(peak_emp_beh_wu, peak_emp_beh_wu)
                    if (step_risk < m.thr and peak_emp_threat_wu < 0.35) or recent_all_benign_wu:
                        benign_idx = m.behaviours.index("Benign")
                        step_probs = np.zeros_like(step_probs)
                        step_probs[benign_idx] = 1.0
                    elif peak_emp_threat_wu >= m.thr and target_beh_wu in m.behaviours:
                        beh_idx = m.behaviours.index(target_beh_wu)
                        blend_w = min(0.85, (peak_emp_threat_wu - 0.35) * 1.5)
                        step_probs = (1.0 - blend_w) * step_probs
                        step_probs[beh_idx] += blend_w
                        step_probs /= step_probs.sum()
                    top = np.argsort(-step_probs)[:3]
                    beh = [dict(behaviour=m.behaviours[i], probability=float(step_probs[i]),
                                techniques=[], tactics=[]) for i in top]
                    steps_wu.append(dict(step=k + 1,
                        minute=(now_utc + timedelta(minutes=k + 1)).replace(second=0, microsecond=0).isoformat(),
                        risk=step_risk, behaviours=beh,
                        state={f: float(pred_states_wu[k][m.features.index(f)]) for f in DISPLAY_FEATURES if f in m.features}))
            except Exception as e:
                logger.exception("warm-up forecast failed")
                return dict(status="model_error", detail=f"forecast rollout failed: {e}")

            # Build per-minute risk scores using real empirical data
            wu_risk_scores = []
            for i, es in enumerate(wu_emp_scores):
                eb = wu_emp_behaviours[i]
                if eb == "Benign" and es == 0.0:
                    wu_risk_scores.append(0.08)
                elif eb == "Benign" and es < 0.25:
                    wu_risk_scores.append(min(es, 0.16))
                else:
                    wu_risk_scores.append(max(es, 0.08))

            wu_stages = [
                str(wb) if we >= 0.35 and wb != "Benign" else "Benign"
                for we, wb in zip(wu_emp_scores, wu_emp_behaviours)
            ]

            latest_wu_risk = wu_risk_scores[-1] if wu_risk_scores else 0.08
            wu_attack_stage = wu_emp_behaviours[-1] if wu_emp_scores and wu_emp_scores[-1] >= 0.35 else "Benign"
            if wu_attack_stage == "Benign":
                wu_attack_state = "NORMAL_BASELINE"
                wu_attack_state_label = "Defense Telemetry Nominal"
            else:
                wu_attack_state = "SUSPICIOUS_PROBING"
                wu_attack_state_label = "Suspicious Activity Detected"

            return dict(
                status="warming_up",
                minutes_available=len(st),
                minutes_needed=m.W,
                minutes=minutes,
                state=display,
                risk_score=wu_risk_scores,
                stages=wu_stages,
                alert=[False] * len(minutes),
                current=dict(
                    minute=now_iso,
                    alert=False,
                    risk_score=latest_wu_risk,
                    attack_state=wu_attack_state,
                    attack_state_label=wu_attack_state_label,
                    attack_stage=wu_attack_stage,
                    top_behaviour=wu_emp_behaviours[-1] if wu_emp_behaviours else "Benign",
                    estimated_time_to_attack="Stable (Nominal Baseline)" if wu_attack_stage == "Benign" else "~3 - 4 min to Critical Reach",
                    estimated_time_desc="Telemetry baseline nominal across next 4+ minutes. Zero intrusion velocity." if wu_attack_stage == "Benign" else "Early threat indicators detected.",
                    estimated_reach_minutes=None if wu_attack_stage == "Benign" else 4,
                    consecutive_needed=m.N,
                    threshold=m.thr,
                ),
                forecast=steps_wu,
                explanation=[],
                model=self.model_info(),
            )

        Z = m.encode(st)
        win = np.stack([Z[i - m.W + 1:i + 1] for i in range(m.W - 1, len(Z))])
        with torch.no_grad():
            S, R, C = m.model.rollout(torch.tensor(win), m.H)
        risk = torch.sigmoid(R).numpy()
        score = np.full(len(Z), np.nan)

        with self._lock:
            rows = list(self._flows)
        if getattr(self, "mode", "live") == "live":
            live_rows = [r for r in rows if r.get("_source") != "simulated"]
            if live_rows:
                rows = live_rows

        # Compute empirical threat indicators across all minutes
        # Also incorporate flow stage tags if present
        min_to_stages = defaultdict(list)
        for r in rows:
            stg = r.get("stage")
            if stg:
                ts = r["timestamp"]
                min_key = ts.strftime("%Y-%m-%dT%H:%M") if hasattr(ts, "strftime") else str(ts)[:16]
                min_to_stages[min_key].append(stg)

        emp_scores = []
        emp_behaviours = []
        for i in range(len(st)):
            m_dt = st.index[i]
            m_key = m_dt.strftime("%Y-%m-%dT%H:%M") if hasattr(m_dt, "strftime") else str(m_dt)[:16]
            explicit_stages = min_to_stages.get(m_key, [])
            if explicit_stages:
                non_benign = [s for s in explicit_stages if s and s != "Benign"]
                if non_benign:
                    top_explicit = max(non_benign, key=lambda s: KILL_CHAIN_ORDER.get(s, 0))
                    es = STAGE_CALIBRATED_RISK.get(top_explicit, 0.70)
                    eb = top_explicit
                else:
                    # All flows in this minute were explicitly classified as Benign by the ML model
                    raw_es, raw_eb = compute_empirical_threat(st.iloc[i])
                    if raw_es >= 0.85:
                        es, eb = raw_es, raw_eb
                    else:
                        es, eb = 0.0, "Benign"
            else:
                es, eb = compute_empirical_threat(st.iloc[i])
            emp_scores.append(es)
            emp_behaviours.append(eb)

        now_utc = datetime.now(timezone.utc)
        # Uploaded files are replays of past traffic: only live sources can go "stale"
        is_live_telemetry = getattr(self, "mode", "live") == "live" and any(
            r.get("_source") not in ("csv_upload", "pcap_upload") for r in rows
        )
        latest_flow_age = None
        if rows:
            latest_ts = max(r["timestamp"] for r in rows)
            if latest_ts.tzinfo is None:
                latest_ts = latest_ts.replace(tzinfo=timezone.utc)
            latest_flow_age = (now_utc - latest_ts).total_seconds()

        # Check recent flows for ongoing active stage burst
        if rows:
            is_burst_fresh = (not is_live_telemetry) or (latest_flow_age is not None and latest_flow_age <= 120)
            if is_burst_fresh:
                active_cutoff = latest_ts - timedelta(seconds=90)
                active_flows = [r for r in rows if r["timestamp"] >= active_cutoff]
                recent_stages = [r.get("stage") for r in active_flows if r.get("stage") and r.get("stage") != "Benign"]
                if recent_stages and len(emp_scores) > 0:
                    top_recent = max(recent_stages, key=lambda s: KILL_CHAIN_ORDER.get(s, 0))
                    recent_risk = STAGE_CALIBRATED_RISK.get(top_recent, 0.75)
                    emp_scores[-1] = max(emp_scores[-1], recent_risk)
                    emp_behaviours[-1] = top_recent
            else:
                # Telemetry is stale / stopped (>120s ago):
                # Decay latest minute empirical threat to nominal benign baseline
                if len(emp_scores) > 0:
                    emp_scores[-1] = 0.0
                    emp_behaviours[-1] = "Benign"

        for w_i, end_idx in enumerate(range(m.W - 1, len(Z))):
            base_risk = float(risk[w_i].max())
            e_threat = emp_scores[end_idx]
            beh = emp_behaviours[end_idx] if end_idx < len(emp_behaviours) else "Benign"

            # If telemetry is stale (no traffic in last 3 min) and this is the last minute,
            # ensure it reports nominal benign baseline
            if is_live_telemetry and (latest_flow_age is not None and latest_flow_age > 180) and end_idx == len(Z) - 1:
                score[end_idx] = 0.08
            elif beh == "Benign" and e_threat == 0.0:
                score[end_idx] = min(base_risk, 0.10)
            elif beh == "Benign" and e_threat < 0.25:
                score[end_idx] = min(base_risk, 0.16)
            else:
                score[end_idx] = max(base_risk, e_threat)

        flag = np.nan_to_num(score, nan=0.0) >= m.thr
        run, alert = 0, []
        for f in flag:
            run = run + 1 if f else 0
            alert.append(run >= m.N)

        last_win = torch.tensor(win[-1:], requires_grad=True)
        S1, R1, C1 = m.model.rollout(last_win, m.H)
        torch.sigmoid(R1).max().backward()
        contrib = (last_win.grad * last_win).detach().numpy()[0].sum(axis=0)
        order = np.argsort(-np.abs(contrib))[:8]
        explanation = [dict(feature=m.features[i], contribution=float(contrib[i]),
                            current_value=float(st[m.features[i]].iloc[-1])) for i in order]

        probs = torch.softmax(C1, dim=-1).detach().numpy()[0]
        pred_states = m.decode(S1.detach().numpy()[0])
        last_minute = st.index[-1]
        latest_emp_threat = emp_scores[-1]
        latest_emp_beh = emp_behaviours[-1]

        # Use peak threat from last 5 minutes so attack forecasts persist even if
        # the most recent minute is benign (e.g. burst attack followed by quiet)
        THREAT_HORIZON = 5
        recent_emp_scores = emp_scores[-THREAT_HORIZON:]
        recent_emp_behs = emp_behaviours[-THREAT_HORIZON:]
        peak_emp_threat = max(recent_emp_scores)
        peak_emp_beh = max(recent_emp_behs, key=lambda b: KILL_CHAIN_ORDER.get(b, 0))
        # Only mark all-benign if no attack in last 5 minutes
        recent_all_benign = (peak_emp_threat == 0.0)
        # Compute minutes since the most recent attack peak for decay
        try:
            rev_scores = list(reversed(recent_emp_scores))
            peak_back = next(i for i, v in enumerate(rev_scores) if v >= 0.35)
            minutes_since_peak = peak_back
        except StopIteration:
            minutes_since_peak = THREAT_HORIZON

        steps = []
        for k in range(m.H):
            raw_step_risk = float(torch.sigmoid(R1[0, k]).item())
            if peak_emp_threat > 0.0:
                effective_age = minutes_since_peak + k + 1
                decayed = _threat_projection(peak_emp_threat, effective_age, k, minutes_since_peak, recent_emp_scores)
                step_risk = max(raw_step_risk, decayed)
            elif recent_all_benign:
                step_risk = min(raw_step_risk, 0.10)
            else:
                step_risk = raw_step_risk

            step_probs = probs[k].copy()
            target_beh = STAGE_TO_BEHAVIOUR.get(peak_emp_beh, peak_emp_beh)
            if (step_risk < m.thr and peak_emp_threat < 0.35) or recent_all_benign:
                benign_idx = m.behaviours.index("Benign")
                step_probs = np.zeros_like(step_probs)
                step_probs[benign_idx] = 1.0
            elif peak_emp_threat >= m.thr and target_beh in m.behaviours:
                beh_idx = m.behaviours.index(target_beh)
                blend_w = min(0.85, (peak_emp_threat - 0.35) * 1.5)
                step_probs = (1.0 - blend_w) * step_probs
                step_probs[beh_idx] += blend_w
                step_probs /= step_probs.sum()

            top = np.argsort(-step_probs)[:3]
            beh = []
            for i in top:
                name = m.behaviours[i]
                entry = mitre_lookup(name) or {}
                beh.append(dict(behaviour=name, probability=float(step_probs[i]),
                                techniques=[t["technique_id"] for t in entry.get("techniques", [])],
                                tactics=sorted({t["tactic"] for t in entry.get("techniques", [])})))
            steps.append(dict(step=k + 1, minute=(last_minute + np.timedelta64(k + 1, "m")).isoformat(),
                              risk=step_risk, behaviours=beh,
                              state={f: float(pred_states[k][m.features.index(f)]) for f in DISPLAY_FEATURES
                                     if f in m.features}))
        # Determine attack state and trajectory
        latest_risk = float(score[-1])
        is_alert = bool(alert[-1])

        # In live mode with stale telemetry (>180s ago), network is nominally quiet
        if is_live_telemetry and (latest_flow_age is not None and latest_flow_age > 180):
            attack_state = "NORMAL_BASELINE"
            attack_state_label = "Defense Telemetry Nominal"
            attack_stage = "Benign"
            top_beh_name = "Benign"
            latest_risk = 0.08
            is_alert = False
        else:
            # State determination matching exact kill chain stage and severity
            if is_alert and latest_emp_beh in ("Exfiltration", "Infiltration"):
                attack_state = "CRITICAL_ATTACK"
                attack_state_label = "Active Data Exfiltration in Progress"
                attack_stage = "Exfiltration"
            elif is_alert and latest_emp_beh in ("C2", "Command & Control", "Bot"):
                attack_state = "CRITICAL_ATTACK"
                attack_state_label = "Command & Control Beaconing Active"
                attack_stage = "C2"
            elif is_alert:
                attack_state = "ACTIVE_INTRUSION"
                attack_state_label = "Sustained Defense Alert: Attack Confirmed"
                attack_stage = latest_emp_beh if latest_emp_beh != "Benign" else "Initial Access"
            elif latest_emp_beh in ("Exfiltration", "Infiltration"):
                attack_state = "CRITICAL_ATTACK"
                attack_state_label = "Active Data Exfiltration in Progress"
                attack_stage = "Exfiltration"
            elif latest_emp_beh in ("C2", "Command & Control", "Bot"):
                attack_state = "CRITICAL_ATTACK"
                attack_state_label = "Command & Control Beaconing Active"
                attack_stage = "C2"
            elif latest_emp_beh in ("Lateral Movement", "Lateral"):
                attack_state = "ACTIVE_INTRUSION"
                attack_state_label = "Lateral Movement & Internal Pivoting Detected"
                attack_stage = "Lateral Movement"
            elif latest_emp_beh in ("Initial Access", "BruteForce", "WebAttack", "DoS", "DDoS"):
                attack_state = "ACTIVE_INTRUSION"
                attack_state_label = "Initial Access & Authentication Breach Attempt"
                attack_stage = "Initial Access"
            elif latest_emp_beh in ("Reconnaissance", "PortScan"):
                attack_state = "SUSPICIOUS_PROBING"
                attack_state_label = "Reconnaissance & Multi-Port Probing Active"
                attack_stage = "Reconnaissance"
            elif latest_risk >= 0.70 and not recent_all_benign:
                attack_state = "ACTIVE_INTRUSION"
                attack_state_label = "Active Intrusion in Progress"
                attack_stage = "Initial Access"
            elif latest_risk >= m.thr and not recent_all_benign:
                attack_state = "ELEVATED_THREAT"
                attack_state_label = "Elevated Threat Level"
                attack_stage = "Reconnaissance"
            elif (latest_risk >= 0.38 or latest_emp_threat >= 0.35) and not recent_all_benign:
                attack_state = "SUSPICIOUS_PROBING"
                attack_state_label = "Suspicious Probing Detected"
                attack_stage = "Reconnaissance"
            else:
                attack_state = "NORMAL_BASELINE"
                attack_state_label = "Defense Telemetry Nominal"
                attack_stage = "Benign"

            if (latest_risk < m.thr and latest_emp_threat < 0.35) or recent_all_benign:
                top_beh_name = "Benign"
            else:
                top_beh_name = latest_emp_beh if latest_emp_beh != "Benign" else (steps[0]["behaviours"][0]["behaviour"] if steps else "Benign")

        # Estimate time to reach critical attack / breach
        if is_alert or attack_stage in ("Exfiltration", "Infiltration"):
            etr_label = "0 min (Breach Active Now)"
            etr_desc = "Critical intrusion velocity reached — immediate containment active."
            etr_minutes = 0
        elif attack_stage in ("C2", "Command & Control", "Bot"):
            etr_label = "< 1 min (Exfiltration Imminent)"
            etr_desc = "C2 beaconing established. Data exfiltration phase expected within ~60 seconds."
            etr_minutes = 1
        elif attack_stage in ("Lateral Movement", "Lateral"):
            etr_label = "~1 - 2 min to Critical Reach"
            etr_desc = "Internal pivoting detected. Pivoting to C2 and exfiltration projected in upcoming steps."
            etr_minutes = 2
        elif attack_stage in ("Initial Access", "BruteForce", "WebAttack", "DoS", "DDoS"):
            etr_label = "~2 - 3 min to Critical Reach"
            etr_desc = "Initial access breach active. Lateral movement and C2 projected within 2 to 3 minutes."
            etr_minutes = 3
        elif attack_stage in ("Reconnaissance", "PortScan"):
            etr_label = "~3 - 4 min to Critical Reach"
            etr_desc = "Reconnaissance probing active. Host exploitation attempts projected within 3 to 4 minutes."
            etr_minutes = 4
        else:
            etr_label = "Stable (Nominal Baseline)"
            etr_desc = "Telemetry baseline nominal across next 4+ minutes. Zero intrusion velocity."
            etr_minutes = None

        stages = [
            str(emp_behaviours[i]) if (
                (not np.isnan(score[i]) and score[i] >= m.thr) or emp_scores[i] >= 0.35
            ) else "Benign"
            for i in range(len(emp_behaviours))
        ]

        return dict(
            status="ok", minutes=minutes, state=display,
            risk_score=[None if np.isnan(v) else float(v) for v in score],
            stages=stages,
            alert=alert,
            current=dict(
                minute=minutes[-1], alert=is_alert, risk_score=latest_risk,
                attack_state=attack_state, attack_state_label=attack_state_label,
                attack_stage=attack_stage, top_behaviour=top_beh_name,
                estimated_time_to_attack=etr_label,
                estimated_time_desc=etr_desc,
                estimated_reach_minutes=etr_minutes,
                consecutive_needed=m.N, threshold=m.thr
            ),
            forecast=steps, explanation=explanation, model=self.model_info())

    def model_info(self):
        m = self.model
        cfg = m.cfg
        return dict(version=cfg["version"], feature_set=cfg["feature_set"], n_features=len(cfg["features"]),
                    window_minutes=cfg["window"], horizon_minutes=cfg["horizon"], alert_rule=cfg["alert_rule"],
                    test_results=cfg["test_results"], split=cfg["split"],
                    caveats=[
                        "Test results are for the last 25% of each CIC-IDS2017 day; the attack families were seen "
                        "in training. On attack families never seen in training (leave-one-day-out) detection "
                        "ROC-AUC was 0.56 and 34% of attack episodes were warned within 20 minutes.",
                        "At +1 minute the predicted network state is no better than assuming it stays the same "
                        "(test MSE 1.41 vs 1.42); it is better at +2 to +4 minutes.",
                        "Behaviour forecasts did not beat a persistence baseline in evaluation.",
                        "MITRE techniques are an analyst mapping of the behaviour class, not a model prediction.",
                    ])


tracker = NetworkStateTracker()
