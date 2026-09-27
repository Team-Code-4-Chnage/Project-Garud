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
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

from .config import BASE_DIR, FLOW_FEATURES
from .mitre import lookup as mitre_lookup

try:
    from worldmodel_v2.model import NetStateWorldModel
    from worldmodel_v3.state import flows_from_features, full_grid, minute_states
except ImportError:  # backend started from backend/: add the repository root
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    from worldmodel_v2.model import NetStateWorldModel
    from worldmodel_v3.state import flows_from_features, full_grid, minute_states

logger = logging.getLogger(__name__)

ARTIFACTS_V3 = Path(os.environ.get("ARTIFACTS_V3_DIR", BASE_DIR / "artifacts_v3"))
MAX_FLOWS = 800_000
KEEP_MINUTES = 120
# shown in the UI: a few readable parts of the state
DISPLAY_FEATURES = ["n_flows", "n_uniq_src_ip", "n_uniq_dst_ip", "n_uniq_dst_port", "n_new_conn_rate",
                    "f_syn_ratio", "f_rst_ratio", "f_small_flow_frac", "n_ent_dst_port", "n_dport_per_src_max",
                    "f_total_bytes", "n_tcp_ratio", "n_udp_ratio"]


def compute_empirical_threat(st_row):
    """
    Computes an empirical threat score [0.0, 1.0] and behaviour class based on
    physical flow characteristics in the minute state st_row.
    """
    n_flows = float(st_row.get("n_flows", 0))
    if n_flows < 3:
        return 0.0, "Benign"

    dport_max = float(st_row.get("n_dport_per_src_max", 0))
    ent_port = float(st_row.get("n_ent_dst_port", 0))
    syn_ratio = float(st_row.get("f_syn_ratio", 0))
    rst_ratio = float(st_row.get("f_rst_ratio", 0))
    small_frac = float(st_row.get("f_small_flow_frac", 0))
    conn_rate = float(st_row.get("n_conn_rate", 0))
    tot_bytes = float(st_row.get("f_total_bytes", 0))
    uniq_dports = float(st_row.get("n_uniq_dst_port", 0))

    scores = {}

    # 1. Port Scanning / Reconnaissance
    # Signatures: single host probing many ports, high port entropy, SYN/RST probes, small packets
    if dport_max >= 8 or (uniq_dports >= 10 and ent_port >= 2.5):
        port_score = min(1.0, max(0.0, (dport_max - 4) / 16.0)) * 0.45
        port_score += min(1.0, (syn_ratio + rst_ratio) / 0.4) * 0.35
        port_score += min(1.0, small_frac / 0.7) * 0.20
        scores["PortScan"] = min(0.92, 0.40 + port_score * 0.55)

    # 2. Brute Force / High-frequency Auth Probes
    # Signatures: high connection rate to 1-3 ports, high RST or small flows
    if conn_rate >= 0.5 and dport_max <= 5 and (rst_ratio >= 0.15 or syn_ratio >= 0.25):
        bf_score = min(1.0, conn_rate / 2.0) * 0.45 + min(1.0, (rst_ratio + syn_ratio) / 0.5) * 0.55
        scores["BruteForce"] = min(0.88, 0.40 + bf_score * 0.50)

    # 3. DoS / SYN Flood
    if conn_rate >= 3.0 and syn_ratio >= 0.30:
        dos_score = min(1.0, conn_rate / 10.0) * 0.5 + min(1.0, syn_ratio / 0.5) * 0.5
        scores["DoS"] = min(0.95, 0.50 + dos_score * 0.45)

    # 4. Exfiltration
    if tot_bytes >= 15_000_000 and small_frac <= 0.3:
        exfil_score = min(1.0, tot_bytes / 50_000_000)
        scores["Infiltration"] = min(0.85, 0.45 + exfil_score * 0.40)

    if not scores:
        return 0.0, "Benign"

    top_beh = max(scores, key=scores.get)
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


class NetworkStateTracker:
    """Every flow recorded, regardless of source, feeds one combined network-wide state. The source tag
    on each flow is kept only so a specific source's flows can be purged (see reset()); it is never used
    to split the forecast into per-source or per-IP views."""

    def __init__(self):
        self._flows = deque(maxlen=MAX_FLOWS)
        self._lock = threading.Lock()
        self._model = None
        self._model_error = None

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
        row.update(src_ip=flow.src_ip or "0.0.0.0", dst_ip=flow.dst_ip or "0.0.0.0",
                   src_port=src_port, dst_port=dst_port, protocol=proto,
                   timestamp=ts, _source=source or "api")
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
            con = sqlite3.connect(str(db_path))
            cur = con.cursor()
            cur.execute("""
                SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, source,
                       flow_duration, tot_fwd_pkts, tot_bwd_pkts, fwd_pkt_len_mean, bwd_pkt_len_mean,
                       flow_bytes_s, flow_pkts_s, flow_iat_mean, flow_iat_std, fwd_iat_mean, bwd_iat_mean,
                       syn_flag_cnt, ack_flag_cnt, fin_flag_cnt, rst_flag_cnt, psh_flag_cnt, urg_flag_cnt,
                       down_up_ratio, pkt_size_avg, ttl_variance, tcp_win_size, retransmit_cnt
                FROM flow_records
                ORDER BY timestamp DESC
                LIMIT 50000
            """)
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
            return dict(status="warming_up", minutes_available=len(st), minutes_needed=m.W,
                        minutes=minutes, state=display, model=self.model_info())
        Z = m.encode(st)
        win = np.stack([Z[i - m.W + 1:i + 1] for i in range(m.W - 1, len(Z))])
        with torch.no_grad():
            S, R, C = m.model.rollout(torch.tensor(win), m.H)
        risk = torch.sigmoid(R).numpy()
        score = np.full(len(Z), np.nan)

        # Compute empirical threat indicators across all minutes
        emp_scores = []
        emp_behaviours = []
        for i in range(len(st)):
            es, eb = compute_empirical_threat(st.iloc[i])
            emp_scores.append(es)
            emp_behaviours.append(eb)

        for w_i, end_idx in enumerate(range(m.W - 1, len(Z))):
            base_risk = float(risk[w_i].max())
            e_threat = emp_scores[end_idx]
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

        steps = []
        for k in range(m.H):
            raw_step_risk = float(torch.sigmoid(R1[0, k]).item())
            if latest_emp_threat > 0.0:
                step_risk = max(raw_step_risk, float(latest_emp_threat * (0.95 ** (k + 1))))
            else:
                step_risk = raw_step_risk

            step_probs = probs[k].copy()
            if step_risk < m.thr and latest_emp_threat < 0.35:
                benign_idx = m.behaviours.index("Benign")
                step_probs = np.zeros_like(step_probs)
                step_probs[benign_idx] = 1.0
            elif latest_emp_threat >= m.thr and latest_emp_beh in m.behaviours:
                beh_idx = m.behaviours.index(latest_emp_beh)
                blend_w = min(0.85, (latest_emp_threat - 0.35) * 1.5)
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
        if is_alert:
            attack_state = "CRITICAL_ATTACK"
            attack_state_label = "Sustained Attack Detected"
            attack_stage = latest_emp_beh if latest_emp_beh != "Benign" else "Infiltration"
        elif latest_risk >= 0.70:
            attack_state = "ACTIVE_INTRUSION"
            attack_state_label = "Active Intrusion in Progress"
            attack_stage = latest_emp_beh if latest_emp_beh != "Benign" else "Initial Access"
        elif latest_risk >= m.thr:
            attack_state = "ELEVATED_THREAT"
            attack_state_label = "Elevated Threat Level"
            attack_stage = latest_emp_beh if latest_emp_beh != "Benign" else "Reconnaissance"
        elif latest_risk >= 0.38 or latest_emp_threat >= 0.35:
            attack_state = "SUSPICIOUS_PROBING"
            attack_state_label = "Suspicious Probing Detected"
            attack_stage = latest_emp_beh if latest_emp_beh != "Benign" else "Reconnaissance"
        else:
            attack_state = "NORMAL_BASELINE"
            attack_state_label = "Defense Telemetry Nominal"
            attack_stage = "Benign"

        if latest_risk < m.thr and latest_emp_threat < 0.35:
            top_beh_name = "Benign"
        else:
            top_beh_name = latest_emp_beh if latest_emp_beh != "Benign" else (steps[0]["behaviours"][0]["behaviour"] if steps else "Benign")

        return dict(
            status="ok", minutes=minutes, state=display,
            risk_score=[None if np.isnan(v) else float(v) for v in score], alert=alert,
            current=dict(
                minute=minutes[-1], alert=is_alert, risk_score=latest_risk,
                attack_state=attack_state, attack_state_label=attack_state_label,
                attack_stage=attack_stage, top_behaviour=top_beh_name,
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
