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
        row = {f: float(getattr(flow, f)) for f in FLOW_FEATURES}
        row.update(src_ip=flow.src_ip or "0.0.0.0", dst_ip=flow.dst_ip or "0.0.0.0",
                   src_port=flow.src_port or 0, dst_port=flow.dst_port or 0, protocol=flow.protocol or "TCP",
                   timestamp=flow.timestamp or datetime.now(timezone.utc), _source=source or "api")
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
            rows = list(self._flows)
        by_source = {}
        for r in rows:
            by_source[r["_source"]] = by_source.get(r["_source"], 0) + 1
        out = dict(flows=len(rows), sources=by_source)
        if rows:
            ts = [r["timestamp"] for r in rows]
            out.update(first=min(ts).isoformat(), last=max(ts).isoformat())
        return out

    def states(self):
        with self._lock:
            rows = list(self._flows)
        if not rows:
            return None
        st = full_grid(minute_states(flows_from_features(rows)))
        now_min = np.datetime64(datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0))
        st = st[st.index.values < now_min]  # the current wall-clock minute may still receive more flows
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
        score[m.W - 1:] = risk.max(axis=1)
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
        steps = []
        for k in range(m.H):
            top = np.argsort(-probs[k])[:3]
            beh = []
            for i in top:
                name = m.behaviours[i]
                entry = mitre_lookup(name) or {}
                beh.append(dict(behaviour=name, probability=float(probs[k][i]),
                                techniques=[t["technique_id"] for t in entry.get("techniques", [])],
                                tactics=sorted({t["tactic"] for t in entry.get("techniques", [])})))
            steps.append(dict(step=k + 1, minute=(last_minute + np.timedelta64(k + 1, "m")).isoformat(),
                              risk=float(torch.sigmoid(R1[0, k]).item()), behaviours=beh,
                              state={f: float(pred_states[k][m.features.index(f)]) for f in DISPLAY_FEATURES
                                     if f in m.features}))
        return dict(
            status="ok", minutes=minutes, state=display,
            risk_score=[None if np.isnan(v) else float(v) for v in score], alert=alert,
            current=dict(minute=minutes[-1], alert=bool(alert[-1]), risk_score=float(score[-1]),
                         consecutive_needed=m.N, threshold=m.thr),
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
