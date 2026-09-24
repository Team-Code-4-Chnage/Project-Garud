"""Unit tests for the V2 network-state world model components."""
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from worldmodel_v2.model import NetStateWorldModel  # noqa: E402
from worldmodel_v2.state_features import (FLOW_FEATURES, STATE_DIM, STATE_FEATURES,  # noqa: E402
                                          session_states, state_from_groups)


def _flows(n, seed=0):
    r = np.random.default_rng(seed)
    x = r.uniform(1, 100, size=(n, len(FLOW_FEATURES)))
    x[:, FLOW_FEATURES.index("retransmit_cnt")] = 0
    return x


def test_state_dim_matches_names():
    assert STATE_DIM == len(STATE_FEATURES) == len(set(STATE_FEATURES))


def test_state_shape_and_finite():
    g = _flows(40).reshape(10, 4, -1)
    s = state_from_groups(g)
    assert s.shape == (10, STATE_DIM)
    assert np.isfinite(s).all()


def test_session_states_labels_do_not_change_features():
    f = _flows(24)
    a = session_states(f, np.zeros(24, int), np.zeros(24, int), 4)
    b = session_states(f, np.ones(24, int), np.full(24, 2), 4)
    assert np.array_equal(a[0], b[0])
    assert b[1].all() and (b[2] == 2).all() and not a[1].any()


def test_state_is_order_insensitive_within_window_only():
    f = _flows(8)
    s1 = session_states(f, np.zeros(8, int), np.zeros(8, int), 4)[0]
    s2 = session_states(f[[3, 2, 1, 0, 7, 6, 5, 4]], np.zeros(8, int), np.zeros(8, int), 4)[0]
    assert np.allclose(s1, s2, atol=1e-5)  # aggregate over the window
    s3 = session_states(np.vstack([f[4:], f[:4]]), np.zeros(8, int), np.zeros(8, int), 4)[0]
    assert np.allclose(s3[0], s1[1], atol=1e-5) and not np.allclose(s3[0], s1[0])  # window order matters


def test_trailing_flows_dropped_not_padded():
    f = _flows(10)
    s, yr, ys, first = session_states(f, np.zeros(10, int), np.zeros(10, int), 4)
    assert len(s) == 2 and list(first) == [0, 4]


def test_rollout_shapes_and_teacher_forcing():
    m = NetStateWorldModel(STATE_DIM, hidden=16, layers=1).eval()
    w = torch.randn(3, 6, STATE_DIM)
    S, R, C = m.rollout(w, 4)
    assert S.shape == (3, 4, STATE_DIM) and R.shape == (3, 4) and C.shape == (3, 4, 6)
    fut = torch.randn(3, 4, STATE_DIM)
    S_tf, _, _ = m.rollout(w, 4, fut, tf_prob=1.0)
    assert torch.allclose(S_tf[:, 0], S[:, 0])          # step 1 never depends on teacher forcing
    assert not torch.allclose(S_tf[:, 1], S[:, 1])      # step 2 consumes the true state instead
    S_free, _, _ = m.rollout(w, 4, fut, tf_prob=0.0)
    assert torch.allclose(S_free, S)                    # tf_prob=0 is pure free-running rollout


def test_future_steps_use_recursion():
    m = NetStateWorldModel(STATE_DIM, hidden=16, layers=1).eval()
    w = torch.randn(1, 6, STATE_DIM)
    S, R, _ = m.rollout(w, 3)
    ns, _, _ = m.step(w)
    w2 = torch.cat([w[:, 1:], ns.unsqueeze(1)], dim=1)
    ns2, r2, _ = m.step(w2)
    assert torch.allclose(S[:, 1], ns2, atol=1e-6) and torch.allclose(R[:, 1], r2, atol=1e-6)
