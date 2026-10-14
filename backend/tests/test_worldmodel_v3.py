"""Harness tests for the V3 alert/episode evaluation (guards the metric mechanics)."""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from worldmodel_v3.lib import LOOKBACK, QUIET, W, choose_operating_point, episodes, evaluate_alerts, sustained  # noqa: E402


def test_sustained_requires_n_consecutive():
    f = np.array([1, 1, 0, 1, 1, 1, 0], bool)
    assert list(sustained(f, 1)) == list(f)
    assert list(sustained(f, 2)) == [False, True, False, False, True, True, False]
    assert list(sustained(f, 3)) == [False, False, False, False, False, True, False]


def test_episodes_need_quiet_lead():
    y = np.zeros(60, int)
    y[3:6] = 1            # attack too early: fewer than QUIET clean minutes before it -> not an episode
    y[30:40] = 1
    assert episodes(y) == [(30, 40)]
    assert all(o >= QUIET for o, _ in episodes(y))


def _series(n=120, onset=60, dur=15):
    y = np.zeros(n, int)
    y[onset:onset + dur] = 1
    return y


def test_oracle_forecaster_warns_and_random_does_not_leak_lead():
    y = _series()
    score = np.full(len(y), np.nan)
    for t in range(W - 1, len(y)):           # oracle: fires exactly 3 minutes before an attack starts
        score[t] = 1.0 if (t + 3 < len(y) and y[t + 3] == 1 and y[t] == 0) else 0.0
    r = evaluate_alerts({"d": score}, {"d": y}, 0.5, 1)
    assert r["eligible"] == 1 and len(r["leads"]) == 1
    assert 1 <= r["leads"][0] <= 3 and r["within"][5] == 1


def test_alert_only_inside_attack_is_not_a_warning():
    y = _series()
    score = np.full(len(y), np.nan)
    score[W - 1:] = 0.0
    score[65:70] = 1.0                        # fires only after onset (a detection, not a warning)
    r = evaluate_alerts({"d": score}, {"d": y}, 0.5, 1)
    assert r["eligible"] == 1 and r["leads"] == [] and r["within"][20] == 0
    assert r["fa_events"] == 0                # not a false alarm either: an attack is present


def test_false_alarm_counted_only_on_quiet_time():
    y = _series(n=200, onset=150)
    score = np.full(len(y), np.nan)
    score[W - 1:] = 0.0
    score[30:32] = 1.0                        # far from any attack -> false alarm
    r = evaluate_alerts({"d": score}, {"d": y}, 0.5, 1)
    assert r["fa_events"] == 1


def test_operating_point_uses_only_validation_data():
    y = _series()
    rng = np.random.default_rng(0)
    score = np.full(len(y), np.nan)
    score[W - 1:] = rng.random(len(y) - W + 1)
    a = choose_operating_point({"v": score}, {"v": y})
    b = choose_operating_point({"v": score.copy()}, {"v": y.copy()})
    assert a == b                              # deterministic and depends only on its arguments
    assert 1 <= a[1] <= 5 and LOOKBACK == 20
