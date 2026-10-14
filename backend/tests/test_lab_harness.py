"""Lab dataset-collection harness: the safety allow-list and the timeline labelling (no VMs needed)."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "lab" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


collect = _load("collect_dataset")


def base_cfg():
    return json.loads((ROOT / "lab" / "lab_config.example.json").read_text())


def test_example_config_validates():
    collect.validate(base_cfg())  # must not raise


def test_target_outside_subnet_is_refused():
    cfg = base_cfg()
    cfg["scenarios"][1]["target"] = "8.8.8.8"
    with pytest.raises(collect.LabError, match="outside lab_subnet"):
        collect.validate(cfg)


def test_target_not_a_lab_machine_is_refused():
    cfg = base_cfg()
    cfg["scenarios"][1]["target"] = "192.168.56.200"  # in subnet but not a configured VM
    with pytest.raises(collect.LabError, match="not one of the configured lab machines"):
        collect.validate(cfg)


def test_machine_ip_outside_subnet_is_refused():
    cfg = base_cfg()
    cfg["attacker"]["ip"] = "10.0.0.5"
    with pytest.raises(collect.LabError):
        collect.validate(cfg)


def test_command_must_use_target_placeholder():
    cfg = base_cfg()
    cfg["scenarios"][1]["command"] = "nmap -sS 192.168.56.20"  # hard-coded, no {target}
    with pytest.raises(collect.LabError, match="{target}"):
        collect.validate(cfg)


def test_timeline_labelling_and_utc():
    extract = _load("extract_flows")
    windows = [dict(start=extract.parse_iso("2024-01-01T10:00:00+00:00"),
                    end=extract.parse_iso("2024-01-01T10:05:00+00:00"), label="Reconnaissance", scenario_id="recon")]
    inside = extract.parse_iso("2024-01-01T10:02:00+00:00")
    outside = extract.parse_iso("2024-01-01T10:10:00+00:00")
    assert extract.label_for(inside, windows) == ("Reconnaissance", "recon")
    assert extract.label_for(outside, windows) == ("Benign", "")
    # naive and UTC-aware strings must resolve to the same instant
    assert extract.parse_iso("2024-01-01T10:00:00") == extract.parse_iso("2024-01-01T10:00:00+00:00")
