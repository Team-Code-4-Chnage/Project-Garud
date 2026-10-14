"""MITRE interpretation layer: mapping correctness rules and API exposure."""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.mitre import BEHAVIOUR_MAP, LEGACY_STAGE_MAP, lookup, technique_ids
from app.model_loader import artifacts


@pytest.fixture(scope="module")
def client():
    if not artifacts.is_loaded:
        artifacts.load()
    with TestClient(app) as tc:
        yield tc


def tactics(label):
    return {t["tactic"] for t in lookup(label)["techniques"]}


def test_dos_is_impact_not_c2():
    assert tactics("DoS") == {"Impact"}
    assert tactics("DDoS") == {"Impact"}
    assert "Command and Control" not in tactics("DoS")


def test_brute_force_is_credential_access_not_recon():
    assert tactics("BruteForce") == {"Credential Access"}


def test_portscan_is_recon_or_discovery():
    assert tactics("PortScan") <= {"Reconnaissance", "Discovery"}


def test_legacy_c2_stage_reveals_it_is_dos_traffic():
    e = lookup("C2")
    assert e["from_behaviours"] == ["DoS", "DDoS"]
    assert {t["tactic"] for t in e["techniques"]} == {"Impact"}
    assert "Impact" in e["note"]


def test_ambiguous_legacy_stage_is_flagged():
    assert lookup("Reconnaissance")["ambiguous"] is True


def test_every_entry_documents_its_reasoning():
    for name, e in BEHAVIOUR_MAP.items():
        assert e["rationale"] and e["description"], name
        if e["techniques"]:
            assert e["confidence"] in ("high", "medium", "low"), name
    assert set(LEGACY_STAGE_MAP) >= {"Benign", "Reconnaissance", "Initial Access", "Lateral Movement", "C2",
                                     "Exfiltration"}


def test_benign_and_unknown():
    assert technique_ids("Benign") == ""
    assert lookup("NotAClass") is None


def test_mapping_endpoint(client):
    r = client.get("/mitre/mapping")
    assert r.status_code == 200
    body = r.json()
    assert body["behaviours"]["DoS"]["techniques"][0]["tactic"] == "Impact"
    assert "legacy_stages" in body and "disclaimer" in body


def test_lookup_endpoint(client):
    assert client.get("/mitre/lookup/BruteForce").json()["techniques"][0]["technique_id"] == "T1110"
    assert client.get("/mitre/lookup/nope").status_code == 404
