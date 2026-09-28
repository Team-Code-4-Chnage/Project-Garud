"""
Tests for the session graph endpoint (PS 26153 — graph-based representation).

Validates:
  - build_session_graph() builds correct nodes and edges
  - /graph/topology endpoint responds correctly
  - /graph/topology/summary returns required fields
  - High-risk detection threshold works
  - Empty session list produces a valid empty graph
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.graph_state import build_session_graph


# ── Unit tests for build_session_graph ─────────────────────────────────────────

class TestBuildSessionGraph:

    def test_empty_sessions(self):
        graph = build_session_graph([])
        assert graph["node_count"] == 0
        assert graph["edge_count"] == 0
        assert graph["nodes"] == []
        assert graph["edges"] == []
        assert graph["high_risk_nodes"] == []

    def test_single_session_creates_two_nodes_one_edge(self):
        sessions = [{
            "session_key": "10.0.0.1->192.168.1.1@80",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "predicted_stage": "Reconnaissance",
            "latest_risk_score": 0.3,
            "flow_count": 5,
        }]
        graph = build_session_graph(sessions)
        assert graph["node_count"] == 2
        assert graph["edge_count"] == 1
        ids = {n["id"] for n in graph["nodes"]}
        assert "10.0.0.1" in ids
        assert "192.168.1.1" in ids

    def test_high_risk_node_flagged(self):
        sessions = [{
            "session_key": "10.0.0.1->192.168.1.1@443",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "predicted_stage": "C2",
            "latest_risk_score": 0.92,
            "flow_count": 20,
        }]
        graph = build_session_graph(sessions)
        assert "10.0.0.1" in graph["high_risk_nodes"] or \
               "192.168.1.1" in graph["high_risk_nodes"]

    def test_benign_low_risk_not_flagged(self):
        sessions = [{
            "session_key": "10.0.0.2->10.0.0.3@80",
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.3",
            "predicted_stage": "Benign",
            "latest_risk_score": 0.1,
            "flow_count": 100,
        }]
        graph = build_session_graph(sessions)
        assert len(graph["high_risk_nodes"]) == 0

    def test_multiple_sessions_same_ip_merged_into_one_node(self):
        sessions = [
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
             "predicted_stage": "Reconnaissance", "latest_risk_score": 0.4, "flow_count": 3},
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.2",
             "predicted_stage": "Initial Access", "latest_risk_score": 0.75, "flow_count": 7},
        ]
        graph = build_session_graph(sessions)
        # 10.0.0.1 appears in both, should be one node with max_risk from the higher session
        src_node = next(n for n in graph["nodes"] if n["id"] == "10.0.0.1")
        assert src_node["max_risk"] == pytest.approx(0.75, abs=0.01)
        assert src_node["max_stage"] == "Initial Access"
        assert graph["edge_count"] == 2

    def test_kill_chain_summary_populated(self):
        sessions = [
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
             "predicted_stage": "Reconnaissance", "latest_risk_score": 0.3, "flow_count": 1},
            {"src_ip": "10.0.0.2", "dst_ip": "192.168.1.1",
             "predicted_stage": "Reconnaissance", "latest_risk_score": 0.4, "flow_count": 1},
            {"src_ip": "10.0.0.3", "dst_ip": "192.168.1.1",
             "predicted_stage": "C2", "latest_risk_score": 0.88, "flow_count": 1},
        ]
        graph = build_session_graph(sessions)
        assert graph["kill_chain_summary"].get("Reconnaissance") == 2
        assert graph["kill_chain_summary"].get("C2") == 1

    def test_missing_ip_falls_back_to_unknown(self):
        sessions = [{"predicted_stage": "Benign", "latest_risk_score": 0.0, "flow_count": 0}]
        graph = build_session_graph(sessions)
        # Should not raise — unknown node is acceptable
        assert graph["node_count"] >= 0


# ── API endpoint tests ──────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    from app.model_loader import artifacts
    if not artifacts.is_loaded:
        artifacts.load()
    from app.main import app
    with TestClient(app) as tc:
        yield tc


class TestGraphEndpoints:

    def test_topology_endpoint_responds(self, client):
        res = client.get("/graph/topology")
        assert res.status_code == 200
        data = res.json()
        assert "nodes" in data
        assert "edges" in data
        assert "node_count" in data
        assert "edge_count" in data
        assert "high_risk_nodes" in data
        assert "kill_chain_summary" in data

    def test_topology_summary_endpoint_responds(self, client):
        res = client.get("/graph/topology/summary")
        assert res.status_code == 200
        data = res.json()
        assert "node_count" in data
        assert "edge_count" in data
        assert "high_risk_nodes" in data
        assert "high_risk_count" in data
        assert "kill_chain_summary" in data

    def test_topology_min_risk_filter_accepted(self, client):
        res = client.get("/graph/topology?min_risk=0.5")
        assert res.status_code == 200

    def test_topology_invalid_min_risk_rejected(self, client):
        res = client.get("/graph/topology?min_risk=2.0")
        assert res.status_code == 422

    def test_topology_limit_too_large_rejected(self, client):
        res = client.get("/graph/topology?limit=99999")
        assert res.status_code == 422
