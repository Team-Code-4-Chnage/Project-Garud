"""
Network topology graph derived from active sessions (PS 26153 — graph-based representation).

Converts concurrent flow sessions into a directed graph where:
  - Nodes  = IP addresses  (attributes: role, max_risk, session_count)
  - Edges  = active sessions between two IPs  (attributes: stage, probability, session_key)

This satisfies the SIH 2026 PS:26153 requirement for "graph-based representation of
network state."  The graph is built on-demand from the in-memory session list returned
by the /sessions API so it requires no additional model or data store.

The graph structure also makes high-risk IP clusters immediately visible — a node with
high max_risk and many incoming edges is a natural candidate for containment, which maps
directly to the "proactive defence" requirement.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

# Ordered kill-chain stages — lower index = earlier in kill chain.
KILL_CHAIN_ORDER: dict[str, int] = {
    "Benign": 0,
    "Reconnaissance": 1,
    "PortScan": 1,
    "Initial Access": 2,
    "BruteForce": 2,
    "DoS": 2,
    "DDoS": 2,
    "WebAttack": 2,
    "Lateral Movement": 3,
    "C2": 4,
    "Bot": 4,
    "Exfiltration": 5,
    "Infiltration": 5,
}


def _stage_severity(stage: str) -> int:
    """Return kill-chain ordinal for a stage label (0 = benign, 5 = exfiltration)."""
    return KILL_CHAIN_ORDER.get(stage, 0)


def build_session_graph(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Build a serialisable directed graph from a list of session dicts.

    Parameters
    ----------
    sessions : list of dicts with keys:
        session_key, src_ip, dst_ip, predicted_stage, latest_risk_score (or
        infiltration_probability), flow_count, source.

    Returns
    -------
    {
        "nodes": [ {id, role, max_risk, session_count, max_stage, max_stage_severity}, … ],
        "edges": [ {source, target, stage, probability, session_key, flow_count}, … ],
        "node_count": int,
        "edge_count": int,
        "high_risk_nodes": [ id, … ],   # nodes with max_risk > 0.7
        "kill_chain_summary": { stage: count, … },
    }
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    kill_chain_summary: dict[str, int] = defaultdict(int)

    for s in sessions:
        src = s.get("src_ip") or "unknown"
        dst = s.get("dst_ip") or "unknown"
        stage = s.get("predicted_stage") or "Benign"
        prob = float(s.get("latest_risk_score") or s.get("infiltration_probability") or 0.0)
        flow_count = int(s.get("flow_count") or 0)
        session_key = s.get("session_key") or f"{src}->{dst}"
        app_name = s.get("app_name") or s.get("process_name") or "Network Flow"
        protocol = s.get("protocol") or "TCP"
        src_port = s.get("src_port")
        dst_port = s.get("dst_port")

        kill_chain_summary[stage] += 1

        # ── Update nodes ──────────────────────────────────────────────────────
        for ip, role, peer_ip in [(src, "source", dst), (dst, "destination", src)]:
            if ip not in nodes:
                nodes[ip] = {
                    "id": ip,
                    "role": role,
                    "max_risk": 0.0,
                    "session_count": 0,
                    "max_stage": "Benign",
                    "max_stage_severity": 0,
                    "apps": set(),
                    "sessions": [],
                }
            n = nodes[ip]
            n["session_count"] += 1
            if app_name and app_name.lower() not in ("unknown", "network flow"):
                n["apps"].add(app_name)
            n["sessions"].append({
                "session_key": session_key,
                "peer_ip": peer_ip,
                "stage": stage,
                "risk": round(prob, 4),
                "app": app_name,
                "protocol": protocol,
            })
            if prob > n["max_risk"]:
                n["max_risk"] = round(prob, 6)
            if _stage_severity(stage) > n["max_stage_severity"]:
                n["max_stage"] = stage
                n["max_stage_severity"] = _stage_severity(stage)

        # ── Add edge ──────────────────────────────────────────────────────────
        edges.append({
            "source": src,
            "target": dst,
            "stage": stage,
            "probability": round(prob, 6),
            "session_key": session_key,
            "flow_count": flow_count,
            "app_name": app_name,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
        })

    node_list = [
        {
            **v,
            "max_risk": round(v["max_risk"], 4),
            "apps": sorted(list(v["apps"])),
            "sessions": v["sessions"][:12],  # Keep top recent sessions
        }
        for v in nodes.values()
    ]
    high_risk = [n["id"] for n in node_list if n["max_risk"] > 0.7]

    return {
        "nodes": node_list,
        "edges": edges,
        "node_count": len(node_list),
        "edge_count": len(edges),
        "high_risk_nodes": high_risk,
        "kill_chain_summary": dict(kill_chain_summary),
    }
