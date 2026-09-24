"""
MITRE ATT&CK interpretation layer.

This is an analyst-written lookup, not something the model learns or predicts. The pipeline is:

    model output (behaviour class or legacy stage name)
        -> behaviour interpretation (what the traffic actually is)
        -> MITRE technique(s)
        -> MITRE tactic(s)

Rules followed:
  * A dataset label is never renamed into a tactic. Each entry states what the traffic in the
    training data actually is and why the technique fits.
  * DoS/DDoS is Impact, not Command and Control. Brute force is Credential Access, not Reconnaissance.
  * Where one class covers more than one behaviour the entry says so (ambiguous=True) and lists
    candidates instead of picking one silently.
  * `confidence` is the author's judgement of how well the technique fits the observed behaviour
    (high / medium / low). It is not a model probability.

Technique and tactic IDs follow ATT&CK Enterprise. Verify against the current ATT&CK release before
publishing externally; ATT&CK renumbers and deprecates entries between versions.
"""
from typing import Optional

TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0001": "Initial Access",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _t(tid, name, tactic):
    return {"technique_id": tid, "technique": name, "tactic_id": tactic, "tactic": TACTICS[tactic]}


# Behaviour classes used by the V3 experiment (CIC-IDS2017 attack behaviours).
BEHAVIOUR_MAP = {
    "Benign": {"description": "No malicious behaviour.", "techniques": [], "ambiguous": False,
               "confidence": None, "rationale": "Nothing to map."},
    "PortScan": {
        "description": "Nmap-style scan of many ports on one victim host from an external source.",
        "techniques": [_t("T1595", "Active Scanning", "TA0043"),
                       _t("T1046", "Network Service Discovery", "TA0007")],
        "ambiguous": False, "confidence": "high",
        "rationale": "External source probing a target is Active Scanning (Reconnaissance). The same scan "
                     "run from a host already inside the network is Network Service Discovery.",
    },
    "BruteForce": {
        "description": "FTP-Patator and SSH-Patator: repeated login attempts against FTP/SSH.",
        "techniques": [_t("T1110", "Brute Force", "TA0006")],
        "ambiguous": False, "confidence": "high",
        "rationale": "Credential guessing against a service is Brute Force (Credential Access). It is not "
                     "reconnaissance: the attacker is trying to authenticate, not to map the target.",
    },
    "DoS": {
        "description": "Hulk, GoldenEye, slowloris and Slowhttptest: HTTP flooding and slow-connection "
                      "exhaustion of a web server.",
        "techniques": [_t("T1499", "Endpoint Denial of Service", "TA0040")],
        "ambiguous": False, "confidence": "high",
        "rationale": "Exhausting a single service is Endpoint Denial of Service (Impact). Not Command and "
                     "Control: there is no attacker-controlled channel to an implant.",
    },
    "DDoS": {
        "description": "LOIC-style HTTP flood labelled DDoS in CIC-IDS2017 (all flows share one masked "
                      "source address in the labelled files).",
        "techniques": [_t("T1498", "Network Denial of Service", "TA0040"),
                       _t("T1499", "Endpoint Denial of Service", "TA0040")],
        "ambiguous": True, "confidence": "medium",
        "rationale": "Impact. Whether this is network-layer (T1498) or application-layer (T1499) flooding "
                     "cannot be settled from flow statistics; both are listed.",
    },
    "WebAttack": {
        "description": "Web login brute force, XSS and SQL injection against a web application.",
        "techniques": [_t("T1190", "Exploit Public-Facing Application", "TA0001"),
                       _t("T1110", "Brute Force", "TA0006")],
        "ambiguous": True, "confidence": "medium",
        "rationale": "XSS and SQL injection exploit the application (Initial Access). The web login brute "
                     "force subset is Credential Access. The class merges both, so flow statistics alone "
                     "do not pick one.",
    },
    "Bot": {
        "description": "ARES botnet: infected hosts beaconing to and taking commands from a controller.",
        "techniques": [_t("T1071", "Application Layer Protocol", "TA0011")],
        "ambiguous": False, "confidence": "medium",
        "rationale": "Periodic HTTP-based check-in with an external controller is Command and Control.",
    },
    "Infiltration": {
        "description": "36 flows from an internal host to an external host after an infiltration step "
                       "(file download / exploit follow-on).",
        "techniques": [_t("T1105", "Ingress Tool Transfer", "TA0011")],
        "ambiguous": True, "confidence": "low",
        "rationale": "Too few flows (36) and too little context to be sure; Ingress Tool Transfer is the "
                     "best fit for a download after compromise. Treat as a weak mapping.",
    },
    "Heartbleed": {
        "description": "CVE-2014-0160 TLS heartbeat memory disclosure against one host (11 flows).",
        "techniques": [_t("T1190", "Exploit Public-Facing Application", "TA0001")],
        "ambiguous": False, "confidence": "medium",
        "rationale": "Exploiting a vulnerable public-facing TLS service. It leaks memory rather than moving "
                     "files, so it is not mapped to Exfiltration.",
    },
}

# V1/V2 six-stage labels are dataset-derived proxies, not campaign stages. Each maps to the behaviours
# that produced it in the training data, so the interpretation stays honest.
LEGACY_STAGE_MAP = {
    "Benign": {"from_behaviours": ["Benign"]},
    "Reconnaissance": {"from_behaviours": ["PortScan", "Bot", "BruteForce"],
                       "note": "Trained on PortScan, Bot and FTP/SSH-Patator. Only PortScan is reconnaissance."},
    "Initial Access": {"from_behaviours": ["WebAttack"], "note": "Trained on web attacks only."},
    "Lateral Movement": {"from_behaviours": ["Infiltration"],
                         "note": "Trained on CIC Infiltration; not verified lateral movement."},
    "C2": {"from_behaviours": ["DoS", "DDoS"],
           "note": "Trained on DoS/DDoS traffic, which is Impact, not Command and Control."},
    "Exfiltration": {"from_behaviours": ["Heartbleed"],
                     "note": "Trained on Heartbleed; see the Heartbleed entry."},
}


def lookup(label: str) -> Optional[dict]:
    """Interpret a V3 behaviour class or a legacy V1 stage name. Returns None if unknown."""
    if label in BEHAVIOUR_MAP:
        return {"label": label, "kind": "behaviour", **BEHAVIOUR_MAP[label]}
    if label in LEGACY_STAGE_MAP:
        legacy = LEGACY_STAGE_MAP[label]
        techniques, seen = [], set()
        for b in legacy["from_behaviours"]:
            for t in BEHAVIOUR_MAP[b]["techniques"]:
                if t["technique_id"] not in seen:
                    seen.add(t["technique_id"])
                    techniques.append(t)
        return {"label": label, "kind": "legacy_stage", "techniques": techniques,
                "ambiguous": len(legacy["from_behaviours"]) > 1, "from_behaviours": legacy["from_behaviours"],
                "note": legacy.get("note"), "confidence": None,
                "description": f"Legacy stage label '{label}' (dataset-derived proxy).",
                "rationale": "Techniques are the union of the behaviours that produced this label in training."}
    return None


def technique_ids(label: str) -> str:
    """Compact string such as 'T1595 / T1046' for display, empty for benign or unknown labels."""
    entry = lookup(label)
    return " / ".join(t["technique_id"] for t in entry["techniques"]) if entry else ""


def full_mapping() -> dict:
    return {"tactics": TACTICS, "behaviours": {k: lookup(k) for k in BEHAVIOUR_MAP},
            "legacy_stages": {k: lookup(k) for k in LEGACY_STAGE_MAP},
            "disclaimer": "Analyst-written interpretation of model output, not a model prediction. "
                          "Verify IDs against the current ATT&CK release."}
