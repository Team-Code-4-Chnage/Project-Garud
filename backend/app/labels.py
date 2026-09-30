"""
Attack labels of public flow datasets mapped to the behaviour classes the models use.

The mapping is by normalised substring, so CIC-IDS2017 names ("DoS Hulk"), CSE-CIC-IDS2018 names
("Brute Force -Web", "Infilteration"), UNSW-NB15 categories and plain 0/1 or normal/attack columns all
resolve. A label that is clearly an attack but matches no class is "Other attack": it counts as malicious
for detection scores but has no family. A label that cannot be interpreted is "Unknown" and is left out
of scores instead of being guessed.
"""
from __future__ import annotations

import re

BEHAVIOURS = [
    "Benign", "PortScan", "BruteForce", "DoS", "DDoS", "WebAttack", "Bot", "Infiltration", "Heartbleed",
    "Reconnaissance", "Initial Access", "Lateral Movement", "C2", "Exfiltration",
]
OTHER_ATTACK = "Other attack"
UNKNOWN = "Unknown"

BENIGN_WORDS = {"benign", "normal", "0", "false", "background", "legitimate", "none", "legit", "clean", ""}
GENERIC_ATTACK_WORDS = {
    "1", "true", "attack", "malicious", "anomaly", "abnormal", "intrusion", "bad", "threat",
    "malware", "generic", "backdoor", "fuzzers", "analysis", "worms", "trojan", "ransomware",
    "c2", "command and control", "command_and_control", "exfiltration", "exfil",
    "initial access", "initial_access", "lateral movement", "lateral_movement", "reconnaissance", "recon",
    "execution", "privilege escalation", "credential access", "defense evasion", "discovery", "collection", "impact",
}

# order matters: the first matching rule wins
_RULES = [
    (r"heartbleed", "Heartbleed"),
    (r"exfil", "Exfiltration"),
    (r"\bc2\b|command ?(?:and|&|-) ?control", "C2"),
    (r"lateral ?move", "Lateral Movement"),
    (r"initial ?access", "Initial Access"),
    (r"infil", "Infiltration"),
    (r"\bbot|botnet|ares", "Bot"),
    (r"port ?scan|portsweep|reconnaissance|recon|scan|probe|nmap", "PortScan"),
    (r"sql|xss|web ?attack|brute ?force ?-? ?(web|xss)|webattack|injection|shellcode|exploit", "WebAttack"),
    (r"ddos|loic|hoic|distributed", "DDoS"),
    (r"dos|hulk|goldeneye|slowloris|slowhttp|flood|slowread", "DoS"),
    (r"patator|brute ?force|bruteforce|password|ssh-?bf|ftp-?bf|guess", "BruteForce"),
]
_COMPILED = [(re.compile(p), b) for p, b in _RULES]


def norm_label(value) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^ -~]", "-", str(value))).strip().lower()


def behaviour_of(label) -> str | None:
    """Behaviour class of a label; None when the label is missing."""
    if label is None:
        return None
    s = norm_label(label)
    if s in ("nan", "<na>", "null", "na", "n/a"):
        return None
    if s in BENIGN_WORDS:
        return "Benign"
    for rx, name in _COMPILED:
        if rx.search(s):
            return name
    if s in GENERIC_ATTACK_WORDS or re.search(r"attack|malware|malicious|intrusion", s):
        return OTHER_ATTACK
    return UNKNOWN


def is_attack_label(label) -> bool | None:
    b = behaviour_of(label)
    return None if b in (None, UNKNOWN) else b != "Benign"
