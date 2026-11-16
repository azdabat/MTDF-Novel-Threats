"""
attack_tactics.py - MITRE ATT&CK Enterprise tactics in kill-chain order.

Folder names under detections/ must be one of the slugs below. They match the
tactic folder names used by OTRF Security-Datasets, so a dataset's home and a
detection's home line up.
"""

TACTICS = [
    # (folder slug,          ATT&CK ID, display name)
    ("reconnaissance",       "TA0043", "Reconnaissance"),
    ("resource_development", "TA0042", "Resource Development"),
    ("initial_access",       "TA0001", "Initial Access"),
    ("execution",            "TA0002", "Execution"),
    ("persistence",          "TA0003", "Persistence"),
    ("privilege_escalation", "TA0004", "Privilege Escalation"),
    ("defense_evasion",      "TA0005", "Defense Evasion"),
    ("credential_access",    "TA0006", "Credential Access"),
    ("discovery",            "TA0007", "Discovery"),
    ("lateral_movement",     "TA0008", "Lateral Movement"),
    ("collection",           "TA0009", "Collection"),
    ("command_and_control",  "TA0011", "Command and Control"),
    ("exfiltration",         "TA0010", "Exfiltration"),
    ("impact",               "TA0040", "Impact"),
]

SLUGS = [t[0] for t in TACTICS]
ORDER = {slug: i for i, slug in enumerate(SLUGS)}
DISPLAY = {slug: f"{name} ({tid})" for slug, tid, name in TACTICS}
