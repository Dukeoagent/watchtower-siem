"""
WatchTower SIEM - MITRE ATT&CK Mapper
========================================
Maps Wazuh rule IDs and rule groups to MITRE ATT&CK
Tactics, Techniques, and Procedures (TTPs).

MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/
"""

from typing import Optional, Dict

# ── Rule ID → TTP Mapping ─────────────────────────────────────────────────────
# Format: rule_id: {"id": "T####", "name": "Technique Name", "tactic": "Tactic"}
#
# Wazuh Rule ID reference:
#   550-599  → Syscheck / File Integrity Monitoring
#   591x     → Rootcheck / Rootkit detection
#   87xxx    → SCA / Configuration Assessment
#   1002     → Unknown / Syslog errors
#   5XXX     → Authentication events
#   2XXX     → PAM / User management
#   185XX    → Vulnerability detection
#   100XXX   → ClamAV / Malware

RULE_ID_MAP: Dict[int, Dict] = {
    # ── File Integrity Monitoring ───────────────────────────────────────────
    550:  {"id": "T1565.001", "name": "Stored Data Manipulation",     "tactic": "Impact"},
    551:  {"id": "T1565.001", "name": "Stored Data Manipulation",     "tactic": "Impact"},
    552:  {"id": "T1565.001", "name": "Stored Data Manipulation",     "tactic": "Impact"},
    553:  {"id": "T1565.001", "name": "Stored Data Manipulation",     "tactic": "Impact"},
    554:  {"id": "T1105",     "name": "Ingress Tool Transfer",         "tactic": "Command and Control"},
    555:  {"id": "T1070.004", "name": "File Deletion",                "tactic": "Defense Evasion"},

    # ── Rootkit / Rootcheck ─────────────────────────────────────────────────
    5910: {"id": "T1014",    "name": "Rootkit",                        "tactic": "Defense Evasion"},
    5911: {"id": "T1014",    "name": "Rootkit",                        "tactic": "Defense Evasion"},

    # ── Authentication / Brute Force ────────────────────────────────────────
    5710: {"id": "T1110",    "name": "Brute Force",                    "tactic": "Credential Access"},
    5711: {"id": "T1110",    "name": "Brute Force",                    "tactic": "Credential Access"},
    5712: {"id": "T1110.001","name": "Password Guessing",              "tactic": "Credential Access"},
    5720: {"id": "T1110",    "name": "Brute Force",                    "tactic": "Credential Access"},

    # ── Privilege Escalation ────────────────────────────────────────────────
    5400: {"id": "T1548.003","name": "Sudo and Sudo Caching",          "tactic": "Privilege Escalation"},
    5401: {"id": "T1548.003","name": "Sudo and Sudo Caching",          "tactic": "Privilege Escalation"},

    # ── User Account Creation ───────────────────────────────────────────────
    5901: {"id": "T1136.001","name": "Create Local Account",           "tactic": "Persistence"},
    5902: {"id": "T1136.001","name": "Create Local Account",           "tactic": "Persistence"},

    # ── ClamAV Malware Detection ────────────────────────────────────────────
    100200: {"id": "T1204.002","name": "Malicious File",               "tactic": "Execution"},
    100201: {"id": "T1204.002","name": "Malicious File",               "tactic": "Execution"},
    100202: {"id": "T1566.001","name": "Spearphishing Attachment",     "tactic": "Initial Access"},

    # ── Vulnerability Detection ─────────────────────────────────────────────
    18501: {"id": "T1190",   "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    18502: {"id": "T1190",   "name": "Exploit Public-Facing Application","tactic": "Initial Access"},

    # ── Process / Execution ─────────────────────────────────────────────────
    5100: {"id": "T1059",    "name": "Command and Scripting Interpreter","tactic": "Execution"},
    5101: {"id": "T1059.004","name": "Unix Shell",                     "tactic": "Execution"},

    # ── Network ─────────────────────────────────────────────────────────────
    1001: {"id": "T1046",    "name": "Network Service Discovery",      "tactic": "Discovery"},
    1002: {"id": "T1595",    "name": "Active Scanning",               "tactic": "Reconnaissance"},

    # ── Web Attack ──────────────────────────────────────────────────────────
    31100: {"id": "T1190",   "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    31101: {"id": "T1059.007","name": "JavaScript",                   "tactic": "Execution"},
}

# ── Rule Group → TTP Fallback ─────────────────────────────────────────────────
# If the rule_id isn't in the map above, fall back to group-level mapping.
GROUP_MAP: Dict[str, Dict] = {
    "syscheck":       {"id": "T1565.001", "name": "Stored Data Manipulation",  "tactic": "Impact"},
    "fim":            {"id": "T1565.001", "name": "Stored Data Manipulation",  "tactic": "Impact"},
    "malware":        {"id": "T1204.002", "name": "Malicious File",            "tactic": "Execution"},
    "virus":          {"id": "T1204.002", "name": "Malicious File",            "tactic": "Execution"},
    "rootcheck":      {"id": "T1014",     "name": "Rootkit",                   "tactic": "Defense Evasion"},
    "sca":            {"id": "T1562.001", "name": "Disable or Modify Tools",   "tactic": "Defense Evasion"},
    "authentication_failed": {"id": "T1110", "name": "Brute Force",            "tactic": "Credential Access"},
    "authentication_success": {"id": "T1078", "name": "Valid Accounts",        "tactic": "Defense Evasion"},
    "sudo":           {"id": "T1548.003", "name": "Sudo and Sudo Caching",     "tactic": "Privilege Escalation"},
    "adduser":        {"id": "T1136.001", "name": "Create Local Account",      "tactic": "Persistence"},
    "vulnerability":  {"id": "T1190",     "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    "web":            {"id": "T1190",     "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    "attack":         {"id": "T1595",     "name": "Active Scanning",           "tactic": "Reconnaissance"},
}


def enrich_alert_with_ttp(rule_id: int, rule_groups: str) -> Dict:
    """
    Given a Wazuh rule ID and its groups string, return the best-matching
    MITRE ATT&CK TTP.

    Priority:
      1. Exact rule ID match
      2. First matching rule group
      3. Empty dict (unknown technique)
    """
    # 1. Exact rule_id match
    if rule_id in RULE_ID_MAP:
        return RULE_ID_MAP[rule_id]

    # 2. Group-based fallback
    groups = [g.strip().lower() for g in rule_groups.split(",")]
    for group in groups:
        if group in GROUP_MAP:
            return GROUP_MAP[group]

    # 3. Nothing matched
    return {"id": None, "name": None, "tactic": None}
