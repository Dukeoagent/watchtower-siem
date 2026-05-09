"""
WatchTower SIEM - Remediation Engine
=======================================
For every alert, suggest a concrete remediation action.
This is the "what do I do about this?" layer.

Remediations are keyed by rule_id first, then rule_group fallback.
"""

from typing import Dict, Optional

# ── Rule ID → Remediation Text ────────────────────────────────────────────────
RULE_REMEDIATION: Dict[int, str] = {
    # File Integrity Monitoring
    550: "A monitored file was modified. Verify the change was authorized. "
         "If unexpected, isolate the host, check running processes (ps aux), "
         "and review recent logins (last -n 20). Restore file from known-good backup if needed.",
    551: "A new file appeared in a monitored directory. Check if it's a legitimate "
         "deployment artifact. If unknown, scan it with ClamAV: `clamscan -r /path/to/file`. "
         "Check file ownership and permissions: `ls -la /path/to/file`.",
    554: "New binary detected in a sensitive path. Run `sha256sum <file>` and compare "
         "against known-good hashes. Check for rootkit with `rkhunter --check`.",
    555: "A monitored file was deleted. If unplanned, check audit logs: "
         "`ausearch -f /path/to/file`. Review who had access and when.",

    # Rootcheck
    5910: "Rootkit indicators found! Immediate action: 1) Isolate the host from network. "
          "2) Do NOT reboot (evidence loss). 3) Take a forensic snapshot. "
          "4) Run `rkhunter --check` and `chkrootkit`. 5) Escalate to incident response team.",
    5911: "Suspicious hidden process or file detected. Run `unhide proc` and `unhide sys`. "
          "Check for anomalous network connections: `ss -tulnp`. Consider full system reimaging.",

    # Authentication
    5710: "SSH brute-force attack detected. Immediately: 1) Block the source IP: "
          "`iptables -A INPUT -s <IP> -j DROP`. 2) Check if any attempt succeeded: "
          "`grep 'Accepted' /var/log/auth.log`. 3) Enable fail2ban if not active.",
    5720: "Multiple failed logins. Block attacking IP with fail2ban or UFW. "
          "Enable MFA for SSH. Review SSH config: disable root login, use key-based auth only.",

    # Privilege Escalation
    5400: "Unexpected sudo usage detected. Review sudoers file: `visudo`. "
          "Check who ran the command: `grep sudo /var/log/auth.log | tail -50`. "
          "If unauthorized, revoke sudo privileges immediately: `deluser <user> sudo`.",

    # User Creation
    5901: "New user account created. Verify this was authorized. "
          "If not: `userdel -r <username>`. Audit who created it: "
          "`grep useradd /var/log/auth.log`. Review all accounts: `cat /etc/passwd`.",

    # Malware (ClamAV)
    100200: "Malware detected by ClamAV! 1) Quarantine the file: move to /quarantine. "
            "2) Identify how it arrived (check download history, email attachments, "
            "recently modified files). 3) Scan the full system: `clamscan -r / --remove`. "
            "4) Check for lateral movement: review network connections and other hosts.",
    100201: "Infected file found. Remove with: `clamscan --remove /path/to/file`. "
            "Update ClamAV signatures: `freshclam`. Schedule regular scans via cron.",

    # Vulnerabilities
    18501: "Critical CVE detected on a running service. 1) Check if the service is "
           "exposed to the internet. 2) Apply patches immediately: `apt upgrade <package>`. "
           "3) If patch unavailable, restrict network access via firewall. "
           "4) Monitor for exploitation attempts in logs.",
}

# ── Group-Based Remediation Fallback ─────────────────────────────────────────
GROUP_REMEDIATION: Dict[str, str] = {
    "syscheck": "A file change was detected. Verify it was an authorized change "
                "(deployment, update, config change). If unexpected, investigate immediately — "
                "check running processes, recent logins, and file ownership.",

    "malware":  "Malware activity detected. Isolate the endpoint, quarantine the file, "
                "run a full ClamAV scan, and check for persistence mechanisms "
                "(crontabs, startup scripts, new user accounts).",

    "rootcheck": "Rootkit or hidden process detected. Isolate the host immediately. "
                 "Do not reboot. Take a memory dump for forensics. Reimage the system "
                 "from a known-clean baseline.",

    "sca":      "A CIS security benchmark check failed. Review the specific check and apply "
                "the recommended hardening. Common fixes: disable unused services, "
                "enforce password policies, restrict file permissions.",

    "authentication_failed": "Failed authentication attempts detected. Block the source IP, "
                              "enable account lockout policies, and enable MFA where possible.",

    "vulnerability": "A known vulnerability was detected. Patch the affected package "
                     "immediately. If a patch is unavailable, apply compensating controls "
                     "(WAF rules, network restrictions, disable the service).",

    "attack":   "Active attack pattern detected. Immediately block the source IP, "
                "review firewall rules, and check for successful exploitation in logs.",

    "web":      "Web attack detected. Check WAF logs, review application error logs, "
                "and verify no data was exfiltrated. Apply relevant patches and "
                "restrict access to admin endpoints.",
}

DEFAULT_REMEDIATION = (
    "Review the full alert log and identify the affected system. "
    "Check for unusual processes, network connections, and file changes. "
    "Escalate to your security team if the activity cannot be explained."
)


def get_remediation(rule_id: int, rule_groups: str) -> str:
    """
    Return a human-readable remediation suggestion for an alert.
    """
    # 1. Exact rule ID match
    if rule_id in RULE_REMEDIATION:
        return RULE_REMEDIATION[rule_id]

    # 2. Group-based fallback
    groups = [g.strip().lower() for g in rule_groups.split(",")]
    for group in groups:
        if group in GROUP_REMEDIATION:
            return GROUP_REMEDIATION[group]

    # 3. Generic fallback
    return DEFAULT_REMEDIATION
