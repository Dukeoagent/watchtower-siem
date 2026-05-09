"""
WatchTower SIEM - Demo Data Seeder
=====================================
Seeds the database with realistic-looking alerts so you can
demo the dashboard without a live Wazuh agent.

Two ways to use it:
  1. Standalone (via HTTP):  python3 seed_alerts.py
     Posts each alert through the REST API. Use this from outside
     the container.

  2. As a library (direct DB write):
       from seed_alerts import seed_database
       seed_database(db_session)
     Used by the backend on first startup to auto-populate.
"""

import os
import json
import random
import time
from datetime import datetime, timedelta

API = os.getenv("WATCHTOWER_API", "http://localhost:8000")

AGENTS = [
    {"name": "prod-web-01",    "ip": "10.0.1.10",     "os": "Ubuntu 22.04"},
    {"name": "dev-laptop-arm", "ip": "192.168.1.105", "os": "Windows 11"},
    {"name": "db-server-02",   "ip": "10.0.2.20",     "os": "Debian 12"},
    {"name": "jenkins-ci",     "ip": "10.0.3.5",      "os": "Ubuntu 22.04"},
    {"name": "ubuntu-desktop", "ip": "192.168.1.200", "os": "Ubuntu 24.04"},
]

ALERTS = [
    # Critical
    {
        "rule_id": 100200, "rule_level": 14,
        "rule_description": "ClamAV: Malware found - Trojan.GenericKD.47391782",
        "rule_groups": "malware,virus",
        "full_log": "ClamAV: /tmp/.x/payload.sh: Trojan.GenericKD.47391782 FOUND",
        "extra": {"syscheck": {"path": "/tmp/.x/payload.sh", "event": "modified"}},
    },
    {
        "rule_id": 5910, "rule_level": 13,
        "rule_description": "Rootkit detection: Hidden process found",
        "rule_groups": "rootcheck,intrusion_detection",
        "full_log": "rootcheck: Rootkit 'Suckit Rootkit' detected. Hidden process 4821.",
        "extra": {},
    },
    {
        "rule_id": 550, "rule_level": 13,
        "rule_description": "FIM: Critical binary modified - /usr/bin/sudo",
        "rule_groups": "syscheck,fim",
        "full_log": "File '/usr/bin/sudo' was modified. Old MD5: a3f2... New MD5: d91c...",
        "extra": {"syscheck": {
            "path": "/usr/bin/sudo", "event": "modified",
            "md5_before": "a3f2e1b9c4d8e7f0", "md5_after": "d91c3b7a2e5f9012"
        }},
    },
    {
        "rule_id": 5720, "rule_level": 13,
        "rule_description": "SSH brute-force: 150 failed login attempts from 185.220.101.45",
        "rule_groups": "authentication_failed,attack",
        "full_log": "Multiple authentication failures from 185.220.101.45 (150 attempts in 60s)",
        "extra": {"src_ip": "185.220.101.45"},
    },

    # High
    {
        "rule_id": 554, "rule_level": 11,
        "rule_description": "FIM: New file in /etc/cron.d - possible persistence",
        "rule_groups": "syscheck,fim",
        "full_log": "New file '/etc/cron.d/backdoor' detected. Owner: www-data",
        "extra": {"syscheck": {"path": "/etc/cron.d/backdoor", "event": "added"}},
    },
    {
        "rule_id": 5400, "rule_level": 11,
        "rule_description": "Unexpected sudo execution: www-data ran /bin/bash",
        "rule_groups": "sudo,attack",
        "full_log": "sudo: www-data : command=/bin/bash ; TTY=pts/0",
        "extra": {},
    },
    {
        "rule_id": 18501, "rule_level": 10,
        "rule_description": "CVE-2023-44487 (HTTP/2 Rapid Reset) detected in nginx 1.18.0",
        "rule_groups": "vulnerability",
        "full_log": "Package: nginx 1.18.0 | CVE: CVE-2023-44487 | CVSS: 7.5 | Fix: 1.25.3",
        "extra": {"vulnerability": {"cve": "CVE-2023-44487", "package": "nginx", "cvss": 7.5}},
    },
    {
        "rule_id": 5901, "rule_level": 10,
        "rule_description": "New privileged user account created: sysbackup",
        "rule_groups": "adduser,authentication_success",
        "full_log": "useradd: new user 'sysbackup' added to group 'sudo'. Initiated by: jenkins",
        "extra": {},
    },
    {
        "rule_id": 100201, "rule_level": 10,
        "rule_description": "ClamAV: Suspicious script detected - PHP.Webshell.D",
        "rule_groups": "malware",
        "full_log": "ClamAV: /var/www/html/shell.php: PHP.Webshell.D FOUND",
        "extra": {"syscheck": {"path": "/var/www/html/shell.php", "event": "added"}},
    },

    # Medium
    {
        "rule_id": 550, "rule_level": 8,
        "rule_description": "FIM: /etc/passwd modified",
        "rule_groups": "syscheck,fim",
        "full_log": "File '/etc/passwd' was modified. New entry detected.",
        "extra": {"syscheck": {"path": "/etc/passwd", "event": "modified"}},
    },
    {
        "rule_id": 550, "rule_level": 8,
        "rule_description": "FIM: /etc/ssh/sshd_config modified",
        "rule_groups": "syscheck,fim",
        "full_log": "File '/etc/ssh/sshd_config' was modified. PermitRootLogin changed.",
        "extra": {"syscheck": {"path": "/etc/ssh/sshd_config", "event": "modified"}},
    },
    {
        "rule_id": 87701, "rule_level": 7,
        "rule_description": "SCA: CIS check failed - Password max age not set",
        "rule_groups": "sca",
        "full_log": "SCA check 2003 FAILED: Ensure password expiration is 365 days or less",
        "extra": {},
    },
    {
        "rule_id": 87702, "rule_level": 7,
        "rule_description": "SCA: CIS check failed - Root account SSH access not disabled",
        "rule_groups": "sca",
        "full_log": "SCA check 2009 FAILED: Ensure SSH root login is disabled (PermitRootLogin no)",
        "extra": {},
    },
    {
        "rule_id": 5710, "rule_level": 8,
        "rule_description": "Failed SSH authentication from 192.168.1.50 (12 attempts)",
        "rule_groups": "authentication_failed",
        "full_log": "12 authentication failures from 192.168.1.50 in 30 seconds",
        "extra": {},
    },
    {
        "rule_id": 554, "rule_level": 8,
        "rule_description": "FIM: New executable in /tmp",
        "rule_groups": "syscheck,fim",
        "full_log": "New file '/tmp/update.sh' with execute permissions detected",
        "extra": {"syscheck": {"path": "/tmp/update.sh", "event": "added"}},
    },

    # Low
    {
        "rule_id": 5711, "rule_level": 5,
        "rule_description": "User authentication failed - invalid credentials",
        "rule_groups": "authentication_failed",
        "full_log": "pam_unix(sshd:auth): authentication failure; user=admin",
        "extra": {},
    },
    {
        "rule_id": 87703, "rule_level": 4,
        "rule_description": "SCA: Check failed - Audit log rotation not configured",
        "rule_groups": "sca",
        "full_log": "SCA check 4512 FAILED: Ensure audit log storage size is configured",
        "extra": {},
    },
    {
        "rule_id": 555, "rule_level": 5,
        "rule_description": "FIM: Log file deleted in /var/log",
        "rule_groups": "syscheck,fim",
        "full_log": "File '/var/log/auth.log.1' was deleted.",
        "extra": {"syscheck": {"path": "/var/log/auth.log.1", "event": "deleted"}},
    },
    {
        "rule_id": 1002, "rule_level": 3,
        "rule_description": "Unknown problem somewhere in the system",
        "rule_groups": "syslog",
        "full_log": "Unknown message from syslog",
        "extra": {},
    },
]


def _severity_label(level: int) -> str:
    if level >= 13: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    return "low"


def seed_database(db) -> int:
    """
    Direct in-process seed using a SQLAlchemy session.
    Returns the number of alerts created.
    Skips agents/alerts if the table already has rows.
    """
    from models import Alert, Agent
    from attack_mapper import enrich_alert_with_ttp
    from remediation import get_remediation

    # Don't double-seed
    existing = db.query(Alert).count()
    if existing > 0:
        return 0

    now = datetime.utcnow()

    # Create agents first
    for ag in AGENTS:
        if not db.query(Agent).filter(Agent.name == ag["name"]).first():
            db.add(Agent(
                name=ag["name"], ip=ag["ip"], os=ag["os"],
                status="active", last_seen=now,
            ))
    db.commit()

    count = 0
    for i, tpl in enumerate(ALERTS):
        agent = random.choice(AGENTS)
        minutes_ago = random.randint(0, 7 * 24 * 60)
        ts = now - timedelta(minutes=minutes_ago)

        ttp = enrich_alert_with_ttp(tpl["rule_id"], tpl["rule_groups"])
        remediation = get_remediation(tpl["rule_id"], tpl["rule_groups"])
        sev = _severity_label(tpl["rule_level"])

        db.add(Alert(
            agent_name=agent["name"],
            agent_ip=agent["ip"],
            rule_id=tpl["rule_id"],
            rule_description=tpl["rule_description"],
            rule_level=tpl["rule_level"],
            rule_groups=tpl["rule_groups"],
            severity=sev,
            full_log=tpl["full_log"],
            timestamp=ts,
            ttp_id=ttp.get("id"),
            ttp_name=ttp.get("name"),
            ttp_tactic=ttp.get("tactic"),
            remediation=remediation,
            extra=json.dumps(tpl.get("extra", {})),
        ))
        count += 1

    db.commit()
    return count


def seed_via_http():
    """Standalone seeder - uses HTTP to post alerts. Run from outside the container."""
    import requests

    print(f"Seeding WatchTower database at {API}")
    print("   (Make sure the backend is running: docker-compose up)\n")

    now = datetime.utcnow()
    count = 0

    for i, alert_template in enumerate(ALERTS):
        agent = random.choice(AGENTS)
        minutes_ago = random.randint(0, 7 * 24 * 60)
        ts = (now - timedelta(minutes=minutes_ago)).isoformat()

        payload = {
            **alert_template,
            "agent_name": agent["name"],
            "agent_ip":   agent["ip"],
            "timestamp":  ts,
        }

        try:
            resp = requests.post(f"{API}/api/ingest/alert", json=payload, timeout=10)
            if resp.ok:
                print(f"  [OK] [{i+1}/{len(ALERTS)}] {alert_template['rule_description'][:60]}")
                count += 1
            else:
                print(f"  [FAIL] {resp.status_code} - {resp.text}")
        except requests.ConnectionError:
            print(f"\nCannot connect to {API}")
            print("   Run `docker-compose up` first, then try again.\n")
            break

        time.sleep(0.1)

    print(f"\nSeeded {count}/{len(ALERTS)} alerts across {len(AGENTS)} agents.")
    print("   Open http://localhost:3000 to see the dashboard.\n")


if __name__ == "__main__":
    seed_via_http()
