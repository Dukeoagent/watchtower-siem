#!/bin/bash
# ============================================================
#  WatchTower SIEM — Linux Sensor Installer
#  Installs Wazuh agent + WatchTower forwarder
#
#  Usage:
#    curl -sO https://raw.githubusercontent.com/YOUR_USER/siem-toolkit/main/sensors/install-linux.sh
#    sudo bash install-linux.sh --server YOUR_WATCHTOWER_IP
#
#  Or one-liner:
#    bash <(curl -s http://YOUR_WATCHTOWER_IP:8000/install/linux)
# ============================================================

set -e

# ── Parse args ────────────────────────────────────────────────────────────────
WATCHTOWER_IP="localhost"
WAZUH_VERSION="4.7.3"

while [[ $# -gt 0 ]]; do
  case $1 in
    --server) WATCHTOWER_IP="$2"; shift 2 ;;
    --version) WAZUH_VERSION="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║    WatchTower SIEM — Sensor Installer         ║"
echo "║    Target server: $WATCHTOWER_IP              "
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ── Check OS ──────────────────────────────────────────────────────────────────
OS=""
if   [[ -f /etc/debian_version ]]; then OS="debian"
elif [[ -f /etc/redhat-release ]]; then OS="redhat"
elif [[ -f /etc/arch-release ]];   then OS="arch"
else
  echo "❌ Unsupported OS. Tested on Ubuntu/Debian/CentOS/RHEL."
  exit 1
fi

echo "✅ Detected OS family: $OS"

# ── Install dependencies ──────────────────────────────────────────────────────
echo "📦 Installing dependencies..."
if [[ "$OS" == "debian" ]]; then
  apt-get update -qq
  apt-get install -y -qq curl wget gnupg2 python3 python3-pip clamav clamav-daemon
else
  yum install -y -q curl wget python3 python3-pip clamav clamd
fi

# ── Install Wazuh agent ───────────────────────────────────────────────────────
echo "🔐 Installing Wazuh agent v${WAZUH_VERSION}..."

if [[ "$OS" == "debian" ]]; then
  # Add Wazuh repo
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    | tee /etc/apt/sources.list.d/wazuh.list > /dev/null
  apt-get update -qq
  WAZUH_MANAGER="${WATCHTOWER_IP}" apt-get install -y -qq wazuh-agent
else
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
  WAZUH_MANAGER="${WATCHTOWER_IP}" yum install -y wazuh-agent
fi

# Configure agent to point at WatchTower server
sed -i "s|<address>.*</address>|<address>${WATCHTOWER_IP}</address>|g" /var/ossec/etc/ossec.conf

# ── Enable FIM, SCA, Malware detection ────────────────────────────────────────
echo "⚙️  Configuring FIM, SCA, ClamAV integration..."

# Copy enhanced config
cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>WATCHTOWER_IP_PLACEHOLDER</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu20, ubuntu20.04</config-profile>
  </client>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>

    <!-- Critical system files — monitor in real-time -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>
    <directories realtime="yes" check_all="yes">/bin,/sbin,/usr/bin,/usr/sbin</directories>
    <directories realtime="yes" check_all="yes">/boot</directories>

    <!-- Ignore noisy dirs -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
  </syscheck>

  <!-- Rootkit detection -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
  </rootcheck>

  <!-- Security Configuration Assessment (CIS benchmarks) -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <!-- ClamAV malware scanning via localfile -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/clamav/clamav.log</location>
  </localfile>

  <!-- Vulnerability detection -->
  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <feed name="ubuntu-18">
      <disabled>no</disabled>
      <update_interval>1h</update_interval>
    </feed>
  </wodle>

  <!-- Log collection -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>
</ossec_config>
EOF

# Replace placeholder with actual server IP
sed -i "s|WATCHTOWER_IP_PLACEHOLDER|${WATCHTOWER_IP}|g" /var/ossec/etc/ossec.conf

# ── Install WatchTower forwarder ──────────────────────────────────────────────
echo "📡 Installing WatchTower alert forwarder..."

pip3 install -q requests

# Download the forwarder script
cat > /usr/local/bin/watchtower-forwarder.py << FORWARDER
#!/usr/bin/env python3
"""WatchTower forwarder — tails Wazuh alerts and posts to central server."""
import json, time, requests, sys, logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wt-forwarder")
ALERTS = "/var/ossec/logs/alerts/alerts.json"
API = "http://${WATCHTOWER_IP}:8000"

def parse(raw):
    try: a = json.loads(raw.strip())
    except: return None
    r = a.get("rule", {})
    ag = a.get("agent", {})
    return {
        "agent_name": ag.get("name","unknown"),
        "agent_ip": ag.get("ip","0.0.0.0"),
        "rule_id": int(r.get("id",0)),
        "rule_description": r.get("description",""),
        "rule_level": int(r.get("level",0)),
        "rule_groups": ",".join(r.get("groups",[])),
        "full_log": a.get("full_log",""),
        "timestamp": a.get("timestamp"),
        "extra": {"syscheck": a.get("syscheck",{})},
    }

p = Path(ALERTS)
while not p.exists():
    logger.info(f"Waiting for {ALERTS}...")
    time.sleep(5)
logger.info(f"Forwarding {ALERTS} → {API}")
with open(ALERTS) as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line: time.sleep(0.5); continue
        payload = parse(line)
        if payload:
            try: requests.post(f"{API}/api/ingest/alert", json=payload, timeout=10)
            except Exception as e: logger.error(e)
FORWARDER

chmod +x /usr/local/bin/watchtower-forwarder.py

# Create systemd service for the forwarder
cat > /etc/systemd/system/watchtower-forwarder.service << EOF
[Unit]
Description=WatchTower SIEM Alert Forwarder
After=wazuh-agent.service network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/watchtower-forwarder.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ── Start services ────────────────────────────────────────────────────────────
echo "🚀 Starting services..."
systemctl daemon-reload
systemctl enable --now wazuh-agent
systemctl enable --now watchtower-forwarder

# ── Update ClamAV signatures ──────────────────────────────────────────────────
echo "🦠 Updating ClamAV signatures..."
freshclam --quiet || true

# Schedule daily ClamAV scan
echo "0 2 * * * root clamscan -r / --exclude-dir='^/proc' --exclude-dir='^/sys' \
  --log=/var/log/clamav/clamav.log --quiet" > /etc/cron.d/clamav-scan

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ WatchTower sensor installed successfully!               ║"
echo "║                                                            ║"
echo "║  Wazuh agent:    $(systemctl is-active wazuh-agent)       ║"
echo "║  WT Forwarder:   $(systemctl is-active watchtower-forwarder) ║"
echo "║  Dashboard:      http://${WATCHTOWER_IP}:3000            ║"
echo "╚════════════════════════════════════════════════════════════╝"
