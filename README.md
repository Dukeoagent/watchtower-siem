# 👁 WatchTower SIEM

> Open-source endpoint SIEM powered by Wazuh. CrowdStrike Falcon-style dashboard.
> File Integrity Monitoring · Malware Detection · Config Assessment · MITRE ATT&CK mapping.

![Stack](https://img.shields.io/badge/stack-Wazuh%20%2B%20FastAPI%20%2B%20React-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What This Is

WatchTower is a self-hosted Security Information & Event Management (SIEM) system.

**It does three things:**
1. **Collects** security events from your endpoints (servers, laptops, VMs) via Wazuh agents
2. **Enriches** every alert with MITRE ATT&CK Tactics, Techniques & Procedures (TTPs) and remediation suggestions
3. **Displays** everything in a real-time dark dashboard, and **emails you** when something critical happens

---

## Architecture

```
  [Your Endpoints]              [WatchTower Server]
  ┌─────────────┐               ┌──────────────────────────────────┐
  │ Wazuh Agent │──alerts.json──► alert_processor.py               │
  │  - FIM      │               │   ↓                               │
  │  - SCA      │               │ attack_mapper.py (MITRE ATT&CK)  │
  │  - Rootkit  │               │   ↓                               │
  │  - ClamAV   │               │ FastAPI Backend (port 8000)       │
  └─────────────┘               │   ↓              ↓               │
                                 │ SQLite DB    WebSocket           │
                                 │   ↓              ↓               │
                                 │ REST API    React Dashboard       │
                                 │             (port 3000)          │
                                 │   ↓                               │
                                 │ Email Alerts (SMTP)              │
                                 └──────────────────────────────────┘
```

---

## Quick Start (5 minutes)

### Step 1 — Prerequisites

Install on your server (Linux recommended):
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- Git

### Step 2 — Get the code

```bash
git clone https://github.com/YOUR_USERNAME/siem-toolkit.git
cd siem-toolkit
```

### Step 3 — Configure email (optional but recommended)

```bash
cp .env.example .env
nano .env   # or open with any text editor
```

Fill in your SMTP details. For Gmail, see the comments in `.env.example`.

### Step 4 — Start everything

```bash
docker-compose up --build
```

Wait about 2 minutes for the first build. After that it starts in seconds.

### Step 5 — Open the dashboard

🌐 **http://localhost:3000**

API docs available at: http://localhost:8000/docs

### Step 6 — Load demo data (no agent needed)

```bash
cd backend
pip3 install requests
python3 seed_alerts.py
```

This seeds 40 realistic alerts so you can explore the dashboard immediately.

---

## Installing Sensors on Endpoints

### Linux / Ubuntu / Debian

```bash
# Replace with your WatchTower server's IP or hostname
bash <(curl -s http://YOUR_SERVER_IP:8000/install/linux) --server YOUR_SERVER_IP

# Or download and run manually:
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/siem-toolkit/main/sensors/install-linux.sh
sudo bash install-linux.sh --server YOUR_SERVER_IP
```

### Windows (PowerShell — run as Administrator)

```powershell
# Replace with your WatchTower server's IP or hostname
iwr http://YOUR_SERVER_IP:8000/install/windows | iex

# Or download and run manually:
.\sensors\install-windows.ps1 -Server YOUR_SERVER_IP
```

### What the sensor installs

| Component | Purpose |
|-----------|---------|
| **Wazuh Agent** | Core sensor — monitors files, logs, config |
| **ClamAV** | Antivirus / malware scanner (signature-based) |
| **WatchTower Forwarder** | Python script that forwards Wazuh alerts to central server |
| **Systemd / Task Scheduler** | Keeps the forwarder running on reboots |

---

## Dashboard Pages

| Page | What you see |
|------|-------------|
| **Overview** | KPI cards, 24h alert timeline, recent alerts table |
| **Alerts** | Full searchable/filterable alert history with detail modal |
| **Endpoints** | All monitored machines, their status, and alert counts |
| **ATT&CK Map** | MITRE ATT&CK heatmap showing which tactics/techniques fired |
| **File Integrity** | Every monitored file change (modified/added/deleted) |
| **Settings** | Email notification config + test email button |

---

## Detection Capabilities

### File Integrity Monitoring (FIM)
- Real-time monitoring of `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/boot` (Linux)
- `C:\Windows\System32`, `C:\Program Files` (Windows)
- Detects: modified files, new files, deleted files
- Captures: old hash, new hash, file owner, permissions

### Malware Detection (Signature-Based)
- **ClamAV** antivirus — updated daily via `freshclam`
- **YARA rules** in `signatures/yara/` — add your own
- **Hash-based** detection — add known-bad hashes to `signatures/hashes.csv`

### Security Configuration Assessment
- CIS Benchmark checks run every 12 hours
- Fails appear as alerts with remediation suggestions

### Rootkit Detection
- Wazuh `rootcheck` module scans for hidden processes, files, and ports

### Vulnerability Detection
- CVE scanning against installed packages
- Severity ratings and fix versions shown in alerts

---

## Email Alerts

1. Open the dashboard → **Settings**
2. Enter your email address
3. Choose minimum severity level (recommended: High)
4. Toggle which alert types to send
5. Click **Save Settings**
6. Click **Send Test Email** to verify it works

Each email includes:
- Alert severity and description
- Affected endpoint name + IP
- MITRE ATT&CK technique
- Raw log excerpt
- **Step-by-step remediation instructions**

---

## Adding Custom Detection Rules

### YARA Rules (for malware detection)
```bash
# Add a .yar file to:
signatures/yara/your-rule.yar

# Example rule:
rule SuspiciousScript {
    strings:
        $cmd = "base64 -d" ascii
        $dl  = "curl http://" ascii
    condition:
        all of them
}
```

### Custom Wazuh Rules
Edit `wazuh-config/local_rules.xml`. Wazuh rule format:
```xml
<rule id="100001" level="10">
    <if_group>syscheck</if_group>
    <match>/etc/cron.d</match>
    <description>New cron job added — potential persistence</description>
    <group>fim,persistence</group>
</rule>
```

---

## Project Structure

```
siem-toolkit/
├── backend/
│   ├── main.py             # FastAPI app — all endpoints
│   ├── models.py           # Database table definitions
│   ├── database.py         # SQLite/PostgreSQL connection
│   ├── attack_mapper.py    # MITRE ATT&CK TTP enrichment
│   ├── remediation.py      # Per-alert fix suggestions
│   ├── emailer.py          # HTML email notifications
│   ├── alert_processor.py  # Wazuh alerts.json forwarder
│   ├── seed_alerts.py      # Demo data generator
│   └── requirements.txt
├── dashboard/
│   └── src/
│       ├── App.jsx
│       ├── api.js          # All API calls in one place
│       ├── pages/          # One file per page
│       └── components/     # Sidebar, Topbar
├── sensors/
│   ├── install-linux.sh    # One-command Linux installer
│   └── install-windows.ps1 # One-command Windows installer
├── wazuh-config/           # Wazuh manager config files
├── signatures/yara/        # YARA malware detection rules
├── docker-compose.yml      # Start everything with one command
└── .env.example            # Configuration template
```

---

## Troubleshooting

**Dashboard shows "No alerts yet"**
→ Run `python3 backend/seed_alerts.py` to load demo data.

**"Cannot connect to backend"**
→ Make sure `docker-compose up` is running. Check with `docker ps`.

**Emails not sending**
→ Check your `.env` SMTP settings. For Gmail, make sure you're using an App Password.
→ Click "Send Test Email" in Settings for a specific error message.

**Sensor not appearing in Endpoints**
→ Verify the sensor can reach port 8000 and 1514 on your WatchTower server.
→ Check firewall: `sudo ufw allow 8000` and `sudo ufw allow 1514`.

---

## License

MIT — use freely, build on it, contribute back.
