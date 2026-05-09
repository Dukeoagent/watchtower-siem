# 👁 WatchTower SIEM

> Open-source endpoint SIEM with a CrowdStrike Falcon-style dashboard.
> File Integrity Monitoring · Malware Detection · Config Assessment · MITRE ATT&CK mapping · Live demo mode.

![Stack](https://img.shields.io/badge/stack-FastAPI%20%2B%20React%20%2B%20Wazuh-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What This Is

WatchTower is a self-hosted Security Information & Event Management (SIEM) system you can spin up in one command.

**It does three things:**
1. **Collects** security events from your endpoints via Wazuh-compatible agents
2. **Enriches** every alert with MITRE ATT&CK Tactics, Techniques & Procedures (TTPs) and remediation suggestions
3. **Displays** everything in a real-time dark-themed dashboard, and **emails** you when something critical happens

A built-in **DEMO** mode lets viewers (e.g. classmates on their phones via an ngrok link) trigger live alerts that show up on every connected dashboard with their actual geo-location enriched in.

---

## Architecture

```
  [Endpoints / Demo Visitors]      [WatchTower Server]
  ┌─────────────────────────┐      ┌────────────────────────────────────┐
  │ Wazuh Agent             │──┐   │ FastAPI Backend (port 8000)        │
  │   FIM · SCA · Rootkit   │  │   │   ↓                                 │
  │   ClamAV                │  │   │ attack_mapper.py (MITRE ATT&CK)    │
  │ Browser DEMO buttons    │──┼──►│   ↓                                 │
  └─────────────────────────┘  │   │ SQLite DB ←→ WebSocket             │
                                │   │   ↓              ↓                  │
                                │   │ REST API   React Dashboard         │
                                │   │             (port 3000, nginx)     │
                                │   │   ↓                                 │
                                │   │ Email Alerts (SMTP)                │
                                │   └────────────────────────────────────┘
```

---

## Quick Start (5 minutes)

### Step 1 — Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- Git

### Step 2 — Get the code

```bash
git clone https://github.com/Dukeoagent/watchtower-siem.git
cd watchtower-siem
```

### Step 3 — (Optional) Configure email alerts

```bash
cp .env.example .env
# Open .env in any editor and fill in SMTP settings (Gmail App Password works)
```

You can skip this — the stack runs fine without email and emailing is disabled gracefully when SMTP isn't set.

### Step 4 — Start everything

```bash
docker-compose up --build
```

First build takes ~2 minutes. After that it boots in seconds.

### Step 5 — Open the dashboard

🌐 **http://localhost:3000**

API docs: **http://localhost:8000/docs**

That's it. The backend auto-seeds 19 demo alerts on first run so the dashboard isn't empty.

---

## Sharing the Dashboard Publicly (ngrok)

To show the dashboard to someone on a different network — over a phone, projector, or another laptop — point an ngrok tunnel at port 3000:

```bash
ngrok http 3000
```

Share the `https://*.ngrok-free.app` URL ngrok prints. Anyone who opens it sees the same dashboard with the same data, and can use the **DEMO** button (top-right, next to the bell) to trigger live alerts that pop up in real time on every viewer's screen.

---

## Demo Mode (live alert injection)

Click the orange **DEMO** button in the top bar to open the demo panel and pick a severity:

| Button   | Severity | What happens                                                         |
|----------|----------|----------------------------------------------------------------------|
| Critical | level 13 | Mock ransomware-style alert, ATT&CK T1486                            |
| High     | level 11 | Suspicious script execution, ATT&CK T1059                            |
| Medium   | level 8  | File / directory discovery, ATT&CK T1083                             |
| Low      | level 4  | Remote system discovery, ATT&CK T1018                                |

Each click hits `/api/demo/alert?severity=…`, which:
1. Reads the visitor's real IP from `X-Forwarded-For` (set by nginx and ngrok)
2. Looks up the IP via `ip-api.com` to get **ISP**, **city**, **region**, **country**
3. Creates a real `Alert` row in the DB, MITRE-enriched and remediation-tagged
4. Broadcasts it over the WebSocket so every connected dashboard sees it instantly

Perfect for showing classmates how the live alert pipeline works without installing an actual agent.

---

## Dashboard Pages

| Page             | What you see                                                                |
|------------------|------------------------------------------------------------------------------|
| **Overview**     | KPI cards, 24h alert timeline, severity donut, recent alerts table          |
| **Alerts**       | Full searchable & filterable alert history with detail modal                |
| **Endpoints**    | All monitored machines, their status, OS, and alert counts                  |
| **ATT&CK Map**   | MITRE ATT&CK heatmap grouped by tactic                                      |
| **File Integrity** | FIM events (modified / added / deleted files)                              |
| **Settings**     | Email notification config + test-email button                               |

The MITRE ATT&CK column shows the **technique name** in a cyan badge with the technique ID (e.g. `T1059`) directly below it.

---

## Detection Capabilities (with real Wazuh agents)

### File Integrity Monitoring (FIM)
- Real-time monitoring of `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/boot` (Linux) and `C:\Windows\System32`, `C:\Program Files` (Windows)
- Captures: old hash, new hash, owner, permissions, event type

### Malware Detection (Signature-Based)
- **ClamAV** antivirus updated daily via `freshclam`
- **YARA rules** in `signatures/yara/` — drop in your own
- **Hash-based** detection via `signatures/hashes.csv`

### Security Configuration Assessment
- CIS Benchmark checks every 12h, fails surface as alerts with remediation

### Rootkit & Vulnerability Detection
- Wazuh `rootcheck` for hidden processes/files/ports
- CVE scanning with severity ratings and fix versions

---

## Email Alerts

1. Open **Settings** in the dashboard
2. Enter your email and minimum severity
3. Toggle which alert types should email you
4. Save → click **Send Test Email** to verify

Each email includes severity, endpoint, ATT&CK technique, raw log excerpt, and **remediation steps**.

If SMTP isn't configured the test endpoint returns `{"status":"skipped","reason":"SMTP credentials not configured"}` instead of crashing.

---

## Installing Real Sensors on Endpoints

### Linux

```bash
bash <(curl -s http://YOUR_SERVER_IP:8000/install/linux) --server YOUR_SERVER_IP
# or:
sudo bash sensors/install-linux.sh --server YOUR_SERVER_IP
```

### Windows (PowerShell as Administrator)

```powershell
iwr http://YOUR_SERVER_IP:8000/install/windows | iex
# or:
.\sensors\install-windows.ps1 -Server YOUR_SERVER_IP
```

### What the sensor installs

| Component                    | Purpose                                                |
|------------------------------|--------------------------------------------------------|
| **Wazuh Agent**              | Core sensor — files, logs, configuration               |
| **ClamAV**                   | Antivirus / malware scanner                            |
| **WatchTower Forwarder**     | Forwards Wazuh alerts to the central API               |
| **systemd / Task Scheduler** | Keeps the forwarder alive on reboots                   |

---

## Project Structure

```
watchtower-siem/
├── backend/
│   ├── main.py             # FastAPI app — all REST + WebSocket endpoints
│   ├── models.py           # SQLAlchemy table definitions
│   ├── database.py         # SQLite/Postgres connection
│   ├── attack_mapper.py    # MITRE ATT&CK TTP enrichment
│   ├── remediation.py      # Per-alert fix suggestions
│   ├── emailer.py          # HTML email notifications
│   ├── alert_processor.py  # Wazuh alerts.json forwarder (runs on endpoints)
│   ├── seed_alerts.py      # Auto-seed 19 realistic demo alerts on first boot
│   ├── Dockerfile
│   └── requirements.txt
├── dashboard/
│   ├── src/
│   │   ├── main.jsx
│   │   ├── App.jsx
│   │   ├── api.js          # All API calls + WebSocket helper
│   │   ├── pages/          # Overview, Alerts, Agents, ATTACK, FIM, Settings
│   │   └── components/     # Sidebar, Topbar (with DEMO button)
│   ├── nginx.conf          # Proxies /api and /ws to the backend
│   ├── vite.config.js
│   └── Dockerfile          # Multi-stage: build with Node, serve with nginx
├── sensors/
│   ├── install-linux.sh
│   └── install-windows.ps1
├── wazuh-config/           # Wazuh manager config files
├── signatures/yara/        # YARA malware detection rules
├── docker-compose.yml      # backend + dashboard, one command
└── .env.example            # SMTP / config template
```

---

## Adding Custom Detection Rules

### YARA (malware)
```bash
# Drop a .yar file into signatures/yara/
rule SuspiciousScript {
    strings:
        $cmd = "base64 -d" ascii
        $dl  = "curl http://" ascii
    condition:
        all of them
}
```

### Wazuh rules
Edit `wazuh-config/local_rules.xml`:
```xml
<rule id="100001" level="10">
    <if_group>syscheck</if_group>
    <match>/etc/cron.d</match>
    <description>New cron job — potential persistence</description>
    <group>fim,persistence</group>
</rule>
```

---

## Troubleshooting

**Dashboard shows "No results found" when searching**
→ That's the normal empty-search state. Clear the filter to see all alerts.

**Containers won't start / port already in use**
→ Stop whatever owns 3000 or 8000, or change the host port in `docker-compose.yml`.

**`docker-compose up` fails with permission errors on `./data`**
→ Delete the `./data/` folder and re-run; it'll be recreated by the container.

**DEMO button shows "Unknown" location**
→ ip-api.com couldn't geo-locate the IP (private network or rate-limited). The alert still fires; only the geo enrichment is skipped.

**Emails not sending**
→ Check `.env` SMTP settings. For Gmail use an App Password, not your account password. Click **Send Test Email** in Settings for a specific error.

**Sensor not appearing in Endpoints**
→ Verify the sensor reaches port 8000 (and 1514 for native Wazuh). On Linux: `sudo ufw allow 8000`.

---

## License

MIT — use freely, build on it, contribute back.
