# ============================================================
#  WatchTower SIEM — Windows Sensor Installer (PowerShell)
#  Run in PowerShell as Administrator:
#
#  iwr http://YOUR_WATCHTOWER_IP:8000/install/windows | iex
#  OR
#  .\install-windows.ps1 -Server YOUR_WATCHTOWER_IP
# ============================================================

param(
    [string]$Server = "localhost",
    [string]$WazuhVersion = "4.7.3"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║    WatchTower SIEM — Windows Sensor           ║" -ForegroundColor Cyan
Write-Host "║    Server: $Server" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Check Administrator ───────────────────────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ Run PowerShell as Administrator!" -ForegroundColor Red
    exit 1
}

# ── Download & install Wazuh agent ───────────────────────────────────────────
Write-Host "📦 Downloading Wazuh agent v$WazuhVersion..." -ForegroundColor Yellow
$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
$msiPath = "$env:TEMP\wazuh-agent.msi"

Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

Write-Host "🔐 Installing Wazuh agent..." -ForegroundColor Yellow
Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /quiet WAZUH_MANAGER=`"$Server`"" -Wait

# ── Configure agent ───────────────────────────────────────────────────────────
Write-Host "⚙️  Configuring FIM & SCA..." -ForegroundColor Yellow
$configPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

$config = @"
<ossec_config>
  <client>
    <server>
      <address>$Server</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- File Integrity Monitoring — Windows -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>

    <!-- Monitor critical Windows paths in real-time -->
    <directories realtime="yes" check_all="yes">%WINDIR%\System32</directories>
    <directories realtime="yes" check_all="yes">%WINDIR%\SysWOW64</directories>
    <directories realtime="yes" check_all="yes">%PROGRAMFILES%</directories>
    <directories check_all="yes">%USERPROFILE%\Desktop</directories>
    <directories check_all="yes">%USERPROFILE%\Downloads</directories>

    <ignore>%WINDIR%\System32\LogFiles</ignore>
    <ignore>%WINDIR%\System32\wbem\Logs</ignore>
    <ignore>%WINDIR%\System32\config</ignore>
  </syscheck>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <windows_apps>yes</windows_apps>
    <windows_malware>yes</windows_malware>
  </rootcheck>

  <!-- Security Configuration Assessment -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>

  <!-- Windows Event Log collection -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156]</query>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
"@

Set-Content -Path $configPath -Value $config -Encoding UTF8

# ── Install Python + forwarder ────────────────────────────────────────────────
Write-Host "🐍 Installing Python forwarder..." -ForegroundColor Yellow

# Check if Python is available
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "   Python not found — downloading..." -ForegroundColor Gray
    $pyUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    $pyPath = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri $pyUrl -OutFile $pyPath -UseBasicParsing
    Start-Process $pyPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
}

& python -m pip install --quiet requests

# Write forwarder script
$forwarderScript = @"
import json, time, requests, sys
from pathlib import Path

ALERTS = r'C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json'
API = 'http://${Server}:8000'

def parse(raw):
    try: a = json.loads(raw.strip())
    except: return None
    r = a.get('rule', {})
    ag = a.get('agent', {})
    return {
        'agent_name': ag.get('name','windows-host'),
        'agent_ip': ag.get('ip','0.0.0.0'),
        'rule_id': int(r.get('id',0)),
        'rule_description': r.get('description',''),
        'rule_level': int(r.get('level',0)),
        'rule_groups': ','.join(r.get('groups',[])),
        'full_log': a.get('full_log',''),
        'timestamp': a.get('timestamp'),
        'extra': {'syscheck': a.get('syscheck',{})},
    }

p = Path(ALERTS)
while not p.exists():
    time.sleep(5)

with open(ALERTS) as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line: time.sleep(0.5); continue
        payload = parse(line)
        if payload:
            try: requests.post(f'{API}/api/ingest/alert', json=payload, timeout=10)
            except: pass
"@

$forwarderPath = "C:\Program Files (x86)\ossec-agent\watchtower-forwarder.py"
Set-Content -Path $forwarderPath -Value $forwarderScript -Encoding UTF8

# Create a Windows scheduled task to run the forwarder
$action  = New-ScheduledTaskAction -Execute "python" -Argument $forwarderPath
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "WatchTower Forwarder" -Action $action `
    -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null

# ── Start Wazuh agent ─────────────────────────────────────────────────────────
Write-Host "🚀 Starting Wazuh agent..." -ForegroundColor Yellow
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Set-Service  -Name "WazuhSvc" -StartupType Automatic

# Start forwarder task
Start-ScheduledTask -TaskName "WatchTower Forwarder"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ WatchTower sensor installed successfully!               ║" -ForegroundColor Green
Write-Host "║  Dashboard: http://$Server`:3000                         ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
