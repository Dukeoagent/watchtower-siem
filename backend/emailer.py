"""
WatchTower SIEM - Email Notification Service
=============================================
Sends beautiful HTML alert emails to the admin.
Supports SMTP (Gmail, Outlook, any provider) and SendGrid.

Configure via .env:
  EMAIL_PROVIDER=smtp          # smtp | sendgrid
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USER=you@gmail.com
  SMTP_PASS=your-app-password  # For Gmail: use App Passwords, not your real password
  SENDGRID_API_KEY=SG.xxxxx    # Only if EMAIL_PROVIDER=sendgrid
  EMAIL_FROM=alerts@yourdomain.com
"""

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#ff2b2b",
    "high":     "#ff8c00",
    "medium":   "#ffd600",
    "low":      "#00d4ff",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
}


def _build_html(alert: dict) -> str:
    """Build a dark-themed HTML email for an alert."""
    sev = alert.get("severity", "low")
    color = SEVERITY_COLORS.get(sev, "#aaa")
    icon = SEVERITY_ICONS.get(sev, "⚪")
    ts = alert.get("timestamp", datetime.utcnow().isoformat())

    ttp_section = ""
    if alert.get("ttp_id"):
        ttp_section = f"""
        <tr>
          <td style="padding:8px 12px; color:#8892a4; font-size:13px;">MITRE ATT&CK</td>
          <td style="padding:8px 12px; color:#e8eaf0; font-size:13px;">
            <span style="background:#1e2a3a; color:#00d4ff; padding:2px 8px;
                         border-radius:4px; font-family:monospace;">
              {alert['ttp_id']}
            </span>
            {alert.get('ttp_name', '')}
            <span style="color:#8892a4;"> — {alert.get('ttp_tactic', '')}</span>
          </td>
        </tr>"""

    remediation = alert.get("remediation", "")
    remediation_section = ""
    if remediation:
        remediation_section = f"""
        <div style="background:#0d1a2d; border-left:3px solid #00ff94; border-radius:4px;
                    padding:16px 20px; margin-top:20px;">
          <div style="color:#00ff94; font-size:12px; font-weight:700; letter-spacing:1px;
                      margin-bottom:8px; font-family:'Courier New',monospace;">
            ✅ SUGGESTED REMEDIATION
          </div>
          <div style="color:#b8c5d6; font-size:13px; line-height:1.6;">{remediation}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#080a0f;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:640px;margin:30px auto;background:#0d1117;border-radius:10px;
              overflow:hidden;border:1px solid #1e2533;">

    <!-- Header -->
    <div style="background:#080a0f;padding:24px 28px;border-bottom:1px solid #1e2533;
                display:flex;align-items:center;">
      <div style="font-size:22px;font-weight:900;color:#e8eaf0;letter-spacing:2px;">
        👁 WATCHTOWER
      </div>
      <div style="margin-left:auto;background:{color}22;color:{color};
                  padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;
                  letter-spacing:1px;border:1px solid {color}44;">
        {icon} {sev.upper()} ALERT
      </div>
    </div>

    <!-- Alert Title -->
    <div style="padding:24px 28px 0;">
      <div style="border-left:3px solid {color};padding-left:16px;">
        <div style="color:#8892a4;font-size:11px;letter-spacing:1.5px;
                    text-transform:uppercase;margin-bottom:6px;">
          Security Alert #{alert.get('id', '—')}
        </div>
        <div style="color:#e8eaf0;font-size:18px;font-weight:600;line-height:1.4;">
          {alert.get('rule_description', 'Security Event')}
        </div>
      </div>
    </div>

    <!-- Details Table -->
    <div style="padding:20px 28px;">
      <table style="width:100%;border-collapse:collapse;">
        <tr style="border-bottom:1px solid #1e2533;">
          <td style="padding:8px 12px;color:#8892a4;font-size:13px;width:130px;">Endpoint</td>
          <td style="padding:8px 12px;color:#e8eaf0;font-size:13px;">
            {alert.get('agent_name', '—')}
            <span style="color:#8892a4;margin-left:8px;">{alert.get('agent_ip', '')}</span>
          </td>
        </tr>
        <tr style="border-bottom:1px solid #1e2533;">
          <td style="padding:8px 12px;color:#8892a4;font-size:13px;">Rule ID</td>
          <td style="padding:8px 12px;color:#e8eaf0;font-size:13px;font-family:monospace;">
            #{alert.get('rule_id', '—')} — Level {alert.get('rule_level', '—')}
          </td>
        </tr>
        <tr style="border-bottom:1px solid #1e2533;">
          <td style="padding:8px 12px;color:#8892a4;font-size:13px;">Time (UTC)</td>
          <td style="padding:8px 12px;color:#e8eaf0;font-size:13px;">{ts}</td>
        </tr>
        {ttp_section}
      </table>
    </div>

    <!-- Raw Log -->
    <div style="margin:0 28px 20px;">
      <div style="background:#080a0f;border:1px solid #1e2533;border-radius:6px;padding:14px 16px;">
        <div style="color:#8892a4;font-size:11px;letter-spacing:1px;
                    text-transform:uppercase;margin-bottom:8px;">Raw Log</div>
        <div style="color:#6b8aad;font-size:12px;font-family:'Courier New',monospace;
                    white-space:pre-wrap;word-break:break-all;line-height:1.5;">
          {alert.get('full_log', '')[:800]}
        </div>
      </div>
    </div>

    <!-- Remediation -->
    <div style="margin:0 28px 28px;">
      {remediation_section}
    </div>

    <!-- Footer -->
    <div style="background:#080a0f;padding:16px 28px;border-top:1px solid #1e2533;
                color:#4a5568;font-size:11px;">
      WatchTower SIEM · Open Source Endpoint Security ·
      <a href="http://localhost:3000" style="color:#00d4ff;text-decoration:none;">
        View Dashboard
      </a>
    </div>
  </div>
</body>
</html>"""


def _send_via_smtp(to_email: str, subject: str, html_body: str) -> dict:
    """Send email using SMTP (works with Gmail, Outlook, etc.)"""
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    from_addr = os.getenv("EMAIL_FROM", user)

    if not user or not password:
        logger.warning("SMTP credentials not set. Set SMTP_USER and SMTP_PASS in .env")
        return {"status": "skipped", "reason": "SMTP credentials not configured"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"WatchTower SIEM <{from_addr}>"
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(host, port) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, password)
            smtp.sendmail(from_addr, to_email, msg.as_string())
        logger.info(f"Email sent to {to_email}: {subject}")
        return {"status": "sent"}
    except Exception as e:
        logger.error(f"SMTP error: {e}")
        return {"status": "error", "reason": str(e)}


def send_alert_email(to_email: str, alert: dict) -> dict:
    """Main function — send a security alert email."""
    sev = alert.get("severity", "low").upper()
    icon = SEVERITY_ICONS.get(alert.get("severity", "low"), "⚪")
    subject = (
        f"{icon} [{sev}] {alert.get('rule_description', 'Security Alert')} "
        f"on {alert.get('agent_name', 'Unknown Host')}"
    )
    html = _build_html(alert)
    return _send_via_smtp(to_email, subject, html)


def send_test_email(to_email: str) -> dict:
    """Send a test email to verify the config works."""
    test_alert = {
        "id": "TEST-001",
        "severity": "medium",
        "rule_description": "WatchTower Test Alert — Email is working!",
        "agent_name": "test-host",
        "agent_ip": "192.168.1.100",
        "rule_id": 999,
        "rule_level": 7,
        "ttp_id": "T1078",
        "ttp_name": "Valid Accounts",
        "ttp_tactic": "Defense Evasion",
        "remediation": "This is a test alert. No action needed. Your email notifications are configured correctly.",
        "timestamp": datetime.utcnow().isoformat(),
        "full_log": "Test log entry generated by WatchTower SIEM to verify email delivery.",
    }
    return send_alert_email(to_email, test_alert)
