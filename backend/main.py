"""
WatchTower SIEM - FastAPI Backend
=================================
Central server that receives alerts from Wazuh agents,
enriches them with MITRE ATT&CK mappings, stores them,
and serves them to the dashboard.

Author: WatchTower SIEM Toolkit
"""

import asyncio
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager

import requests
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func

from database import SessionLocal, engine, Base
from models import Alert, Agent, NotifyConfig, FIMEvent, SCAResult, Vulnerability
from attack_mapper import enrich_alert_with_ttp
from emailer import send_alert_email, send_test_email
from remediation import get_remediation
from seed_alerts import seed_database

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create DB tables on startup. Seed demo data if database is empty."""
    Base.metadata.create_all(bind=engine)
    logger.info("WatchTower SIEM backend started. DB tables ready.")

    # Auto-seed demo data on first startup so the dashboard isn't empty.
    # Set SEED_DEMO=0 to disable.
    if os.getenv("SEED_DEMO", "1") == "1":
        db = SessionLocal()
        try:
            n = seed_database(db)
            if n > 0:
                logger.info(f"Seeded {n} demo alerts. Visit http://localhost:3000")
            else:
                logger.info("Database already populated — skipping seed.")
        except Exception as e:
            logger.warning(f"Seed failed (non-fatal): {e}")
        finally:
            db.close()

    yield
    logger.info("WatchTower SIEM backend shutting down.")

app = FastAPI(
    title="WatchTower SIEM API",
    description="Open-Source Endpoint SIEM powered by Wazuh",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow the React dashboard (running on port 3000) to call this API.
# Wide-open in dev/demo. Lock down for production behind a proper proxy.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket Manager (for real-time alert push to dashboard) ─────────────────
class ConnectionManager:
    """Manages active WebSocket connections from the dashboard."""
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: dict):
        """Push a new alert to ALL connected dashboard tabs."""
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

# ── Pydantic Input Schemas ────────────────────────────────────────────────────
class IncomingAlert(BaseModel):
    """Shape of alerts posted by the Wazuh forwarder script."""
    agent_name: str
    agent_ip: str
    rule_id: int
    rule_description: str
    rule_level: int           # Wazuh severity 1-15
    rule_groups: str          # e.g. "syscheck,fim"
    full_log: str
    timestamp: Optional[str] = None
    extra: Optional[dict] = {}  # FIM / vuln / SCA extra fields

class NotifyConfigIn(BaseModel):
    email: str
    min_level: int = 10        # Only alert when rule_level >= this
    notify_fim: bool = True
    notify_malware: bool = True
    notify_sca: bool = True
    notify_vuln: bool = True

# ── Helper ────────────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def severity_label(level: int) -> str:
    if level >= 13: return "critical"
    if level >= 10: return "high"
    if level >= 7:  return "medium"
    return "low"


def iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """
    Serialise a UTC datetime as an ISO-8601 string with a trailing 'Z'.
    The Z suffix makes JavaScript's `new Date(...)` correctly convert the
    timestamp into the user's local timezone (e.g. IST) on the frontend.
    Without it, the browser interprets the string as local time and the
    displayed times end up off by the user's UTC offset.
    """
    if dt is None:
        return None
    return dt.isoformat(timespec="seconds") + "Z"


# ── Demo alert templates (per severity) ──────────────────────────────────────
# Each click of a DEMO button on the dashboard fires one of these. Severity →
# rule_level + ATT&CK technique are picked to look like the real thing.
DEMO_TEMPLATES = {
    "critical": {
        "rule_id": 100501,
        "rule_level": 13,
        "rule_groups": "demo,malware,impact",
        "rule_description": "Ransomware-style mass file encryption detected",
        "ttp_id": "T1486", "ttp_name": "Data Encrypted for Impact", "ttp_tactic": "Impact",
        "remediation": "Isolate the host immediately, terminate the suspicious process, "
                       "restore from clean backup. Do NOT pay any ransom.",
    },
    "high": {
        "rule_id": 100502,
        "rule_level": 11,
        "rule_groups": "demo,execution",
        "rule_description": "Suspicious script execution via base64-encoded payload",
        "ttp_id": "T1059", "ttp_name": "Command and Scripting Interpreter", "ttp_tactic": "Execution",
        "remediation": "Review the parent process, kill the offending shell, "
                       "audit recent script execution logs, rotate exposed credentials.",
    },
    "medium": {
        "rule_id": 100503,
        "rule_level": 8,
        "rule_groups": "demo,discovery",
        "rule_description": "Unusual file & directory enumeration detected",
        "ttp_id": "T1083", "ttp_name": "File and Directory Discovery", "ttp_tactic": "Discovery",
        "remediation": "Review which user account performed the scan. "
                       "If unauthorized, lock the account and audit recent logins.",
    },
    "low": {
        "rule_id": 100504,
        "rule_level": 4,
        "rule_groups": "demo,discovery",
        "rule_description": "Remote system discovery — network sweep observed",
        "ttp_id": "T1018", "ttp_name": "Remote System Discovery", "ttp_tactic": "Discovery",
        "remediation": "No immediate action required. Confirm whether the scan "
                       "originated from an authorised vulnerability scanner.",
    },
}


def _client_ip(request: Request) -> str:
    """Extract the real visitor IP, honouring nginx / ngrok forwarding headers."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # First IP in the comma-separated chain is the original client
        return xff.split(",")[0].strip()
    real = request.headers.get("x-real-ip", "")
    if real:
        return real.strip()
    return request.client.host if request.client else "0.0.0.0"


def _is_private_ip(ip: str) -> bool:
    """Cheap check — geo lookup will fail on RFC1918 / loopback so don't bother calling."""
    if not ip or ip == "0.0.0.0":
        return True
    if ip.startswith(("127.", "10.", "192.168.", "169.254.", "::1")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def _geo_lookup(ip: str) -> dict:
    """
    Look up city / region / country / ISP for an IP via ip-api.com (free, no key).
    Returns {} if the IP is private, lookup fails, or we get rate-limited.
    """
    if _is_private_ip(ip):
        return {}
    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,regionName,city,isp,org,query"
        )
        r = requests.get(url, timeout=4)
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "success":
            return {
                "country":      data.get("country") or "",
                "country_code": data.get("countryCode") or "",
                "region":       data.get("regionName") or "",
                "city":         data.get("city") or "",
                "isp":          data.get("isp") or "",
                "org":          data.get("org") or "",
            }
    except Exception as e:
        logger.warning(f"Geo lookup failed for {ip}: {e}")
    return {}

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "time": iso_utc(datetime.utcnow())}


# ── Ingest: Wazuh forwarder posts alerts here ─────────────────────────────────
@app.post("/api/ingest/alert")
async def ingest_alert(payload: IncomingAlert, background_tasks: BackgroundTasks):
    """
    Endpoint called by the sensor's Python forwarder to push Wazuh alerts.
    1. Enriches with MITRE ATT&CK TTP
    2. Persists to DB
    3. Broadcasts via WebSocket to dashboard
    4. Sends email if threshold met
    """
    db = SessionLocal()
    try:
        ts = datetime.utcnow() if not payload.timestamp else datetime.fromisoformat(payload.timestamp)
        ttp = enrich_alert_with_ttp(payload.rule_id, payload.rule_groups)
        remediation = get_remediation(payload.rule_id, payload.rule_groups)
        sev = severity_label(payload.rule_level)

        alert = Alert(
            agent_name=payload.agent_name,
            agent_ip=payload.agent_ip,
            rule_id=payload.rule_id,
            rule_description=payload.rule_description,
            rule_level=payload.rule_level,
            rule_groups=payload.rule_groups,
            severity=sev,
            full_log=payload.full_log,
            timestamp=ts,
            ttp_id=ttp.get("id"),
            ttp_name=ttp.get("name"),
            ttp_tactic=ttp.get("tactic"),
            remediation=remediation,
            extra=json.dumps(payload.extra or {}),
        )
        db.add(alert)

        # Upsert agent record
        agent = db.query(Agent).filter(Agent.name == payload.agent_name).first()
        if not agent:
            agent = Agent(name=payload.agent_name, ip=payload.agent_ip, status="active", last_seen=ts)
            db.add(agent)
        else:
            agent.ip = payload.agent_ip
            agent.status = "active"
            agent.last_seen = ts

        db.commit()
        db.refresh(alert)

        # Build the dict we broadcast to dashboard
        alert_dict = {
            "id": alert.id, "agent_name": alert.agent_name, "agent_ip": alert.agent_ip,
            "rule_id": alert.rule_id, "rule_description": alert.rule_description,
            "rule_level": alert.rule_level, "severity": sev,
            "ttp_id": ttp.get("id"), "ttp_name": ttp.get("name"), "ttp_tactic": ttp.get("tactic"),
            "remediation": remediation, "timestamp": iso_utc(ts), "full_log": payload.full_log,
        }

        # Push to dashboard in background
        background_tasks.add_task(manager.broadcast, {"type": "new_alert", "alert": alert_dict})

        # Send email if configured and threshold met
        cfg = db.query(NotifyConfig).first()
        if cfg and payload.rule_level >= cfg.min_level:
            should_email = any([
                cfg.notify_fim and "syscheck" in payload.rule_groups,
                cfg.notify_malware and "malware" in payload.rule_groups,
                cfg.notify_sca and "sca" in payload.rule_groups,
                cfg.notify_vuln and "vulnerability" in payload.rule_groups,
                payload.rule_level >= 13,  # Always email critical
            ])
            if should_email:
                background_tasks.add_task(
                    send_alert_email, cfg.email, alert_dict
                )

        return {"status": "ingested", "alert_id": alert.id}
    finally:
        db.close()


# ── Alerts ────────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
def list_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    agent: Optional[str] = None,
    days: int = 7,
):
    db = SessionLocal()
    try:
        since = datetime.utcnow() - timedelta(days=days)
        q = db.query(Alert).filter(Alert.timestamp >= since)
        if severity:
            q = q.filter(Alert.severity == severity)
        if agent:
            q = q.filter(Alert.agent_name == agent)
        alerts = q.order_by(Alert.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": a.id, "agent_name": a.agent_name, "agent_ip": a.agent_ip,
                "rule_id": a.rule_id, "rule_description": a.rule_description,
                "rule_level": a.rule_level, "severity": a.severity,
                "ttp_id": a.ttp_id, "ttp_name": a.ttp_name, "ttp_tactic": a.ttp_tactic,
                "remediation": a.remediation, "timestamp": iso_utc(a.timestamp),
                "full_log": a.full_log, "rule_groups": a.rule_groups,
            }
            for a in alerts
        ]
    finally:
        db.close()


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    db = SessionLocal()
    try:
        a = db.query(Alert).filter(Alert.id == alert_id).first()
        if not a:
            raise HTTPException(404, "Alert not found")
        return {
            "id": a.id, "agent_name": a.agent_name, "agent_ip": a.agent_ip,
            "rule_id": a.rule_id, "rule_description": a.rule_description,
            "rule_level": a.rule_level, "severity": a.severity,
            "ttp_id": a.ttp_id, "ttp_name": a.ttp_name, "ttp_tactic": a.ttp_tactic,
            "remediation": a.remediation, "timestamp": iso_utc(a.timestamp),
            "full_log": a.full_log, "rule_groups": a.rule_groups,
            "extra": json.loads(a.extra or "{}"),
        }
    finally:
        db.close()


# ── Agents ────────────────────────────────────────────────────────────────────
@app.get("/api/agents")
def list_agents():
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        result = []
        for ag in agents:
            alert_count = db.query(func.count(Alert.id)).filter(Alert.agent_name == ag.name).scalar()
            result.append({
                "id": ag.id, "name": ag.name, "ip": ag.ip,
                "os": ag.os or "Unknown", "status": ag.status,
                "last_seen": iso_utc(ag.last_seen),
                "alert_count": alert_count,
            })
        return result
    finally:
        db.close()


# ── Stats / KPIs ──────────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
    db = SessionLocal()
    try:
        since_24h = datetime.utcnow() - timedelta(hours=24)
        since_7d = datetime.utcnow() - timedelta(days=7)

        def count_by_severity(since):
            rows = (
                db.query(Alert.severity, func.count(Alert.id))
                .filter(Alert.timestamp >= since)
                .group_by(Alert.severity)
                .all()
            )
            return {r[0]: r[1] for r in rows}

        sev_24h = count_by_severity(since_24h)
        sev_7d = count_by_severity(since_7d)

        # Hourly counts for the last 24 hours (for the timeline chart).
        # We send `hour_iso` (UTC ISO timestamp with Z) so the dashboard can
        # render hour labels in the viewer's local timezone (IST, etc).
        # `hour` is kept for backwards compatibility / non-JS consumers.
        hourly = []
        for h in range(23, -1, -1):
            start = datetime.utcnow() - timedelta(hours=h+1)
            end = datetime.utcnow() - timedelta(hours=h)
            cnt = db.query(func.count(Alert.id)).filter(
                Alert.timestamp >= start, Alert.timestamp < end
            ).scalar()
            hourly.append({
                "hour":     end.strftime("%H:00"),
                "hour_iso": iso_utc(end.replace(minute=0, second=0, microsecond=0)),
                "count":    cnt,
            })

        total_agents = db.query(func.count(Agent.id)).scalar()
        active_agents = db.query(func.count(Agent.id)).filter(
            Agent.last_seen >= since_24h
        ).scalar()

        return {
            "last_24h": {
                "total": sum(sev_24h.values()),
                "critical": sev_24h.get("critical", 0),
                "high": sev_24h.get("high", 0),
                "medium": sev_24h.get("medium", 0),
                "low": sev_24h.get("low", 0),
            },
            "last_7d": {
                "total": sum(sev_7d.values()),
                "critical": sev_7d.get("critical", 0),
                "high": sev_7d.get("high", 0),
                "medium": sev_7d.get("medium", 0),
                "low": sev_7d.get("low", 0),
            },
            "hourly_timeline": hourly,
            "agents": {"total": total_agents, "active": active_agents},
        }
    finally:
        db.close()


# ── MITRE ATT&CK Heatmap ──────────────────────────────────────────────────────
@app.get("/api/ttp-heatmap")
def ttp_heatmap():
    db = SessionLocal()
    try:
        rows = (
            db.query(Alert.ttp_tactic, Alert.ttp_id, Alert.ttp_name, func.count(Alert.id))
            .filter(Alert.ttp_id.isnot(None))
            .group_by(Alert.ttp_tactic, Alert.ttp_id, Alert.ttp_name)
            .all()
        )
        return [
            {"tactic": r[0], "technique_id": r[1], "technique_name": r[2], "count": r[3]}
            for r in rows
        ]
    finally:
        db.close()


# ── FIM ───────────────────────────────────────────────────────────────────────
@app.get("/api/fim")
def fim_events(agent: Optional[str] = None, limit: int = 50):
    db = SessionLocal()
    try:
        q = db.query(Alert).filter(Alert.rule_groups.contains("syscheck"))
        if agent:
            q = q.filter(Alert.agent_name == agent)
        events = q.order_by(Alert.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": a.id, "agent": a.agent_name, "timestamp": iso_utc(a.timestamp),
                "description": a.rule_description, "severity": a.severity,
                "extra": json.loads(a.extra or "{}"),
            }
            for a in events
        ]
    finally:
        db.close()


# ── Notifications ─────────────────────────────────────────────────────────────
@app.post("/api/notify/config")
def save_notify_config(cfg: NotifyConfigIn):
    db = SessionLocal()
    try:
        existing = db.query(NotifyConfig).first()
        if existing:
            existing.email = cfg.email
            existing.min_level = cfg.min_level
            existing.notify_fim = cfg.notify_fim
            existing.notify_malware = cfg.notify_malware
            existing.notify_sca = cfg.notify_sca
            existing.notify_vuln = cfg.notify_vuln
        else:
            db.add(NotifyConfig(**cfg.model_dump()))
        db.commit()
        return {"status": "saved"}
    finally:
        db.close()


@app.get("/api/notify/config")
def get_notify_config():
    db = SessionLocal()
    try:
        cfg = db.query(NotifyConfig).first()
        if not cfg:
            return {}
        return {
            "email": cfg.email, "min_level": cfg.min_level,
            "notify_fim": cfg.notify_fim, "notify_malware": cfg.notify_malware,
            "notify_sca": cfg.notify_sca, "notify_vuln": cfg.notify_vuln,
        }
    finally:
        db.close()


@app.post("/api/notify/test")
def test_email():
    db = SessionLocal()
    try:
        cfg = db.query(NotifyConfig).first()
        if not cfg:
            raise HTTPException(400, "No notification config saved. Set an email first.")
        result = send_test_email(cfg.email)
        return result
    finally:
        db.close()


# ── Demo alert (live trigger from dashboard buttons) ─────────────────────────
@app.post("/api/demo/alert")
async def demo_alert(severity: str, request: Request, background_tasks: BackgroundTasks):
    """
    Triggered by the DEMO buttons in the topbar. Reads the visitor's real IP,
    enriches with geo-location, creates a real Alert, broadcasts via WebSocket
    so every connected dashboard sees it instantly.
    """
    severity = (severity or "").lower()
    template = DEMO_TEMPLATES.get(severity)
    if not template:
        raise HTTPException(400, f"Invalid severity '{severity}'. Must be one of: {list(DEMO_TEMPLATES)}")

    ip = _client_ip(request)
    geo = _geo_lookup(ip)

    # Build a friendly endpoint name from the geo data
    if geo.get("city") and geo.get("country_code"):
        agent_name = f"demo-{geo['city'].lower().replace(' ', '-')}-{geo['country_code'].lower()}"
    else:
        agent_name = f"demo-{ip.replace('.', '-').replace(':', '-')}"
    agent_name = agent_name[:60]  # keep it sane

    location_str = ", ".join([p for p in [geo.get("city"), geo.get("region"), geo.get("country")] if p]) \
                   or "Unknown location"
    isp_str = geo.get("isp") or geo.get("org") or "Unknown ISP"

    full_log = (
        f"[DEMO ALERT triggered from dashboard]\n"
        f"Visitor IP : {ip}\n"
        f"Location   : {location_str}\n"
        f"ISP / Org  : {isp_str}\n"
        f"Severity   : {severity.upper()}  (rule_level={template['rule_level']})\n"
        f"Description: {template['rule_description']}\n"
        f"ATT&CK     : {template['ttp_id']} — {template['ttp_name']} ({template['ttp_tactic']})"
    )

    db = SessionLocal()
    try:
        ts = datetime.utcnow()
        alert = Alert(
            agent_name=agent_name,
            agent_ip=ip,
            rule_id=template["rule_id"],
            rule_description=template["rule_description"],
            rule_level=template["rule_level"],
            rule_groups=template["rule_groups"],
            severity=severity,
            full_log=full_log,
            timestamp=ts,
            ttp_id=template["ttp_id"],
            ttp_name=template["ttp_name"],
            ttp_tactic=template["ttp_tactic"],
            remediation=template["remediation"],
            extra=json.dumps({
                "demo": True,
                "ip": ip,
                "geo": geo,
            }),
        )
        db.add(alert)

        # Upsert a demo "agent" so the visitor shows up on the Endpoints page
        agent = db.query(Agent).filter(Agent.name == agent_name).first()
        if not agent:
            os_str = f"Browser ({geo.get('country', 'unknown')})" if geo else "Browser"
            agent = Agent(name=agent_name, ip=ip, os=os_str, status="active", last_seen=ts)
            db.add(agent)
        else:
            agent.ip = ip
            agent.status = "active"
            agent.last_seen = ts

        db.commit()
        db.refresh(alert)

        alert_dict = {
            "id": alert.id, "agent_name": alert.agent_name, "agent_ip": alert.agent_ip,
            "rule_id": alert.rule_id, "rule_description": alert.rule_description,
            "rule_level": alert.rule_level, "severity": alert.severity,
            "ttp_id": alert.ttp_id, "ttp_name": alert.ttp_name, "ttp_tactic": alert.ttp_tactic,
            "remediation": alert.remediation, "timestamp": iso_utc(ts),
            "full_log": alert.full_log,
        }

        # Broadcast to every connected dashboard so peers see the alert pop up live
        background_tasks.add_task(manager.broadcast, {"type": "new_alert", "alert": alert_dict})

        return {
            "status":   "ok",
            "alert_id": alert.id,
            "severity": severity,
            "ip":       ip,
            "location": location_str,
            "isp":      isp_str,
            "geo":      geo,
        }
    finally:
        db.close()


# ── WebSocket (real-time alerts to dashboard) ─────────────────────────────────
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    logger.info(f"Dashboard connected via WebSocket: {websocket.client}")
    try:
        while True:
            # Keep alive — actual data is pushed by ingest_alert
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Dashboard WebSocket disconnected")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
