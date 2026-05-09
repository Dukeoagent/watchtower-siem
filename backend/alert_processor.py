"""
WatchTower SIEM - Alert Processor (Sensor-Side Script)
=======================================================
This script runs ON THE WAZUH MANAGER (or agent) and forwards
Wazuh alerts to the WatchTower central API.

It tail-follows /var/ossec/logs/alerts/alerts.json and POSTs
each new alert to the WatchTower backend.

Usage (on Wazuh manager):
  python3 alert_processor.py --api http://YOUR_SERVER:8000

Run as a systemd service for continuous operation.
"""

import argparse
import json
import os
import sys
import time
import logging
import requests
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


def _setup_logging():
    """Configure logging when this script is run as the main entry point.
    We do this lazily so that importing this module from elsewhere
    (e.g. the FastAPI backend) doesn't try to create /var/log/* files
    that may not be writable in every environment.
    """
    handlers = [logging.StreamHandler(sys.stdout)]
    log_path = os.getenv("FORWARDER_LOG", "/var/log/watchtower-forwarder.log")
    try:
        handlers.append(logging.FileHandler(log_path))
    except (OSError, PermissionError):
        pass  # No writable log file — stdout-only is fine.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )

ALERTS_JSON_PATH = os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
WATCHTOWER_API   = os.getenv("WATCHTOWER_API", "http://localhost:8000")
RETRY_DELAY      = 5   # seconds between retries on failure
BATCH_SIZE       = 10  # process alerts in batches


def parse_wazuh_alert(raw: str) -> dict | None:
    """
    Parse one line from Wazuh alerts.json.
    Returns a normalized dict ready for the WatchTower API, or None if unparseable.
    """
    try:
        alert = json.loads(raw.strip())
    except json.JSONDecodeError:
        return None

    # Extract fields from Wazuh's nested JSON format
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})

    extra = {}

    # FIM data
    if syscheck:
        extra["syscheck"] = {
            "path":         syscheck.get("path"),
            "event":        syscheck.get("event"),  # added/modified/deleted
            "md5_before":   syscheck.get("md5_before"),
            "md5_after":    syscheck.get("md5_after"),
            "sha256_after": syscheck.get("sha256_after"),
            "uname_after":  syscheck.get("uname_after"),
            "gname_after":  syscheck.get("gname_after"),
        }

    # Vulnerability data
    if data.get("vulnerability"):
        extra["vulnerability"] = data["vulnerability"]

    return {
        "agent_name":       agent.get("name", "unknown"),
        "agent_ip":         agent.get("ip", "0.0.0.0"),
        "rule_id":          int(rule.get("id", 0)),
        "rule_description": rule.get("description", ""),
        "rule_level":       int(rule.get("level", 0)),
        "rule_groups":      ",".join(rule.get("groups", [])),
        "full_log":         alert.get("full_log", ""),
        "timestamp":        alert.get("timestamp"),
        "extra":            extra,
    }


def post_alert(api_url: str, payload: dict) -> bool:
    """POST a single alert to the WatchTower API. Returns True on success."""
    try:
        resp = requests.post(
            f"{api_url}/api/ingest/alert",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        logger.error(f"Failed to post alert: {e}")
        return False


def register_agent(api_url: str, agent_name: str, agent_ip: str, os_name: str = ""):
    """Register/update agent info at the central server."""
    try:
        requests.post(
            f"{api_url}/api/agents/register",
            json={"name": agent_name, "ip": agent_ip, "os": os_name},
            timeout=5,
        )
    except Exception:
        pass  # Non-critical


def tail_alerts(filepath: str, api_url: str):
    """
    Continuously tail the Wazuh alerts.json file and forward
    each new alert to the WatchTower API.
    """
    path = Path(filepath)

    # Wait for file to exist
    while not path.exists():
        logger.info(f"Waiting for {filepath} to appear...")
        time.sleep(5)

    logger.info(f"📡 Starting to tail {filepath}")
    logger.info(f"🎯 Forwarding to: {api_url}")

    with open(filepath, "r") as f:
        # Seek to end of file (don't replay old alerts on restart)
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)  # No new line yet, wait briefly
                continue

            payload = parse_wazuh_alert(line)
            if payload:
                success = post_alert(api_url, payload)
                if success:
                    logger.debug(f"Forwarded: rule={payload['rule_id']} agent={payload['agent_name']}")
                else:
                    # Retry once
                    time.sleep(RETRY_DELAY)
                    post_alert(api_url, payload)


def main():
    _setup_logging()
    parser = argparse.ArgumentParser(description="WatchTower Wazuh Alert Forwarder")
    parser.add_argument("--api", default=WATCHTOWER_API, help="WatchTower API URL")
    parser.add_argument("--alerts", default=ALERTS_JSON_PATH, help="Path to Wazuh alerts.json")
    args = parser.parse_args()

    logger.info("🔐 WatchTower Alert Forwarder starting...")
    logger.info(f"   Wazuh alerts: {args.alerts}")
    logger.info(f"   API endpoint: {args.api}")

    # Test API connectivity
    try:
        resp = requests.get(f"{args.api}/health", timeout=5)
        logger.info(f"✅ API reachable: {resp.json()}")
    except Exception as e:
        logger.error(f"❌ Cannot reach API at {args.api}: {e}")
        logger.error("   Make sure WatchTower backend is running.")
        sys.exit(1)

    tail_alerts(args.alerts, args.api)


if __name__ == "__main__":
    main()
