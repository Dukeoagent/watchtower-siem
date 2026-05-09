"""
WatchTower SIEM - Database Models
==================================
Defines the shape of every table in the SQLite database.
Each class = one table.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float
from database import Base
from datetime import datetime


class Alert(Base):
    """Every security alert ingested from Wazuh agents."""
    __tablename__ = "alerts"

    id               = Column(Integer, primary_key=True, index=True)
    agent_name       = Column(String, index=True)
    agent_ip         = Column(String)
    rule_id          = Column(Integer, index=True)
    rule_description = Column(String)
    rule_level       = Column(Integer)        # 1-15 (Wazuh scale)
    rule_groups      = Column(String)         # comma-separated
    severity         = Column(String, index=True)  # low/medium/high/critical
    full_log         = Column(Text)
    timestamp        = Column(DateTime, default=datetime.utcnow, index=True)

    # MITRE ATT&CK enrichment
    ttp_id           = Column(String, nullable=True)   # e.g. "T1055"
    ttp_name         = Column(String, nullable=True)   # e.g. "Process Injection"
    ttp_tactic       = Column(String, nullable=True)   # e.g. "Defense Evasion"

    # Remediation suggestion
    remediation      = Column(Text, nullable=True)

    # Extra JSON blob (FIM file paths, CVE details, SCA check name, etc.)
    extra            = Column(Text, default="{}")


class Agent(Base):
    """Each monitored endpoint (server, laptop, VM) that has Wazuh installed."""
    __tablename__ = "agents"

    id        = Column(Integer, primary_key=True, index=True)
    name      = Column(String, unique=True, index=True)
    ip        = Column(String)
    os        = Column(String, nullable=True)
    status    = Column(String, default="active")   # active / disconnected
    last_seen = Column(DateTime, nullable=True)


class NotifyConfig(Base):
    """Admin email notification settings (one row, updated in-place)."""
    __tablename__ = "notify_config"

    id              = Column(Integer, primary_key=True)
    email           = Column(String)
    min_level       = Column(Integer, default=10)  # Alert when rule_level >= this
    notify_fim      = Column(Boolean, default=True)
    notify_malware  = Column(Boolean, default=True)
    notify_sca      = Column(Boolean, default=True)
    notify_vuln     = Column(Boolean, default=True)


class FIMEvent(Base):
    """File Integrity Monitoring — tracks every file change."""
    __tablename__ = "fim_events"

    id          = Column(Integer, primary_key=True)
    agent_name  = Column(String, index=True)
    file_path   = Column(String)
    event_type  = Column(String)   # added / modified / deleted
    hash_before = Column(String, nullable=True)
    hash_after  = Column(String, nullable=True)
    timestamp   = Column(DateTime, default=datetime.utcnow)


class SCAResult(Base):
    """Security Configuration Assessment results (CIS benchmark checks)."""
    __tablename__ = "sca_results"

    id          = Column(Integer, primary_key=True)
    agent_name  = Column(String, index=True)
    policy_name = Column(String)
    check_id    = Column(String)
    check_title = Column(String)
    result      = Column(String)   # passed / failed / not_applicable
    timestamp   = Column(DateTime, default=datetime.utcnow)


class Vulnerability(Base):
    """Known CVEs detected on endpoints via Wazuh vulnerability scanner."""
    __tablename__ = "vulnerabilities"

    id          = Column(Integer, primary_key=True)
    agent_name  = Column(String, index=True)
    cve_id      = Column(String, index=True)
    package     = Column(String)
    version     = Column(String)
    severity    = Column(String)
    cvss_score  = Column(Float, nullable=True)
    fix_version = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    timestamp   = Column(DateTime, default=datetime.utcnow)
