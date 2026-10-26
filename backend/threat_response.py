"""
Autonomous Threat Response – Backend Module
============================================

Provides endpoints for:
  - Automated response playbook management
  - Threat response simulation and execution
  - Response chain orchestration (detect → classify → respond)
  - Integration readiness for SIEM/SOAR/EDR platforms
  - Incident timeline reconstruction
  - Response effectiveness scoring
"""

import secrets
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from sqlalchemy.orm import Session

from auth import require_auth, require_role
from database import get_db, SessionLocal, AuditLog, Job, Incident, IncidentNote, CustomPlaybook

router = APIRouter(prefix="/api/threat-response", tags=["threat-response"])
limiter = Limiter(key_func=get_remote_address)

# ── Response Playbooks ───────────────────────────────────────────────────

PLAYBOOKS = {
    "ddos_mitigation": {
        "id": "PB-001",
        "name": "DDoS Mitigation",
        "description": "Automated response to volumetric and application-layer DDoS attacks",
        "trigger_classes": ["DDoS-TCP_Flood", "DDoS-UDP_Flood", "DDoS-ICMP_Flood", "DDoS-HTTP_Flood",
                           "DDoS-SYN_Flood", "DDoS-SlowLoris", "DDoS-PSHACK_Flood", "DDoS-RSTFINFlood",
                           "DDoS-SynonymousIP_Flood", "DDoS-ACK_Fragmentation", "DDoS-UDP_Fragmentation",
                           "DDoS-ICMP_Fragmentation"],
        "severity": "critical",
        "auto_execute": False,
        "requires_approval": True,
        "response_chain": [
            {"step": 1, "action": "detect", "description": "ML model classifies traffic as DDoS variant", "delay_ms": 0},
            {"step": 2, "action": "verify", "description": "Verify with 3+ MC-Dropout passes (confidence ≥ 0.85)", "delay_ms": 50},
            {"step": 3, "action": "alert", "description": "Push alert to SOC dashboard and SIEM", "delay_ms": 100},
            {"step": 4, "action": "rate_limit", "description": "Apply rate limiting to source IP/subnet", "delay_ms": 500},
            {"step": 5, "action": "firewall", "description": "Generate and stage iptables/nftables DROP rules", "delay_ms": 1000},
            {"step": 6, "action": "upstream_notify", "description": "Notify upstream ISP via BGP FlowSpec (if configured)", "delay_ms": 2000},
            {"step": 7, "action": "log", "description": "Record incident with full evidence chain", "delay_ms": 100},
        ],
        "estimated_response_ms": 3750,
        "effectiveness_score": 0.92,
        "false_positive_rate": 0.03,
    },
    "brute_force_lockout": {
        "id": "PB-002",
        "name": "Brute Force Account Lockout",
        "description": "Progressive response to credential stuffing and brute force attacks",
        "trigger_classes": ["BruteForce-SSH", "BruteForce-FTP", "BruteForce-HTTP", "BruteForce-RDP"],
        "severity": "high",
        "auto_execute": False,
        "requires_approval": False,
        "response_chain": [
            {"step": 1, "action": "detect", "description": "Detect brute force pattern (≥5 failures in 60s)", "delay_ms": 0},
            {"step": 2, "action": "throttle", "description": "Exponential backoff on authentication endpoint", "delay_ms": 100},
            {"step": 3, "action": "captcha", "description": "Enable CAPTCHA challenge for source IP", "delay_ms": 200},
            {"step": 4, "action": "block_temp", "description": "Temporary IP block (30 min) after 20 failures", "delay_ms": 500},
            {"step": 5, "action": "block_perm", "description": "Permanent block after 3 temp blocks in 24h", "delay_ms": 0},
            {"step": 6, "action": "credential_reset", "description": "Force password reset on targeted accounts", "delay_ms": 1000},
            {"step": 7, "action": "log", "description": "Record timeline with source IPs and targeted accounts", "delay_ms": 100},
        ],
        "estimated_response_ms": 1900,
        "effectiveness_score": 0.95,
        "false_positive_rate": 0.02,
    },
    "recon_deception": {
        "id": "PB-003",
        "name": "Reconnaissance Deception",
        "description": "Deploy deception techniques against network reconnaissance",
        "trigger_classes": ["Recon-PortScan", "Recon-OSScan", "Recon-HostDiscovery", "Recon-PingSweep"],
        "severity": "medium",
        "auto_execute": False,
        "requires_approval": False,
        "response_chain": [
            {"step": 1, "action": "detect", "description": "Classify traffic as reconnaissance activity", "delay_ms": 0},
            {"step": 2, "action": "fingerprint", "description": "Fingerprint scanner tool (nmap, masscan, zmap signatures)", "delay_ms": 200},
            {"step": 3, "action": "honeypot", "description": "Redirect scanner to honeypot with fake services", "delay_ms": 500},
            {"step": 4, "action": "tarpit", "description": "Engage TCP tarpit to slow down scanning", "delay_ms": 100},
            {"step": 5, "action": "intel_collect", "description": "Collect attacker TTPs and IOCs for threat intelligence", "delay_ms": 1000},
            {"step": 6, "action": "log", "description": "Record recon attempt with scanner profile", "delay_ms": 100},
        ],
        "estimated_response_ms": 1900,
        "effectiveness_score": 0.88,
        "false_positive_rate": 0.05,
    },
    "malware_containment": {
        "id": "PB-004",
        "name": "Malware Containment",
        "description": "Isolate and contain malware-related network traffic",
        "trigger_classes": ["Malware-Backdoor", "Malware-Ransomware", "Malware-C2", "Mirai-greip_flood",
                           "Mirai-greeth_flood", "Mirai-udpplain"],
        "severity": "critical",
        "auto_execute": False,
        "requires_approval": True,
        "response_chain": [
            {"step": 1, "action": "detect", "description": "ML model classifies malware C2 or payload traffic", "delay_ms": 0},
            {"step": 2, "action": "isolate", "description": "Network isolation of affected host (VLAN quarantine)", "delay_ms": 500},
            {"step": 3, "action": "block_c2", "description": "Block all communication to identified C2 domains/IPs", "delay_ms": 300},
            {"step": 4, "action": "snapshot", "description": "Trigger forensic memory dump and disk snapshot", "delay_ms": 2000},
            {"step": 5, "action": "ioc_extract", "description": "Extract IOCs (hashes, domains, IPs, mutexes)", "delay_ms": 1000},
            {"step": 6, "action": "threat_intel", "description": "Submit IOCs to threat intelligence platforms", "delay_ms": 500},
            {"step": 7, "action": "edr_scan", "description": "Trigger EDR full scan on affected subnet", "delay_ms": 3000},
            {"step": 8, "action": "log", "description": "Record full incident timeline with forensic evidence", "delay_ms": 100},
        ],
        "estimated_response_ms": 7400,
        "effectiveness_score": 0.90,
        "false_positive_rate": 0.04,
    },
    "web_attack_waf": {
        "id": "PB-005",
        "name": "Web Attack WAF Response",
        "description": "Dynamic WAF rule deployment for web application attacks",
        "trigger_classes": ["WebAttack-SQLi", "WebAttack-XSS", "WebAttack-CommandInjection",
                           "WebAttack-BrowserHijacking"],
        "severity": "high",
        "auto_execute": False,
        "requires_approval": False,
        "response_chain": [
            {"step": 1, "action": "detect", "description": "Classify web attack type (SQLi, XSS, CMDi)", "delay_ms": 0},
            {"step": 2, "action": "waf_rule", "description": "Generate and deploy virtual patch / WAF rule", "delay_ms": 300},
            {"step": 3, "action": "session_kill", "description": "Terminate suspicious session and invalidate tokens", "delay_ms": 200},
            {"step": 4, "action": "input_sanitise", "description": "Enable enhanced input validation on targeted endpoint", "delay_ms": 100},
            {"step": 5, "action": "geo_check", "description": "Check source IP geolocation against access policy", "delay_ms": 150},
            {"step": 6, "action": "log", "description": "Record attack payload and response actions", "delay_ms": 100},
        ],
        "estimated_response_ms": 850,
        "effectiveness_score": 0.93,
        "false_positive_rate": 0.06,
    },
    "spoofing_defense": {
        "id": "PB-006",
        "name": "Spoofing Defense",
        "description": "Counter ARP/DNS/IP spoofing attacks",
        "trigger_classes": ["Spoofing-ARP", "Spoofing-DNS", "Spoofing-IP"],
        "severity": "high",
        "auto_execute": False,
        "requires_approval": False,
        "response_chain": [
            {"step": 1, "action": "detect", "description": "Detect spoofing anomaly in network headers", "delay_ms": 0},
            {"step": 2, "action": "validate", "description": "Cross-reference against known MAC/IP/DNS mappings", "delay_ms": 200},
            {"step": 3, "action": "arp_guard", "description": "Enable Dynamic ARP Inspection (DAI) on switch port", "delay_ms": 500},
            {"step": 4, "action": "dns_sinkhole", "description": "Redirect spoofed DNS to sinkhole for analysis", "delay_ms": 300},
            {"step": 5, "action": "alert", "description": "Alert network team with spoofing evidence", "delay_ms": 100},
            {"step": 6, "action": "log", "description": "Record spoofing incident with network topology context", "delay_ms": 100},
        ],
        "estimated_response_ms": 1200,
        "effectiveness_score": 0.87,
        "false_positive_rate": 0.04,
    },
}

# ── Integration Connectors ───────────────────────────────────────────────

INTEGRATIONS = {
    "siem": {
        "name": "SIEM Integration",
        "description": "Forward alerts and incidents to Security Information and Event Management",
        "supported": ["Splunk", "Elastic SIEM", "IBM QRadar", "Microsoft Sentinel", "Wazuh", "OSSIM"],
        "protocol": "Syslog (CEF/LEEF) / REST API / Kafka",
        "status": "available",
        "config_required": ["siem_endpoint", "api_key", "format"],
    },
    "soar": {
        "name": "SOAR Integration",
        "description": "Orchestrate response actions via Security Orchestration, Automation and Response",
        "supported": ["Palo Alto XSOAR", "Splunk SOAR (Phantom)", "IBM Resilient", "TheHive", "Shuffle"],
        "protocol": "REST API / Webhook",
        "status": "available",
        "config_required": ["soar_endpoint", "api_key", "playbook_mapping"],
    },
    "edr": {
        "name": "EDR Integration",
        "description": "Trigger endpoint detection and response actions",
        "supported": ["CrowdStrike Falcon", "SentinelOne", "Microsoft Defender", "Carbon Black", "Cybereason"],
        "protocol": "REST API",
        "status": "available",
        "config_required": ["edr_endpoint", "api_key", "agent_scope"],
    },
    "firewall": {
        "name": "Firewall Integration",
        "description": "Push firewall rules to network security appliances",
        "supported": ["Palo Alto NGFW", "Fortinet FortiGate", "Check Point", "Cisco ASA/FTD", "pfSense"],
        "protocol": "REST API / SSH",
        "status": "native",
        "config_required": ["firewall_endpoint", "credentials", "zone_mapping"],
    },
    "ticketing": {
        "name": "Ticketing Integration",
        "description": "Create and track incident tickets",
        "supported": ["ServiceNow", "Jira Service Management", "PagerDuty", "OpsGenie"],
        "protocol": "REST API / Webhook",
        "status": "available",
        "config_required": ["ticket_endpoint", "api_key", "project_id"],
    },
    "threat_intel": {
        "name": "Threat Intelligence Feeds",
        "description": "Enrich alerts with external threat intelligence",
        "supported": ["VirusTotal", "AbuseIPDB", "AlienVault OTX", "MISP", "STIX/TAXII"],
        "protocol": "REST API / TAXII 2.1",
        "status": "available",
        "config_required": ["api_key", "feed_url"],
    },
}

# ── Helpers ───────────────────────────────────────────────────────────────

def _get_all_playbooks(db: Session) -> dict:
    """Merge built-in PLAYBOOKS with user-created CustomPlaybooks from DB."""
    merged = dict(PLAYBOOKS)
    for cp in db.query(CustomPlaybook).all():
        merged[cp.playbook_key] = {
            "id": f"PB-C{cp.id:03d}",
            "name": cp.name,
            "description": cp.description or "",
            "trigger_classes": cp.trigger_classes or [],
            "severity": cp.severity,
            "auto_execute": cp.auto_execute,
            "requires_approval": cp.requires_approval,
            "response_chain": cp.response_chain or [],
            "estimated_response_ms": cp.estimated_response_ms,
            "effectiveness_score": cp.effectiveness_score,
            "false_positive_rate": cp.false_positive_rate,
            "custom": True,
            "created_by": cp.created_by,
        }
    return merged


def _incident_to_dict(inc: Incident) -> dict:
    """Convert an Incident ORM object to a JSON-friendly dict."""
    return {
        "incident_id": inc.incident_id,
        "playbook_id": inc.playbook_id,
        "playbook_name": inc.playbook_name,
        "severity": inc.severity,
        "source_ip": inc.source_ip,
        "target_ip": inc.target_ip,
        "threat_label": inc.threat_label,
        "confidence": inc.confidence,
        "mode": inc.mode,
        "steps": inc.steps or [],
        "total_simulated_ms": inc.total_simulated_ms,
        "actual_execution_ms": inc.actual_execution_ms,
        "effectiveness_score": inc.effectiveness_score,
        "false_positive_rate": inc.false_positive_rate,
        "triggered_by": inc.triggered_by,
        "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
        "notes": [
            {"author": n.author, "note": n.note, "timestamp": n.timestamp.isoformat() if n.timestamp else None}
            for n in (inc.notes or [])
        ],
    }


# ── Request Models ───────────────────────────────────────────────────────

class SimulateRequest(BaseModel):
    playbook_id: str = Field(..., description="Playbook to simulate")
    source_ip: str = Field("192.168.1.100", description="Simulated source IP")
    target_ip: str = Field("10.0.0.1", description="Simulated target IP")
    threat_label: str = Field("", description="Override threat label")
    confidence: float = Field(0.95, ge=0.0, le=1.0, description="Detection confidence")

class PlaybookToggleRequest(BaseModel):
    auto_execute: bool = Field(..., description="Enable/disable auto-execution")

class IncidentNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000, description="Analyst note")

class PlaybookCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200, description="Playbook name")
    description: str = Field("", max_length=1000, description="Playbook description")
    trigger_classes: list[str] = Field(default_factory=list, description="Threat classes that trigger this playbook")
    severity: str = Field("medium", description="Severity level")
    requires_approval: bool = Field(True, description="Whether manual approval is needed")
    response_chain: list[dict] = Field(default_factory=list, description="Response steps")

class PlaybookUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    trigger_classes: Optional[list[str]] = None
    severity: Optional[str] = None
    requires_approval: Optional[bool] = None
    response_chain: Optional[list[dict]] = None


# ── Endpoints ────────────────────────────────────────────────────────────

@router.get("/playbooks")
async def list_playbooks(user=Depends(require_auth), db: Session = Depends(get_db)):
    """List all response playbooks (built-in + custom) with their configurations."""
    all_pb = _get_all_playbooks(db)
    summary = {}
    for pid, pb in all_pb.items():
        summary[pid] = {
            **pb,
            "trigger_count": len(pb.get("trigger_classes", [])),
            "step_count": len(pb.get("response_chain", [])),
        }
    return {
        "playbooks": summary,
        "total": len(all_pb),
        "auto_execute_enabled": sum(1 for p in all_pb.values() if p.get("auto_execute")),
        "requires_approval": sum(1 for p in all_pb.values() if p.get("requires_approval")),
    }


@router.get("/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str, user=Depends(require_auth), db: Session = Depends(get_db)):
    """Get detailed playbook configuration."""
    all_pb = _get_all_playbooks(db)
    if playbook_id not in all_pb:
        raise HTTPException(404, f"Playbook not found: {playbook_id}")
    return all_pb[playbook_id]


@router.post("/playbooks")
async def create_playbook(body: PlaybookCreateRequest, user=Depends(require_auth), db: Session = Depends(get_db)):
    """Create a new custom playbook."""
    # Generate a URL-safe key from the name
    key = body.name.lower().replace(" ", "_").replace("-", "_")
    key = "".join(c for c in key if c.isalnum() or c == "_")

    # Check for duplicates
    if key in PLAYBOOKS or db.query(CustomPlaybook).filter_by(playbook_key=key).first():
        raise HTTPException(409, f"Playbook with key '{key}' already exists")

    # Validate severity
    if body.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(400, "Severity must be critical, high, medium, or low")

    # Compute estimated response time from chain
    estimated_ms = sum(s.get("delay_ms", 0) for s in body.response_chain) if body.response_chain else 0

    cp = CustomPlaybook(
        playbook_key=key,
        name=body.name,
        description=body.description,
        trigger_classes=body.trigger_classes,
        severity=body.severity,
        auto_execute=False,
        requires_approval=body.requires_approval,
        response_chain=body.response_chain,
        estimated_response_ms=estimated_ms,
        created_by=user.email,
    )
    db.add(cp)
    db.commit()
    db.refresh(cp)

    return {
        "playbook_key": key,
        "id": f"PB-C{cp.id:03d}",
        "name": cp.name,
        "message": "Custom playbook created successfully",
    }


@router.put("/playbooks/{playbook_id}")
async def update_playbook(playbook_id: str, body: PlaybookUpdateRequest, user=Depends(require_auth), db: Session = Depends(get_db)):
    """Update a custom playbook (built-in playbooks cannot be edited)."""
    if playbook_id in PLAYBOOKS:
        raise HTTPException(403, "Built-in playbooks cannot be edited")

    cp = db.query(CustomPlaybook).filter_by(playbook_key=playbook_id).first()
    if not cp:
        raise HTTPException(404, f"Custom playbook not found: {playbook_id}")

    if body.name is not None:
        cp.name = body.name
    if body.description is not None:
        cp.description = body.description
    if body.trigger_classes is not None:
        cp.trigger_classes = body.trigger_classes
    if body.severity is not None:
        if body.severity not in ("critical", "high", "medium", "low"):
            raise HTTPException(400, "Severity must be critical, high, medium, or low")
        cp.severity = body.severity
    if body.requires_approval is not None:
        cp.requires_approval = body.requires_approval
    if body.response_chain is not None:
        cp.response_chain = body.response_chain
        cp.estimated_response_ms = sum(s.get("delay_ms", 0) for s in body.response_chain)

    db.commit()
    return {"playbook_key": playbook_id, "message": "Playbook updated"}


@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str, user=Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Delete a custom playbook (admin only). Built-in playbooks cannot be deleted."""
    if playbook_id in PLAYBOOKS:
        raise HTTPException(403, "Built-in playbooks cannot be deleted")

    cp = db.query(CustomPlaybook).filter_by(playbook_key=playbook_id).first()
    if not cp:
        raise HTTPException(404, f"Custom playbook not found: {playbook_id}")

    db.delete(cp)
    db.commit()
    return {"playbook_key": playbook_id, "message": "Playbook deleted"}


@router.patch("/playbooks/{playbook_id}/toggle")
async def toggle_playbook(playbook_id: str, body: PlaybookToggleRequest, user=Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Enable/disable auto-execution for a playbook (admin only)."""
    all_pb = _get_all_playbooks(db)
    if playbook_id not in all_pb:
        raise HTTPException(404, f"Playbook not found: {playbook_id}")

    # For built-in playbooks, toggle in-memory
    if playbook_id in PLAYBOOKS:
        old_value = PLAYBOOKS[playbook_id]["auto_execute"]
        PLAYBOOKS[playbook_id]["auto_execute"] = body.auto_execute
    else:
        cp = db.query(CustomPlaybook).filter_by(playbook_key=playbook_id).first()
        old_value = cp.auto_execute
        cp.auto_execute = body.auto_execute
        db.commit()

    pb = all_pb[playbook_id]
    return {
        "playbook_id": playbook_id,
        "name": pb["name"],
        "auto_execute": body.auto_execute,
        "previous": old_value,
        "updated_by": user.email,
        "warning": "Critical playbook — requires human approval even in auto mode" if pb.get("requires_approval") else None,
    }


@router.post("/simulate")
@limiter.limit("10/minute")
async def simulate_response(request: Request, body: SimulateRequest, user=Depends(require_auth), db: Session = Depends(get_db)):
    """Simulate a threat response playbook execution with detailed step timing."""
    all_pb = _get_all_playbooks(db)
    if body.playbook_id not in all_pb:
        raise HTTPException(404, f"Playbook not found: {body.playbook_id}")

    pb = all_pb[body.playbook_id]
    trigger_classes = pb.get("trigger_classes", [])
    threat_label = body.threat_label or (trigger_classes[0] if trigger_classes else "Unknown")

    # Simulate execution of each step
    incident_id = f"INC-{secrets.token_hex(4).upper()}"
    steps_executed = []
    total_time_ms = 0
    t_start = time.perf_counter()

    for step in pb.get("response_chain", []):
        step_start = time.perf_counter()
        import asyncio
        await asyncio.sleep(step["delay_ms"] / 10000)  # 100x speedup for simulation
        step_end = time.perf_counter()

        actual_ms = round((step_end - step_start) * 1000, 1)
        total_time_ms += step["delay_ms"]

        steps_executed.append({
            **step,
            "status": "simulated",
            "actual_ms": actual_ms,
            "simulated_ms": step["delay_ms"],
            "cumulative_ms": total_time_ms,
            "timestamp": datetime.utcnow().isoformat(),
        })

    t_end = time.perf_counter()

    # Persist incident to database
    inc_row = Incident(
        incident_id=incident_id,
        playbook_id=body.playbook_id,
        playbook_name=pb["name"],
        severity=pb.get("severity", "medium"),
        source_ip=body.source_ip,
        target_ip=body.target_ip,
        threat_label=threat_label,
        confidence=body.confidence,
        mode="simulation",
        steps=steps_executed,
        total_simulated_ms=total_time_ms,
        actual_execution_ms=round((t_end - t_start) * 1000, 1),
        effectiveness_score=pb.get("effectiveness_score", 0),
        false_positive_rate=pb.get("false_positive_rate", 0),
        triggered_by=user.email,
    )
    db.add(inc_row)
    db.commit()
    db.refresh(inc_row)

    return _incident_to_dict(inc_row)


@router.get("/incidents")
async def list_incidents(
    limit: int = 50,
    severity: Optional[str] = None,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    """List recent incidents (persisted to database)."""
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)

    total_query = db.query(Incident)
    total = total_query.count()

    incidents = query.order_by(Incident.timestamp.desc()).limit(limit).all()

    return {
        "incidents": [_incident_to_dict(i) for i in incidents],
        "total": total if not severity else query.count(),
        "by_severity": {
            "critical": total_query.filter(Incident.severity == "critical").count(),
            "high": total_query.filter(Incident.severity == "high").count(),
            "medium": total_query.filter(Incident.severity == "medium").count(),
            "low": total_query.filter(Incident.severity == "low").count(),
        },
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, user=Depends(require_auth), db: Session = Depends(get_db)):
    """Get detailed incident timeline."""
    inc = db.query(Incident).filter_by(incident_id=incident_id).first()
    if not inc:
        raise HTTPException(404, f"Incident not found: {incident_id}")
    return _incident_to_dict(inc)


@router.post("/incidents/{incident_id}/note")
async def add_incident_note(incident_id: str, body: IncidentNoteRequest, user=Depends(require_auth), db: Session = Depends(get_db)):
    """Add analyst note to an incident."""
    inc = db.query(Incident).filter_by(incident_id=incident_id).first()
    if not inc:
        raise HTTPException(404, f"Incident not found: {incident_id}")

    note_row = IncidentNote(
        incident_id=incident_id,
        author=user.email,
        note=body.note,
    )
    db.add(note_row)
    db.commit()

    return {
        "incident_id": incident_id,
        "note_added": {"author": user.email, "note": body.note, "timestamp": note_row.timestamp.isoformat()},
        "total_notes": db.query(IncidentNote).filter_by(incident_id=incident_id).count(),
    }


@router.get("/integrations")
async def list_integrations(user=Depends(require_auth)):
    """List available security platform integrations."""
    return {
        "integrations": INTEGRATIONS,
        "total": len(INTEGRATIONS),
        "native": sum(1 for i in INTEGRATIONS.values() if i["status"] == "native"),
        "available": sum(1 for i in INTEGRATIONS.values() if i["status"] == "available"),
        "configured": sum(1 for i in INTEGRATIONS.values() if i["status"] == "configured"),
    }


@router.get("/response-metrics")
async def response_metrics(user=Depends(require_auth), db: Session = Depends(get_db)):
    """Get aggregated response metrics across all playbooks and incidents."""
    all_pb = _get_all_playbooks(db)

    playbook_metrics = []
    for pid, pb in all_pb.items():
        inc_count = db.query(Incident).filter_by(playbook_id=pid).count()
        playbook_metrics.append({
            "playbook_id": pid,
            "name": pb["name"],
            "severity": pb.get("severity", "medium"),
            "incidents_triggered": inc_count,
            "effectiveness_score": pb.get("effectiveness_score", 0),
            "false_positive_rate": pb.get("false_positive_rate", 0),
            "avg_response_ms": pb.get("estimated_response_ms", 0),
            "auto_execute": pb.get("auto_execute", False),
            "step_count": len(pb.get("response_chain", [])),
            "trigger_classes": len(pb.get("trigger_classes", [])),
            "custom": pb.get("custom", False),
        })

    total_incidents = db.query(Incident).count()
    avg_effectiveness = round(
        sum(p["effectiveness_score"] for p in playbook_metrics) / len(playbook_metrics) * 100, 1
    ) if playbook_metrics else 0

    # Coverage analysis — which attack classes have playbooks
    covered_classes = set()
    for pb in all_pb.values():
        covered_classes.update(pb.get("trigger_classes", []))

    all_classes = [
        "Benign", "DDoS-TCP_Flood", "DDoS-UDP_Flood", "DDoS-ICMP_Flood", "DDoS-HTTP_Flood",
        "DDoS-SYN_Flood", "DDoS-SlowLoris", "DDoS-PSHACK_Flood", "DDoS-RSTFINFlood",
        "DDoS-SynonymousIP_Flood", "DDoS-ACK_Fragmentation", "DDoS-UDP_Fragmentation",
        "DDoS-ICMP_Fragmentation", "DoS-TCP_Flood", "DoS-UDP_Flood", "DoS-SYN_Flood",
        "DoS-HTTP_Flood", "Recon-PortScan", "Recon-OSScan", "Recon-HostDiscovery",
        "Recon-PingSweep", "BruteForce-SSH", "BruteForce-FTP", "BruteForce-HTTP",
        "BruteForce-RDP", "Spoofing-ARP", "Spoofing-DNS", "Spoofing-IP",
        "WebAttack-SQLi", "WebAttack-XSS", "WebAttack-CommandInjection",
        "WebAttack-BrowserHijacking", "Malware-Backdoor", "Malware-Ransomware",
    ]
    uncovered = [c for c in all_classes if c not in covered_classes and c != "Benign"]

    return {
        "playbooks": playbook_metrics,
        "summary": {
            "total_playbooks": len(all_pb),
            "total_incidents": total_incidents,
            "avg_effectiveness": avg_effectiveness,
            "coverage": {
                "covered_classes": len(covered_classes),
                "total_threat_classes": len(all_classes) - 1,
                "coverage_percentage": round(len(covered_classes) / (len(all_classes) - 1) * 100, 1),
                "uncovered_classes": uncovered,
            },
        },
        "mttr_by_severity": {
            "critical": round(sum(pb.get("estimated_response_ms", 0) for pb in all_pb.values() if pb.get("severity") == "critical") / max(1, sum(1 for pb in all_pb.values() if pb.get("severity") == "critical"))),
            "high": round(sum(pb.get("estimated_response_ms", 0) for pb in all_pb.values() if pb.get("severity") == "high") / max(1, sum(1 for pb in all_pb.values() if pb.get("severity") == "high"))),
            "medium": round(sum(pb.get("estimated_response_ms", 0) for pb in all_pb.values() if pb.get("severity") == "medium") / max(1, sum(1 for pb in all_pb.values() if pb.get("severity") == "medium"))),
        },
    }
