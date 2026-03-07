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

from auth import require_auth, require_role
from database import get_db, SessionLocal, AuditLog, Job

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

# ── In-memory incident store ─────────────────────────────────────────────

_incidents: list[dict] = []

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


# ── Endpoints ────────────────────────────────────────────────────────────

@router.get("/playbooks")
async def list_playbooks(user=Depends(require_auth)):
    """List all response playbooks with their configurations."""
    summary = {}
    for pid, pb in PLAYBOOKS.items():
        summary[pid] = {
            **pb,
            "trigger_count": len(pb["trigger_classes"]),
            "step_count": len(pb["response_chain"]),
        }
    return {
        "playbooks": summary,
        "total": len(PLAYBOOKS),
        "auto_execute_enabled": sum(1 for p in PLAYBOOKS.values() if p["auto_execute"]),
        "requires_approval": sum(1 for p in PLAYBOOKS.values() if p["requires_approval"]),
    }


@router.get("/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str, user=Depends(require_auth)):
    """Get detailed playbook configuration."""
    if playbook_id not in PLAYBOOKS:
        raise HTTPException(404, f"Playbook not found: {playbook_id}")
    return PLAYBOOKS[playbook_id]


@router.patch("/playbooks/{playbook_id}/toggle")
async def toggle_playbook(playbook_id: str, body: PlaybookToggleRequest, user=Depends(require_role("admin"))):
    """Enable/disable auto-execution for a playbook (admin only)."""
    if playbook_id not in PLAYBOOKS:
        raise HTTPException(404, f"Playbook not found: {playbook_id}")

    pb = PLAYBOOKS[playbook_id]
    old_value = pb["auto_execute"]
    pb["auto_execute"] = body.auto_execute

    return {
        "playbook_id": playbook_id,
        "name": pb["name"],
        "auto_execute": body.auto_execute,
        "previous": old_value,
        "updated_by": user.email,
        "warning": "Critical playbook — requires human approval even in auto mode" if pb["requires_approval"] else None,
    }


@router.post("/simulate")
@limiter.limit("10/minute")
async def simulate_response(request: Request, body: SimulateRequest, user=Depends(require_auth)):
    """Simulate a threat response playbook execution with detailed step timing."""
    if body.playbook_id not in PLAYBOOKS:
        raise HTTPException(404, f"Playbook not found: {body.playbook_id}")

    pb = PLAYBOOKS[body.playbook_id]
    threat_label = body.threat_label or (pb["trigger_classes"][0] if pb["trigger_classes"] else "Unknown")

    # Simulate execution of each step
    incident_id = f"INC-{secrets.token_hex(4).upper()}"
    steps_executed = []
    total_time_ms = 0
    t_start = time.perf_counter()

    for step in pb["response_chain"]:
        step_start = time.perf_counter()
        # Simulate processing with realistic timing
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

    incident = {
        "incident_id": incident_id,
        "playbook_id": body.playbook_id,
        "playbook_name": pb["name"],
        "severity": pb["severity"],
        "source_ip": body.source_ip,
        "target_ip": body.target_ip,
        "threat_label": threat_label,
        "confidence": body.confidence,
        "mode": "simulation",
        "steps": steps_executed,
        "total_simulated_ms": total_time_ms,
        "actual_execution_ms": round((t_end - t_start) * 1000, 1),
        "effectiveness_score": pb["effectiveness_score"],
        "false_positive_rate": pb["false_positive_rate"],
        "triggered_by": user.email,
        "timestamp": datetime.utcnow().isoformat(),
        "notes": [],
    }

    _incidents.append(incident)

    return incident


@router.get("/incidents")
async def list_incidents(
    limit: int = 50,
    severity: Optional[str] = None,
    user=Depends(require_auth),
):
    """List recent incidents (simulated and real)."""
    filtered = _incidents
    if severity:
        filtered = [i for i in filtered if i.get("severity") == severity]

    return {
        "incidents": list(reversed(filtered[-limit:])),
        "total": len(filtered),
        "by_severity": {
            "critical": sum(1 for i in _incidents if i.get("severity") == "critical"),
            "high": sum(1 for i in _incidents if i.get("severity") == "high"),
            "medium": sum(1 for i in _incidents if i.get("severity") == "medium"),
            "low": sum(1 for i in _incidents if i.get("severity") == "low"),
        },
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, user=Depends(require_auth)):
    """Get detailed incident timeline."""
    for inc in _incidents:
        if inc["incident_id"] == incident_id:
            return inc
    raise HTTPException(404, f"Incident not found: {incident_id}")


@router.post("/incidents/{incident_id}/note")
async def add_incident_note(incident_id: str, body: IncidentNoteRequest, user=Depends(require_auth)):
    """Add analyst note to an incident."""
    for inc in _incidents:
        if inc["incident_id"] == incident_id:
            note = {
                "author": user.email,
                "note": body.note,
                "timestamp": datetime.utcnow().isoformat(),
            }
            inc.setdefault("notes", []).append(note)
            return {"incident_id": incident_id, "note_added": note, "total_notes": len(inc["notes"])}
    raise HTTPException(404, f"Incident not found: {incident_id}")


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
async def response_metrics(user=Depends(require_auth)):
    """Get aggregated response metrics across all playbooks and incidents."""
    playbook_metrics = []
    for pid, pb in PLAYBOOKS.items():
        related_incidents = [i for i in _incidents if i.get("playbook_id") == pid]
        playbook_metrics.append({
            "playbook_id": pid,
            "name": pb["name"],
            "severity": pb["severity"],
            "incidents_triggered": len(related_incidents),
            "effectiveness_score": pb["effectiveness_score"],
            "false_positive_rate": pb["false_positive_rate"],
            "avg_response_ms": pb["estimated_response_ms"],
            "auto_execute": pb["auto_execute"],
            "step_count": len(pb["response_chain"]),
            "trigger_classes": len(pb["trigger_classes"]),
        })

    total_incidents = len(_incidents)
    avg_effectiveness = round(
        sum(p["effectiveness_score"] for p in playbook_metrics) / len(playbook_metrics) * 100, 1
    ) if playbook_metrics else 0

    # Coverage analysis — which attack classes have playbooks
    covered_classes = set()
    for pb in PLAYBOOKS.values():
        covered_classes.update(pb["trigger_classes"])

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
            "total_playbooks": len(PLAYBOOKS),
            "total_incidents": total_incidents,
            "avg_effectiveness": avg_effectiveness,
            "coverage": {
                "covered_classes": len(covered_classes),
                "total_threat_classes": len(all_classes) - 1,  # exclude Benign
                "coverage_percentage": round(len(covered_classes) / (len(all_classes) - 1) * 100, 1),
                "uncovered_classes": uncovered,
            },
        },
        "mttr_by_severity": {
            "critical": round(sum(pb["estimated_response_ms"] for pb in PLAYBOOKS.values() if pb["severity"] == "critical") / max(1, sum(1 for pb in PLAYBOOKS.values() if pb["severity"] == "critical"))),
            "high": round(sum(pb["estimated_response_ms"] for pb in PLAYBOOKS.values() if pb["severity"] == "high") / max(1, sum(1 for pb in PLAYBOOKS.values() if pb["severity"] == "high"))),
            "medium": round(sum(pb["estimated_response_ms"] for pb in PLAYBOOKS.values() if pb["severity"] == "medium") / max(1, sum(1 for pb in PLAYBOOKS.values() if pb["severity"] == "medium"))),
        },
    }
