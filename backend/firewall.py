"""
Firewall rule generation from detection results.

Generates rules in multiple formats:
  - iptables  (Linux netfilter)
  - nftables  (modern Linux)
  - Snort     (IDS/IPS rules)
  - Suricata  (IDS/IPS rules)

Rules are generated based on detected threats, severity,
and confidence thresholds.
"""

import datetime
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import require_auth
from database import get_db, FirewallRule, Job, User

logger = logging.getLogger("robustidps.firewall")

router = APIRouter(prefix="/api/firewall", tags=["Firewall"])


# ── Schemas ───────────────────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    job_id: str
    rule_type: str = "iptables"        # iptables | nftables | snort | suricata
    min_confidence: float = 0.7
    min_severity: str = "high"         # low | medium | high | critical
    action: str = "DROP"               # DROP | REJECT | LOG


class RuleResponse(BaseModel):
    id: int
    rule_type: str
    source_ip: str
    action: str
    threat_label: str
    severity: str
    confidence: float
    rule_text: str


class GenerateResponse(BaseModel):
    rules: list[RuleResponse]
    total_rules: int
    script: str                        # Full script ready to apply


# ── Severity ordering ─────────────────────────────────────────────────────

SEVERITY_ORDER = {"benign": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Rule generators ──────────────────────────────────────────────────────

def _iptables_rule(src_ip: str, action: str, label: str, sid: int) -> str:
    act = "DROP" if action == "DROP" else "REJECT" if action == "REJECT" else "LOG"
    comment = f"RobustIDPS: {label}"
    if act == "LOG":
        return f'iptables -A INPUT -s {src_ip} -j LOG --log-prefix "[RIDPS:{label}] " -m comment --comment "{comment}"'
    return f'iptables -A INPUT -s {src_ip} -j {act} -m comment --comment "{comment}"'


def _nftables_rule(src_ip: str, action: str, label: str, sid: int) -> str:
    act = "drop" if action == "DROP" else "reject" if action == "REJECT" else "log"
    return f'nft add rule inet filter input ip saddr {src_ip} {act} comment "RobustIDPS: {label}"'


def _snort_rule(src_ip: str, action: str, label: str, sid: int) -> str:
    act = "drop" if action in ("DROP", "REJECT") else "alert"
    return (
        f'{act} ip {src_ip} any -> $HOME_NET any '
        f'(msg:"RobustIDPS: {label}"; sid:{sid}; rev:1; '
        f'classtype:attempted-attack; priority:1;)'
    )


def _suricata_rule(src_ip: str, action: str, label: str, sid: int) -> str:
    act = "drop" if action in ("DROP", "REJECT") else "alert"
    return (
        f'{act} ip {src_ip} any -> $HOME_NET any '
        f'(msg:"RobustIDPS: {label}"; sid:{sid}; rev:1; '
        f'classtype:trojan-activity;)'
    )


_GENERATORS = {
    "iptables": _iptables_rule,
    "nftables": _nftables_rule,
    "snort": _snort_rule,
    "suricata": _suricata_rule,
}


# ── Build script header ──────────────────────────────────────────────────

def _script_header(rule_type: str, n_rules: int) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"# ──────────────────────────────────────────────────────────────\n"
        f"# RobustIDPS.ai — Auto-generated firewall rules\n"
        f"# Format:   {rule_type}\n"
        f"# Rules:    {n_rules}\n"
        f"# Generated: {ts}\n"
        f"# ──────────────────────────────────────────────────────────────\n\n"
    )


# ── Endpoint ──────────────────────────────────────────────────────────────

@router.post("/generate", response_model=GenerateResponse)
def generate_rules(
    body: GenerateRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Generate firewall rules from a completed analysis job."""
    if body.rule_type not in _GENERATORS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported rule type: {body.rule_type}. "
                   f"Supported: {', '.join(_GENERATORS.keys())}",
        )

    # Get job predictions from in-memory store
    from main import job_store
    if body.job_id not in job_store:
        raise HTTPException(status_code=404, detail="Job not found")

    job_data = job_store[body.job_id]
    label_names = job_data.get("label_names")
    if not label_names:
        raise HTTPException(status_code=400, detail="No predictions available for this job")

    # Get predictions to build rules
    from models.surrogate import SurrogateIDS
    from uncertainty import predict_with_uncertainty
    import torch
    from config import DEVICE

    model_ref = job_data.get("_model_ref")
    if model_ref is None:
        from main import model as default_model
        model_ref = default_model

    features = job_data["features"].to(DEVICE)
    result = predict_with_uncertainty(model_ref, features, n_mc=5)  # quick pass

    preds = result["predictions"].cpu()
    confidence = result["confidence"].cpu()
    metadata = job_data["metadata"]

    min_sev = SEVERITY_ORDER.get(body.min_severity, 3)
    generator = _GENERATORS[body.rule_type]
    rules = []
    seen_ips = set()
    sid_counter = 1000000  # start SID

    for i in range(len(preds)):
        cls_idx = preds[i].item()
        label = (
            SurrogateIDS.CLASS_NAMES[cls_idx]
            if cls_idx < len(SurrogateIDS.CLASS_NAMES)
            else f"class_{cls_idx}"
        )
        sev = SurrogateIDS.severity_for(label)
        conf = float(confidence[i])

        # Filter by severity and confidence
        if SEVERITY_ORDER.get(sev, 0) < min_sev:
            continue
        if conf < body.min_confidence:
            continue

        src_ip = (
            str(metadata["src_ip"].iloc[i])
            if "src_ip" in metadata.columns
            else None
        )
        if not src_ip or src_ip in ("", "nan", "0.0.0.0"):
            continue
        if src_ip in seen_ips:
            continue
        seen_ips.add(src_ip)

        sid_counter += 1
        rule_text = generator(src_ip, body.action, label, sid_counter)

        # Save to database
        fw_rule = FirewallRule(
            job_id=body.job_id,
            rule_type=body.rule_type,
            source_ip=src_ip,
            destination_ip="$HOME_NET",
            action=body.action,
            threat_label=label,
            severity=sev,
            confidence=round(conf, 4),
            rule_text=rule_text,
        )
        db.add(fw_rule)
        rules.append(fw_rule)

    db.commit()
    for r in rules:
        db.refresh(r)

    logger.info(
        "Generated %d %s rules for job %s (user=%s)",
        len(rules), body.rule_type, body.job_id, user.email,
    )

    # Build complete script
    script_lines = [_script_header(body.rule_type, len(rules))]
    for r in rules:
        script_lines.append(r.rule_text)
    script = "\n".join(script_lines)

    return GenerateResponse(
        rules=[
            RuleResponse(
                id=r.id, rule_type=r.rule_type, source_ip=r.source_ip,
                action=r.action, threat_label=r.threat_label,
                severity=r.severity, confidence=r.confidence,
                rule_text=r.rule_text,
            )
            for r in rules
        ],
        total_rules=len(rules),
        script=script,
    )


@router.get("/rules/{job_id}")
def get_rules(
    job_id: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Retrieve previously generated firewall rules for a job."""
    rules = (
        db.query(FirewallRule)
        .filter(FirewallRule.job_id == job_id)
        .order_by(FirewallRule.created_at.desc())
        .all()
    )
    return {
        "job_id": job_id,
        "rules": [
            RuleResponse(
                id=r.id, rule_type=r.rule_type, source_ip=r.source_ip,
                action=r.action, threat_label=r.threat_label,
                severity=r.severity, confidence=r.confidence,
                rule_text=r.rule_text,
            )
            for r in rules
        ],
        "total_rules": len(rules),
    }
