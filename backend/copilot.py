"""
SOC Copilot — Agentic AI assistant for security analysts.

Hybrid approach:
  - Claude API (when ANTHROPIC_API_KEY is set): Full reasoning, tool-use, report generation
  - Local fallback: Structured responses from scan data without external API
"""

import json
import logging
from typing import Optional, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from config import ANTHROPIC_API_KEY
from database import get_db, Job, FirewallRule, AuditLog
from auth import require_auth, User

logger = logging.getLogger("robustidps.copilot")

router = APIRouter(prefix="/api/copilot", tags=["SOC Copilot"])


class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    api_key: str = ""

class ChatResponse(BaseModel):
    content: str
    provider: str


TOOLS = [
    {
        "name": "get_recent_jobs",
        "description": "Get recent analysis jobs with their results (threats found, model used, etc.)",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of recent jobs to return", "default": 10},
            },
            "required": [],
        },
    },
    {
        "name": "get_job_details",
        "description": "Get detailed results for a specific analysis job by job_id",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The 8-character job ID"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_firewall_rules",
        "description": "Get firewall rules generated for a specific job",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The job ID to get firewall rules for"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_threat_summary",
        "description": "Get an aggregate summary of all threats detected across all jobs",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_audit_logs",
        "description": "Get recent audit log entries (login, upload, predict actions)",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of entries", "default": 20},
            },
            "required": [],
        },
    },
    {
        "name": "get_system_status",
        "description": "Get current system status: model loaded, device (CPU/GPU), user count, job count",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]


def _exec_tool(name: str, args: dict, db: Session) -> str:
    try:
        if name == "get_recent_jobs":
            limit = args.get("limit", 10)
            jobs = db.execute(select(Job).order_by(desc(Job.created_at)).limit(limit)).scalars().all()
            return json.dumps([{"job_id": j.id, "filename": j.filename, "format": j.format_detected, "n_flows": j.n_flows, "n_threats": j.n_threats, "model_used": j.model_used, "created_at": j.created_at.isoformat() if j.created_at else None} for j in jobs])

        elif name == "get_job_details":
            job = db.get(Job, args["job_id"])
            if not job:
                return json.dumps({"error": f"Job {args['job_id']} not found"})
            rules = db.execute(select(FirewallRule).where(FirewallRule.job_id == args["job_id"])).scalars().all()
            return json.dumps({"job_id": job.id, "filename": job.filename, "format": job.format_detected, "n_flows": job.n_flows, "n_threats": job.n_threats, "model_used": job.model_used, "created_at": job.created_at.isoformat() if job.created_at else None, "firewall_rules_count": len(rules), "top_threats": [{"source_ip": r.source_ip, "threat": r.threat_label, "severity": r.severity, "confidence": r.confidence} for r in rules[:10]]})

        elif name == "get_firewall_rules":
            rules = db.execute(select(FirewallRule).where(FirewallRule.job_id == args["job_id"])).scalars().all()
            return json.dumps([{"rule_type": r.rule_type, "source_ip": r.source_ip, "action": r.action, "threat_label": r.threat_label, "severity": r.severity, "confidence": r.confidence, "rule_text": r.rule_text} for r in rules])

        elif name == "get_threat_summary":
            total_jobs = db.execute(select(func.count(Job.id))).scalar() or 0
            total_flows = db.execute(select(func.sum(Job.n_flows))).scalar() or 0
            total_threats = db.execute(select(func.sum(Job.n_threats))).scalar() or 0
            return json.dumps({"total_jobs": total_jobs, "total_flows_analysed": total_flows, "total_threats_detected": total_threats, "threat_rate": round(total_threats / max(total_flows, 1) * 100, 2)})

        elif name == "get_audit_logs":
            limit = args.get("limit", 20)
            logs = db.execute(select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)).scalars().all()
            return json.dumps([{"action": l.action, "resource": l.resource, "details": l.details, "ip_address": l.ip_address, "timestamp": l.timestamp.isoformat() if l.timestamp else None} for l in logs])

        elif name == "get_system_status":
            total_users = db.execute(select(func.count(User.id))).scalar() or 0
            total_jobs = db.execute(select(func.count(Job.id))).scalar() or 0
            from config import DEVICE
            return json.dumps({"device": DEVICE, "total_users": total_users, "total_jobs": total_jobs, "models_available": 8, "platform": "RobustIDPS.ai"})

        return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


SYSTEM_PROMPT = """You are the RobustIDPS.ai SOC Copilot — an AI security analyst assistant embedded in an adversarially-robust intrusion detection and prevention system.

You help security analysts by:
1. Analysing scan results and explaining detected threats in plain language
2. Providing remediation recommendations for detected attacks
3. Generating incident reports from job data
4. Explaining the AI/ML models' decisions and confidence scores
5. Answering questions about network security, attack types, and defence strategies
6. Helping configure and tune the IDPS (firewall rules, thresholds, model selection)

The platform uses an 8-model ensemble:
- SurrogateIDS (7-branch adversarially-trained ensemble)
- CyberSecLLM (Mamba-CrossAttention-MoE architecture)
- MambaShield (selective state-space model)
- Stochastic Transformer (PAC-Bayesian with MC-Dropout)
- Hierarchical Gaussian Processes
- Temporal Graph Neural Networks (CT-TGNN, TripleE-TGNN)
- Federated LLM (FedLLM-API)
- Post-Quantum IDPS (PQ-IDPS)

Attack types detected include: DDoS variants, Brute Force, SQL Injection, XSS, Bot traffic, infiltration, web attacks, SSH/FTP brute force, port scans, and more.

Always use the available tools to look up actual data before answering questions about jobs, threats, or system status. Be specific and data-driven. When explaining threats, include the attack type, severity, affected IPs, and recommended actions."""


def _local_response(messages: list[ChatMessage], db: Session) -> str:
    last_msg = messages[-1].content.lower() if messages else ""

    if any(w in last_msg for w in ["threat", "summary", "overview", "status"]):
        data = json.loads(_exec_tool("get_threat_summary", {}, db))
        status = json.loads(_exec_tool("get_system_status", {}, db))
        return (
            f"**System Status**\n"
            f"- Device: {status['device'].upper()}\n"
            f"- Users: {status['total_users']}\n"
            f"- Models available: {status['models_available']}\n\n"
            f"**Threat Summary**\n"
            f"- Total jobs analysed: {data['total_jobs']}\n"
            f"- Total flows processed: {data['total_flows_analysed']:,}\n"
            f"- Threats detected: {data['total_threats_detected']:,}\n"
            f"- Threat rate: {data['threat_rate']}%\n\n"
            f"*For deeper investigation and AI-powered analysis, add your Anthropic API key in the chat settings.*"
        )

    if any(w in last_msg for w in ["job", "recent", "scan", "analyse"]):
        data = json.loads(_exec_tool("get_recent_jobs", {"limit": 5}, db))
        if not data:
            return "No analysis jobs found yet. Upload a dataset to get started."
        lines = ["**Recent Analysis Jobs**\n"]
        for j in data:
            lines.append(f"- **{j['job_id']}**: {j['filename']} \u2014 {j['n_flows']} flows, {j['n_threats']} threats ({j['model_used']})")
        lines.append("\n*For detailed threat investigation, provide your Anthropic API key.*")
        return "\n".join(lines)

    if any(w in last_msg for w in ["audit", "log", "activity"]):
        data = json.loads(_exec_tool("get_audit_logs", {"limit": 10}, db))
        if not data:
            return "No audit log entries found."
        lines = ["**Recent Activity**\n"]
        for l in data:
            lines.append(f"- [{l['action']}] {l['resource']} from {l['ip_address']} \u2014 {l['details']}")
        return "\n".join(lines)

    if any(w in last_msg for w in ["help", "what can", "how to", "capabilities"]):
        return (
            "**SOC Copilot Capabilities**\n\n"
            "I can help you with:\n"
            "- **Threat analysis**: Ask about detected threats, attack types, and severity\n"
            "- **Job investigation**: Get details on any analysis job by ID\n"
            "- **Incident reports**: Generate reports from scan results\n"
            "- **System status**: Check model status, user activity, threat overview\n"
            "- **Remediation**: Get recommended actions for detected attacks\n"
            "- **Firewall rules**: Review auto-generated rules for any job\n"
            "- **Audit logs**: View recent system activity\n\n"
            "**Local mode** (current): I provide structured data lookups.\n"
            "**Claude API mode**: Add your Anthropic API key for full AI-powered investigation, "
            "natural language analysis, detailed explanations, and report generation."
        )

    return (
        "I'm the RobustIDPS.ai SOC Copilot. I can help you investigate threats, "
        "review scan results, generate reports, and explain detections.\n\n"
        "Try asking:\n"
        "- \"Show me the threat summary\"\n"
        "- \"What are the recent scan jobs?\"\n"
        "- \"Show audit logs\"\n"
        "- \"What can you do?\"\n\n"
        "*Currently running in local mode. Add an Anthropic API key for full AI-powered analysis.*"
    )


async def _claude_stream(messages: list[ChatMessage], api_key: str, db: Session) -> AsyncIterator[str]:
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    api_messages = [{"role": m.role, "content": m.content} for m in messages]

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=TOOLS,
        messages=api_messages,
    )

    for _ in range(5):
        if response.stop_reason != "tool_use":
            break

        tool_results = []
        assistant_content = response.content
        for block in response.content:
            if block.type == "tool_use":
                result = _exec_tool(block.name, block.input, db)
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result})

        api_messages.append({"role": "assistant", "content": assistant_content})
        api_messages.append({"role": "user", "content": tool_results})

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=api_messages,
        )

    for block in response.content:
        if hasattr(block, "text"):
            yield block.text


@router.post("/chat")
async def chat(req: ChatRequest, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    api_key = req.api_key or ANTHROPIC_API_KEY

    if api_key:
        async def generate():
            try:
                async for chunk in _claude_stream(req.messages, api_key, db):
                    yield f"data: {json.dumps({'content': chunk, 'provider': 'claude'})}\n\n"
                yield f"data: {json.dumps({'done': True, 'provider': 'claude'})}\n\n"
            except Exception as e:
                logger.exception("Claude API error")
                yield f"data: {json.dumps({'error': str(e), 'provider': 'claude'})}\n\n"
        return StreamingResponse(generate(), media_type="text/event-stream")
    else:
        content = _local_response(req.messages, db)
        return ChatResponse(content=content, provider="local")


@router.get("/status")
def copilot_status(user: User = Depends(require_auth)):
    return {"claude_configured": bool(ANTHROPIC_API_KEY), "local_available": True}
