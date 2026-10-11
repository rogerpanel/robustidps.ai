"""A2A (Agent-to-Agent) protocol wrapper — verdict-check every cross-agent
message envelope. Compatible with the Anthropic/Google A2A spec drafts
where agents exchange JSON envelopes over HTTP(S) with declared
capabilities + auth contexts.

The wrapper is framework-less — it operates on dicts that follow the A2A
shape, so it slots into any A2A runtime (the official a2a-sdk, custom
in-house servers, etc.) without pulling additional deps.

    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.a2a import scan_capability, check_message

    cli = MambaGuardClient()
    # At server startup — verdict-check the published capability card
    scan_capability(my_agent_capability_card, cli)
    # Per inbound message
    verdict = check_message(envelope, cli)
    if verdict.blocked:
        return {"error": "blocked by aegis", "findings": verdict.findings}
"""
from __future__ import annotations

import json
from typing import Any

from robustidps.aegis.client import MambaGuardClient, Verdict


def scan_capability(capability_card: dict[str, Any],
                    client: MambaGuardClient | None = None) -> Verdict:
    """Verdict-check a published A2A capability card at server startup.

    A2A capability cards declare what an agent can do (tools, scopes,
    auth requirements). The same risks that hide in MCP manifests hide
    here — credential leakage, side-effect language in tool descriptions,
    rogue-identity claims, missing auth declarations.
    """
    client = client or MambaGuardClient()
    text = json.dumps(capability_card, indent=2, default=str)
    return client.check(text, input_kind="agent_card",
                        context={"agent_id": capability_card.get("agent_id"),
                                 "protocol": "a2a"})


def check_message(envelope: dict[str, Any],
                  client: MambaGuardClient | None = None) -> Verdict:
    """Per-message verdict check on an inbound A2A envelope.

    An envelope typically has: sender_agent_id, recipient_agent_id,
    intent, payload, auth_token. The scanner runs over the assembled
    text so payload prompt-injection attempts and rogue-sender claims
    both surface.
    """
    client = client or MambaGuardClient()
    fields = [
        f"sender: {envelope.get('sender_agent_id', 'unknown')}",
        f"recipient: {envelope.get('recipient_agent_id', 'unknown')}",
        f"intent: {envelope.get('intent', 'unknown')}",
        f"payload: {json.dumps(envelope.get('payload', {}), default=str)}",
    ]
    text = "\n".join(fields)
    return client.check(text, input_kind="agent_card",
                        context={"sender": envelope.get("sender_agent_id"),
                                 "protocol": "a2a"})
