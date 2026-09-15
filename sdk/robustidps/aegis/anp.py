"""ANP (Agent Network Protocol) wrapper — verdict-check the DID-based
agent discovery + capability negotiation messages.

ANP layers agent communication over W3C DIDs and JSON-LD; the security
risks are the same as A2A/MCP plus DID-spoofing (impersonating a
trusted agent's identity in the DID document) and capability inflation
(claiming more scopes than were granted).

    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.anp import scan_did_document, check_capability_request

    cli = MambaGuardClient()
    scan_did_document(my_did_doc, cli)        # at agent startup
    verdict = check_capability_request(req, cli)
"""
from __future__ import annotations

import json
from typing import Any

from robustidps.aegis.client import MambaGuardClient, Verdict


def scan_did_document(did_doc: dict[str, Any],
                      client: MambaGuardClient | None = None) -> Verdict:
    """Verdict-check a W3C DID document used as an agent's ANP identity.

    Particularly looks for: declared verification methods pointing at
    suspicious URIs, service endpoints over file:// or unauthenticated
    schemes, rogue-identity strings in the controller field.
    """
    client = client or MambaGuardClient()
    text = json.dumps(did_doc, indent=2, default=str)
    return client.check(text, input_kind="agent_card",
                        context={"did": did_doc.get("id"),
                                 "protocol": "anp"})


def check_capability_request(request: dict[str, Any],
                             client: MambaGuardClient | None = None) -> Verdict:
    """Verdict-check an inbound ANP capability-request message.

    Typical fields: requester_did, requested_scopes, granted_scopes,
    proof_of_grant. The scanner surfaces capability-inflation attempts
    (asking for more than was granted) and prompt-injection in the
    free-text rationale field.
    """
    client = client or MambaGuardClient()
    fields = [
        f"requester: {request.get('requester_did', 'unknown')}",
        f"requested_scopes: {json.dumps(request.get('requested_scopes', []), default=str)}",
        f"granted_scopes: {json.dumps(request.get('granted_scopes', []), default=str)}",
        f"rationale: {request.get('rationale', '')}",
    ]
    requested = set(request.get("requested_scopes") or [])
    granted = set(request.get("granted_scopes") or [])
    inflated = requested - granted
    text = "\n".join(fields)
    if inflated:
        text += f"\ncapability_inflation_detected: {sorted(inflated)}"
    return client.check(text, input_kind="agent_card",
                        context={"requester": request.get("requester_did"),
                                 "protocol": "anp",
                                 "inflated_scopes": sorted(inflated)})
