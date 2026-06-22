"""Admin-issued licences — the side-channel access path.

For users who can't (or won't) pay via Stripe: regions where Stripe
doesn't operate (Russia, Crimea, Iran, …), bank-wire customers, crypto
payers, comp accounts, sponsorships.

The admin holds `ROBUSTIDPS_ADMIN_TOKEN` and POSTs to
`/api/agent-studio/admin/grants`. Each grant creates a Customer record
+ issues an initial API key — exactly the same shape Stripe Checkout
produces, so downstream code (entitlement, runtime, dossier) sees no
difference.

The `payment_rail` field records *how* the user paid, for audit only:

    wire | crypto | yoomoney | qiwi | sbp | bank_card_offshore |
    comp | sponsorship | other
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from plugins.agent_studio.billing.checkout import (
    Customer, _CUSTOMERS, _persist, issue_api_key,
)

Tier = Literal["pro", "enterprise"]
PaymentRail = Literal[
    "wire", "crypto", "yoomoney", "qiwi", "sbp",
    "bank_card_offshore", "comp", "sponsorship", "other",
]

GRANT_LOG_PATH = Path("weights/agent_studio_admin_grants.json")


@dataclass
class AdminGrant:
    grant_id: str
    customer_id: str
    email: str
    tier: str
    months: int            # billing-cycle equivalent (0 = perpetual / comp)
    payment_rail: str
    granted_at: str
    granted_by: str
    expires_at: str | None
    note: str = ""
    revoked_at: str | None = None


_GRANTS: list[AdminGrant] = []


def _load_grants() -> None:
    if not GRANT_LOG_PATH.exists():
        return
    try:
        records = json.loads(GRANT_LOG_PATH.read_text())
    except json.JSONDecodeError:
        return
    for r in records:
        _GRANTS.append(AdminGrant(**r))


def _persist_grants() -> None:
    GRANT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    GRANT_LOG_PATH.write_text(json.dumps(
        [g.__dict__ for g in _GRANTS], indent=2,
    ))


_load_grants()


def grant_license(
    email: str,
    tier: Tier = "pro",
    months: int = 12,
    payment_rail: PaymentRail = "comp",
    note: str = "",
    granted_by: str = "admin",
) -> dict:
    """Create a customer + initial API key without touching Stripe."""
    customer_id = f"cust_{secrets.token_urlsafe(10)}"
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    expires_at = (
        None if months <= 0
        else time.strftime("%Y-%m-%d", time.gmtime(time.time() + months * 30 * 86400))
    )
    trial_ends = (
        None if months <= 0
        else time.strftime("%Y-%m-%d", time.gmtime(time.time() + months * 30 * 86400))
    )

    customer = Customer(
        customer_id=customer_id,
        email=email,
        tier=tier,
        created_at=now,
        trial_ends_at=trial_ends,
        stripe_customer_id=None,
        stripe_subscription_id=None,
        api_keys=[],
    )
    api_key = issue_api_key(customer_id, label="admin-grant-initial", _customer=customer)
    _CUSTOMERS[customer_id] = customer
    _persist()

    grant = AdminGrant(
        grant_id=f"grnt_{secrets.token_urlsafe(8)}",
        customer_id=customer_id,
        email=email,
        tier=tier,
        months=months,
        payment_rail=payment_rail,
        granted_at=now,
        granted_by=granted_by,
        expires_at=expires_at,
        note=note,
        revoked_at=None,
    )
    _GRANTS.append(grant)
    _persist_grants()

    return {
        "grant_id": grant.grant_id,
        "customer_id": customer_id,
        "email": email,
        "tier": tier,
        "months": months,
        "payment_rail": payment_rail,
        "expires_at": expires_at,
        "api_key": api_key,    # plaintext shown ONCE
        "key_id": customer.api_keys[-1]["id"],
        "note": note,
        "welcome_message": (
            f"Granted {tier.title()} access to {email} via {payment_rail} "
            f"({'perpetual' if months <= 0 else f'{months} months'}). "
            f"Send the API key to the customer — it's the only time we show it."
        ),
    }


def revoke_grant(grant_id: str, revoked_by: str = "admin") -> dict:
    """Revoke a grant and all of its issued API keys."""
    grant = next((g for g in _GRANTS if g.grant_id == grant_id), None)
    if grant is None:
        return {"ok": False, "error": "unknown grant_id"}
    if grant.revoked_at:
        return {"ok": False, "error": "already revoked", "revoked_at": grant.revoked_at}

    customer = _CUSTOMERS.get(grant.customer_id)
    if customer is not None:
        for k in customer.api_keys:
            k["revoked"] = True
        _persist()

    grant.revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _persist_grants()
    return {
        "ok": True, "grant_id": grant_id, "customer_id": grant.customer_id,
        "revoked_at": grant.revoked_at, "revoked_by": revoked_by,
    }


def list_grants(include_revoked: bool = True) -> list[dict]:
    items = _GRANTS if include_revoked else [g for g in _GRANTS if not g.revoked_at]
    return [g.__dict__ for g in items]


def grant_stats() -> dict:
    active = [g for g in _GRANTS if not g.revoked_at]
    by_rail: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    for g in active:
        by_rail[g.payment_rail] = by_rail.get(g.payment_rail, 0) + 1
        by_tier[g.tier] = by_tier.get(g.tier, 0) + 1
    return {
        "n_total": len(_GRANTS),
        "n_active": len(active),
        "n_revoked": len(_GRANTS) - len(active),
        "by_payment_rail": by_rail,
        "by_tier": by_tier,
    }
