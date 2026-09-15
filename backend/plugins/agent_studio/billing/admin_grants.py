"""Admin-issued licences — DB-backed (Sprint 4 migration).

For users who can't (or won't) pay via Stripe: regions where Stripe
doesn't operate, bank-wire customers, crypto payers, comp accounts.

Each grant creates a Customer row + an initial API key in the same
transaction. payment_rail records *how* the user paid, audit only.
"""
from __future__ import annotations

import datetime
import secrets
from typing import Literal

from sqlalchemy.orm import Session

from plugins.agent_studio.billing.checkout import issue_api_key, _iso_dt, _iso_date
from plugins.agent_studio.db_models import (
    AgentStudioCustomer, AgentStudioAdminGrant, AgentStudioApiKey,
)

Tier = Literal["pro", "enterprise"]
PaymentRail = Literal[
    "wire", "crypto", "yoomoney", "qiwi", "sbp",
    "bank_card_offshore", "comp", "sponsorship", "other",
]


def grant_license(
    db: Session,
    email: str,
    tier: Tier = "pro",
    months: int = 12,
    payment_rail: PaymentRail = "comp",
    note: str = "",
    granted_by: str = "admin",
) -> dict:
    customer_id = f"cust_{secrets.token_urlsafe(10)}"
    now = datetime.datetime.utcnow()
    expires_at = (None if months <= 0
                  else (now + datetime.timedelta(days=months * 30)).strftime("%Y-%m-%d"))
    trial_ends = expires_at

    customer = AgentStudioCustomer(
        customer_id=customer_id, email=email, tier=tier,
        created_at=now, trial_ends_at=trial_ends,
    )
    db.add(customer)
    db.flush()

    api_key = issue_api_key(db, customer_id, label="admin-grant-initial")
    key_row = db.query(AgentStudioApiKey).filter_by(
        customer_id=customer_id).order_by(AgentStudioApiKey.created_at.desc()).first()

    grant = AgentStudioAdminGrant(
        grant_id=f"grnt_{secrets.token_urlsafe(8)}",
        customer_id=customer_id, email=email, tier=tier,
        months=months, payment_rail=payment_rail,
        granted_at=now, granted_by=granted_by,
        expires_at=expires_at, note=note,
    )
    db.add(grant)
    db.commit()

    return {
        "grant_id": grant.grant_id, "customer_id": customer_id,
        "email": email, "tier": tier, "months": months,
        "payment_rail": payment_rail, "expires_at": expires_at,
        "api_key": api_key,
        "key_id": key_row.id if key_row else None,
        "note": note,
        "welcome_message": (
            f"Granted {tier.title()} access to {email} via {payment_rail} "
            f"({'perpetual' if months <= 0 else f'{months} months'}). "
            f"Send the API key to the customer — it's the only time we show it."
        ),
    }


def revoke_grant(db: Session, grant_id: str, revoked_by: str = "admin") -> dict:
    grant = db.get(AgentStudioAdminGrant, grant_id)
    if grant is None:
        return {"ok": False, "error": "unknown grant_id"}
    if grant.revoked_at:
        return {"ok": False, "error": "already revoked",
                "revoked_at": _iso_dt(grant.revoked_at)}

    # Revoke every key for the customer too
    for key in db.query(AgentStudioApiKey).filter_by(customer_id=grant.customer_id).all():
        key.revoked = True

    grant.revoked_at = datetime.datetime.utcnow()
    db.commit()
    return {
        "ok": True, "grant_id": grant_id, "customer_id": grant.customer_id,
        "revoked_at": _iso_dt(grant.revoked_at), "revoked_by": revoked_by,
    }


def list_grants(db: Session, include_revoked: bool = True) -> list[dict]:
    q = db.query(AgentStudioAdminGrant)
    if not include_revoked:
        q = q.filter(AgentStudioAdminGrant.revoked_at.is_(None))
    return [_serialize(g) for g in q.order_by(AgentStudioAdminGrant.granted_at.desc()).all()]


def grant_stats(db: Session) -> dict:
    grants = db.query(AgentStudioAdminGrant).all()
    active = [g for g in grants if g.revoked_at is None]
    by_rail: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    for g in active:
        by_rail[g.payment_rail] = by_rail.get(g.payment_rail, 0) + 1
        by_tier[g.tier] = by_tier.get(g.tier, 0) + 1
    return {
        "n_total": len(grants), "n_active": len(active),
        "n_revoked": len(grants) - len(active),
        "by_payment_rail": by_rail, "by_tier": by_tier,
    }


def _serialize(g: AgentStudioAdminGrant) -> dict:
    return {
        "grant_id": g.grant_id, "customer_id": g.customer_id,
        "email": g.email, "tier": g.tier, "months": g.months,
        "payment_rail": g.payment_rail,
        "granted_at": _iso_dt(g.granted_at),
        "granted_by": g.granted_by,
        "expires_at": g.expires_at,
        "note": g.note or "",
        "revoked_at": _iso_dt(g.revoked_at),
    }
