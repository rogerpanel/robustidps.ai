"""Stripe Checkout session creation + post-purchase customer record.

DB-backed (SQLAlchemy via database.SessionLocal / get_db). Staging
mode still works when STRIPE_SECRET_KEY is unset.

Production env:
  STRIPE_SECRET_KEY=sk_live_...
  STRIPE_PRICE_PRO=price_...
  STRIPE_PRICE_ENTERPRISE=price_...
  STRIPE_SUCCESS_URL=https://robustidps.ai/agent-studio/account?session_id={CHECKOUT_SESSION_ID}
  STRIPE_CANCEL_URL=https://robustidps.ai/agent-studio
"""
from __future__ import annotations

import datetime
import hashlib
import os
import secrets
from typing import Literal

from sqlalchemy.orm import Session

from plugins.agent_studio.db_models import (
    AgentStudioCustomer, AgentStudioApiKey,
)

Tier = Literal["pro", "enterprise"]

DEFAULT_SUCCESS_URL = "https://robustidps.ai/agent-studio/account?session_id={CHECKOUT_SESSION_ID}"
DEFAULT_CANCEL_URL = "https://robustidps.ai/agent-studio"


# ── Stripe Checkout (live or staging) ─────────────────────────────────

def create_checkout_session(email: str, tier: Tier, trial_days: int = 14) -> dict:
    """Pure: doesn't need the DB. Returns a redirect URL (live or staging)."""
    secret = os.getenv("STRIPE_SECRET_KEY")
    price_id = (os.getenv("STRIPE_PRICE_PRO") if tier == "pro"
                else os.getenv("STRIPE_PRICE_ENTERPRISE"))
    success_url = os.getenv("STRIPE_SUCCESS_URL", DEFAULT_SUCCESS_URL)
    cancel_url = os.getenv("STRIPE_CANCEL_URL", DEFAULT_CANCEL_URL)

    if not secret or not price_id:
        session_id = f"cs_staging_{secrets.token_urlsafe(20)}"
        return {
            "mode": "staging",
            "session_id": session_id,
            "url": success_url.replace("{CHECKOUT_SESSION_ID}", session_id),
            "tier": tier, "email": email, "trial_days": trial_days,
            "hint": ("STRIPE_SECRET_KEY + STRIPE_PRICE_{PRO|ENTERPRISE} unset; "
                     "staging mode. On confirmation, an API key will issue "
                     "without charging."),
        }

    try:
        import stripe
        stripe.api_key = secret
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            customer_email=email,
            line_items=[{"price": price_id, "quantity": 1}],
            subscription_data={"trial_period_days": trial_days},
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return {
            "mode": "live", "session_id": session.id, "url": session.url,
            "tier": tier, "email": email, "trial_days": trial_days,
        }
    except Exception as e:
        return {"mode": "error", "error": str(e), "tier": tier, "email": email}


# ── Post-checkout fulfilment ──────────────────────────────────────────

def complete_checkout(db: Session, session_id: str, email: str, tier: Tier) -> dict:
    secret = os.getenv("STRIPE_SECRET_KEY")
    stripe_customer_id = None
    stripe_subscription_id = None
    if secret and session_id.startswith("cs_"):
        try:
            import stripe
            stripe.api_key = secret
            session = stripe.checkout.Session.retrieve(session_id)
            stripe_customer_id = session.customer
            stripe_subscription_id = session.subscription
            email = session.customer_email or email
        except Exception:
            pass

    customer_id = f"cust_{secrets.token_urlsafe(10)}"
    trial_ends = _iso_date(datetime.datetime.utcnow() + datetime.timedelta(days=14))

    customer = AgentStudioCustomer(
        customer_id=customer_id, email=email, tier=tier,
        created_at=datetime.datetime.utcnow(),
        trial_ends_at=trial_ends,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
    )
    db.add(customer)
    db.flush()    # let the FK be visible to issue_api_key

    api_key = issue_api_key(db, customer_id, label="initial-key")
    key_row = db.query(AgentStudioApiKey).filter_by(
        customer_id=customer_id).order_by(AgentStudioApiKey.created_at.desc()).first()
    db.commit()

    return {
        "customer_id": customer_id, "email": email, "tier": tier,
        "trial_ends_at": trial_ends,
        "api_key": api_key,
        "api_key_id": key_row.id if key_row else None,
        "welcome_message": (
            f"Welcome to Agent Studio {tier.title()}. Your 14-day trial "
            f"ends {trial_ends}. Save the API key now — it's the only "
            f"time we show the plaintext."
        ),
    }


# ── API key issuance ──────────────────────────────────────────────────

def issue_api_key(db: Session, customer_id: str, label: str = "default") -> str:
    customer = db.get(AgentStudioCustomer, customer_id)
    if customer is None:
        raise KeyError(f"Unknown customer: {customer_id}")
    raw = f"rids_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    key = AgentStudioApiKey(
        id=f"key_{secrets.token_urlsafe(8)}",
        customer_id=customer_id,
        label=label,
        prefix=raw[:14],
        key_hash=key_hash,
        created_at=datetime.datetime.utcnow(),
        revoked=False,
    )
    db.add(key)
    db.commit()
    return raw


def revoke_api_key(db: Session, customer_id: str, key_id: str) -> dict:
    key = db.query(AgentStudioApiKey).filter_by(
        id=key_id, customer_id=customer_id).first()
    if key is None:
        return {"ok": False, "error": "unknown customer or key_id"}
    key.revoked = True
    db.commit()
    return {"ok": True, "key_id": key_id, "revoked": True}


def get_customer(db: Session, customer_id: str) -> dict | None:
    customer = db.get(AgentStudioCustomer, customer_id)
    if customer is None:
        return None
    return _serialize(customer)


def list_customers(db: Session) -> list[dict]:
    return [_serialize(c) for c in db.query(AgentStudioCustomer).all()]


def _serialize(c: AgentStudioCustomer) -> dict:
    return {
        "customer_id": c.customer_id, "email": c.email, "tier": c.tier,
        "created_at": _iso_dt(c.created_at),
        "trial_ends_at": c.trial_ends_at,
        "stripe_customer_id": c.stripe_customer_id,
        "stripe_subscription_id": c.stripe_subscription_id,
        "api_keys": [
            {"id": k.id, "label": k.label, "prefix": k.prefix + "…",
             "created_at": _iso_dt(k.created_at),
             "last_used_at": _iso_dt(k.last_used_at),
             "revoked": k.revoked}
            for k in c.api_keys
        ],
    }


def _iso_dt(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def _iso_date(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)
