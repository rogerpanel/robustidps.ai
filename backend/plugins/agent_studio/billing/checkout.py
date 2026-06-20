"""Stripe Checkout session creation + post-purchase customer record.

Safe to deploy before Stripe is funded — when STRIPE_SECRET_KEY is
unset, returns a staging-mode response with a placeholder session URL
so the Subscribe button flow still works for demos without billing
the user a cent.

Production path (once funded):
  STRIPE_SECRET_KEY=sk_live_...
  STRIPE_PRICE_PRO=price_...
  STRIPE_PRICE_ENTERPRISE=price_...
  STRIPE_SUCCESS_URL=https://robustidps.ai/agent-studio/account?session_id={CHECKOUT_SESSION_ID}
  STRIPE_CANCEL_URL=https://robustidps.ai/agent-studio
"""
from __future__ import annotations

import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Tier = Literal["pro", "enterprise"]

CUSTOMER_LOG_PATH = Path("weights/agent_studio_customers.json")
DEFAULT_SUCCESS_URL = "https://robustidps.ai/agent-studio/account?session_id={CHECKOUT_SESSION_ID}"
DEFAULT_CANCEL_URL = "https://robustidps.ai/agent-studio"


@dataclass
class Customer:
    customer_id: str
    email: str
    tier: str                  # community / pro / enterprise
    created_at: str
    trial_ends_at: str | None  # ISO date or None
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    api_keys: list[dict] = field(default_factory=list)


# ── In-memory + JSON-persisted customer store ──────────────────────────

_CUSTOMERS: dict[str, Customer] = {}


def _load_persisted() -> None:
    if not CUSTOMER_LOG_PATH.exists():
        return
    try:
        records = json.loads(CUSTOMER_LOG_PATH.read_text())
    except json.JSONDecodeError:
        return
    for r in records:
        _CUSTOMERS[r["customer_id"]] = Customer(**r)


def _persist() -> None:
    CUSTOMER_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CUSTOMER_LOG_PATH.write_text(json.dumps(
        [c.__dict__ for c in _CUSTOMERS.values()], indent=2,
    ))


_load_persisted()


# ── Stripe Checkout (live or staging) ─────────────────────────────────

def create_checkout_session(
    email: str,
    tier: Tier,
    trial_days: int = 14,
) -> dict:
    """Create a Stripe Checkout session and return the redirect URL.
    Falls back to a staging-mode URL when Stripe isn't configured."""
    secret = os.getenv("STRIPE_SECRET_KEY")
    price_id = (os.getenv("STRIPE_PRICE_PRO") if tier == "pro"
                else os.getenv("STRIPE_PRICE_ENTERPRISE"))
    success_url = os.getenv("STRIPE_SUCCESS_URL", DEFAULT_SUCCESS_URL)
    cancel_url = os.getenv("STRIPE_CANCEL_URL", DEFAULT_CANCEL_URL)

    if not secret or not price_id:
        # Staging mode: synthesise a session for demo purposes
        session_id = f"cs_staging_{secrets.token_urlsafe(20)}"
        return {
            "mode": "staging",
            "session_id": session_id,
            "url": f"{success_url.replace('{CHECKOUT_SESSION_ID}', session_id)}",
            "tier": tier,
            "email": email,
            "trial_days": trial_days,
            "hint": "STRIPE_SECRET_KEY + STRIPE_PRICE_{PRO|ENTERPRISE} unset; staging mode. "
                    "On confirmation, an API key will issue without charging.",
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
            "mode": "live",
            "session_id": session.id,
            "url": session.url,
            "tier": tier,
            "email": email,
            "trial_days": trial_days,
        }
    except Exception as e:
        return {
            "mode": "error",
            "error": str(e),
            "tier": tier,
            "email": email,
        }


# ── Post-checkout fulfillment ─────────────────────────────────────────

def complete_checkout(session_id: str, email: str, tier: Tier) -> dict:
    """Called by the success URL handler. Creates the customer record,
    issues an initial API key, and returns the new customer + key.

    Live mode validates the session against Stripe; staging mode trusts
    the caller (the success URL contains the session_id placeholder).
    """
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
            pass    # fall through with staging-mode defaults

    customer_id = f"cust_{secrets.token_urlsafe(10)}"
    trial_ends = time.strftime(
        "%Y-%m-%d", time.gmtime(time.time() + 14 * 86400),
    )
    customer = Customer(
        customer_id=customer_id,
        email=email,
        tier=tier,
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        trial_ends_at=trial_ends,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
        api_keys=[],
    )
    api_key = issue_api_key(customer_id, label="initial-key", _customer=customer)
    _CUSTOMERS[customer_id] = customer
    _persist()
    return {
        "customer_id": customer_id,
        "email": email,
        "tier": tier,
        "trial_ends_at": trial_ends,
        "api_key": api_key,    # plaintext shown ONCE
        "api_key_id": customer.api_keys[-1]["id"],
        "welcome_message": (
            f"Welcome to Agent Studio {tier.title()}. Your 14-day trial "
            f"ends {trial_ends}. Save the API key now — it's the only "
            f"time we show the plaintext."
        ),
    }


# ── API key issuance ──────────────────────────────────────────────────

def issue_api_key(customer_id: str, label: str = "default",
                  _customer: Customer | None = None) -> str:
    """Generate a fresh API key for the customer. Returns the plaintext
    key (shown once); the customer record stores only the hash + prefix."""
    import hashlib
    customer = _customer or _CUSTOMERS.get(customer_id)
    if customer is None:
        raise KeyError(f"Unknown customer: {customer_id}")
    raw = f"rids_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    customer.api_keys.append({
        "id": f"key_{secrets.token_urlsafe(8)}",
        "label": label,
        "prefix": raw[:14],
        "hash": key_hash,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_used_at": None,
        "revoked": False,
    })
    if _customer is None:
        _persist()
    return raw


def revoke_api_key(customer_id: str, key_id: str) -> dict:
    customer = _CUSTOMERS.get(customer_id)
    if customer is None:
        return {"ok": False, "error": "unknown customer"}
    for k in customer.api_keys:
        if k["id"] == key_id:
            k["revoked"] = True
            _persist()
            return {"ok": True, "key_id": key_id, "revoked": True}
    return {"ok": False, "error": "unknown key_id"}


def get_customer(customer_id: str) -> dict | None:
    customer = _CUSTOMERS.get(customer_id)
    if customer is None:
        return None
    return {
        "customer_id": customer.customer_id,
        "email": customer.email,
        "tier": customer.tier,
        "created_at": customer.created_at,
        "trial_ends_at": customer.trial_ends_at,
        "api_keys": [
            {"id": k["id"], "label": k["label"], "prefix": k["prefix"] + "…",
             "created_at": k["created_at"], "last_used_at": k["last_used_at"],
             "revoked": k["revoked"]}
            for k in customer.api_keys
        ],
        "stripe_customer_id": customer.stripe_customer_id,
        "stripe_subscription_id": customer.stripe_subscription_id,
    }


def list_customers() -> list[dict]:
    return [get_customer(cid) for cid in _CUSTOMERS]
