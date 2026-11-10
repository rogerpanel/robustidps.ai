"""Stripe webhook receiver — translates Stripe subscription events into
tier updates on the platform user model.

Designed to be safe to deploy before the Stripe account is funded:
parse_event() validates the signature when STRIPE_WEBHOOK_SECRET is set
and accepts unsigned-but-well-formed JSON for staging. handle_event()
maps the events into a structured intent record; the actual user-table
mutation happens through the platform's existing auth/user module if
present.

Configure in production:
    STRIPE_SECRET_KEY=sk_live_...
    STRIPE_WEBHOOK_SECRET=whsec_...
    STRIPE_PRICE_PRO=price_...
    STRIPE_PRICE_ENTERPRISE=price_...
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

SUBSCRIPTION_EVENT_TYPES = {
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.paid",
    "invoice.payment_failed",
}


def _price_to_tier(price_id: str | None) -> str | None:
    """Map a Stripe price ID to a tier name via env config."""
    if not price_id:
        return None
    if price_id == os.getenv("STRIPE_PRICE_PRO"):
        return "pro"
    if price_id == os.getenv("STRIPE_PRICE_ENTERPRISE"):
        return "enterprise"
    return None


def parse_event(payload: bytes, signature: str | None) -> dict[str, Any]:
    """Decode the webhook payload. When STRIPE_WEBHOOK_SECRET is set,
    require a valid signature. Otherwise accept JSON for staging."""
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if secret:
        try:
            import stripe
            return stripe.Webhook.construct_event(payload, signature or "", secret)
        except Exception as e:
            raise ValueError(f"Stripe signature verification failed: {e}") from e
    # No secret configured → staging mode
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid JSON payload: {e}") from e


def handle_event(event: dict[str, Any]) -> dict[str, Any]:
    """Turn a Stripe event into a tier-change intent. Returns the
    intent record so the caller can apply it to whatever user store is
    in use (the existing auth.py user table, in this platform)."""
    event_type = event.get("type", "unknown")
    data = (event.get("data") or {}).get("object") or {}

    if event_type not in SUBSCRIPTION_EVENT_TYPES:
        return {"handled": False, "event_type": event_type, "reason": "ignored_event_type"}

    customer_id = data.get("customer")
    customer_email = data.get("customer_email") or (data.get("customer_details") or {}).get("email")

    if event_type == "customer.subscription.deleted":
        intent = {
            "action": "downgrade",
            "tier": "community",
            "customer_id": customer_id,
            "customer_email": customer_email,
            "reason": "subscription_cancelled",
        }
    elif event_type == "invoice.payment_failed":
        intent = {
            "action": "flag_dunning",
            "customer_id": customer_id,
            "customer_email": customer_email,
            "reason": "payment_failed",
        }
    else:
        # subscription.created / updated / invoice.paid
        price_id = None
        items = (data.get("items") or {}).get("data") or []
        if items:
            price_id = (items[0].get("price") or {}).get("id")
        tier = _price_to_tier(price_id)
        if tier is None:
            return {"handled": False, "event_type": event_type,
                    "reason": "unmapped_price", "price_id": price_id}
        intent = {
            "action": "upgrade_or_renew",
            "tier": tier,
            "customer_id": customer_id,
            "customer_email": customer_email,
            "price_id": price_id,
        }

    logger.info("Stripe webhook intent: %s", intent)
    return {"handled": True, "event_type": event_type, "intent": intent}
