"""Stripe billing scaffold for the Agent Studio commercial vertical.

The webhook receiver in `stripe_webhook.py` is the integration seam
for Pro and Enterprise subscriptions. When the platform's Stripe
account is funded and the webhook secret is set in STRIPE_WEBHOOK_SECRET
env var, the receiver will start mutating subscription_tier on user
records. Until then it logs intent and returns 200 — safe to deploy.
"""
from plugins.agent_studio.billing.stripe_webhook import (
    handle_event, parse_event,
)
from plugins.agent_studio.billing.checkout import (
    create_checkout_session, complete_checkout,
    issue_api_key, revoke_api_key, get_customer, list_customers,
)

__all__ = [
    "handle_event", "parse_event",
    "create_checkout_session", "complete_checkout",
    "issue_api_key", "revoke_api_key",
    "get_customer", "list_customers",
]
