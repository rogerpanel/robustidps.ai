"""API-key + admin-token authentication for Agent Studio endpoints.

Three FastAPI dependencies:

    require_api_key(request, db)            → customer dict
    require_admin(request)                  → {"role": "admin"}
    require_self_or_admin(customer_id, ...) → role-tagged dict

Customer keys are looked up in the `agent_studio_api_keys` table by
SHA-256 of the Bearer token; the row's `last_used_at` is stamped on
every hit. Free endpoints (the scanner wedge, catalogs, snapshots,
template browse, public Stripe webhook) stay open.

Dev escape hatch:
    export AGENT_STUDIO_AUTH_DISABLED=1

Admin token:
    export ROBUSTIDPS_ADMIN_TOKEN=$(openssl rand -base64 32)
"""
from __future__ import annotations

import datetime
import hashlib
import os
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from plugins.agent_studio.db_models import find_api_key_by_hash


DEV_DISABLED_ENV = "AGENT_STUDIO_AUTH_DISABLED"
ADMIN_TOKEN_ENV = "ROBUSTIDPS_ADMIN_TOKEN"


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _extract_bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None
    direct = request.headers.get("x-api-key")
    return direct.strip() if direct else None


def require_api_key(request: Request,
                    db: Session = Depends(get_db)) -> dict:
    """Validate Bearer key against the DB, stamp last_used_at, return
    customer dict."""
    if os.getenv(DEV_DISABLED_ENV, "").lower() in ("1", "true", "yes"):
        return {
            "customer_id": "dev_local",
            "email": "dev@localhost",
            "tier": "enterprise",
            "_dev_bypass": True,
        }

    raw = _extract_bearer(request)
    if not raw:
        raise HTTPException(401, "Missing API key (Authorization: Bearer rids_live_…)")

    hit = find_api_key_by_hash(db, _hash_key(raw))
    if hit is None:
        raise HTTPException(401, "Invalid or revoked API key")

    customer, key = hit
    key.last_used_at = datetime.datetime.utcnow()
    db.commit()
    return {
        "customer_id": customer.customer_id,
        "email": customer.email,
        "tier": customer.tier,
        "stripe_customer_id": customer.stripe_customer_id,
        "stripe_subscription_id": customer.stripe_subscription_id,
    }


def require_admin(request: Request) -> dict:
    """Admin-token gate (distinct from customer keys)."""
    expected = os.getenv(ADMIN_TOKEN_ENV)
    if not expected:
        raise HTTPException(
            503,
            f"Admin endpoints disabled ({ADMIN_TOKEN_ENV} unset on server). "
            "Set the env var to a strong random token to enable admin grants.",
        )
    raw = _extract_bearer(request) or request.headers.get("x-admin-token", "")
    if not secrets.compare_digest(raw, expected):
        raise HTTPException(401, "Invalid admin token")
    return {"role": "admin"}


CustomerDep = Annotated[dict, Depends(require_api_key)]
AdminDep = Annotated[dict, Depends(require_admin)]


def require_self_or_admin(customer_id: str, request: Request,
                           db: Session) -> dict:
    """Allow if the Bearer key belongs to `customer_id`, or admin token."""
    if os.getenv(DEV_DISABLED_ENV, "").lower() in ("1", "true", "yes"):
        return {"_dev_bypass": True, "role": "self"}
    admin_token = os.getenv(ADMIN_TOKEN_ENV)
    raw = _extract_bearer(request) or request.headers.get("x-admin-token", "")
    if admin_token and raw and secrets.compare_digest(raw, admin_token):
        return {"role": "admin"}
    customer = require_api_key(request, db)
    if customer.get("customer_id") != customer_id:
        raise HTTPException(403, "Bearer key does not belong to this customer")
    return {"role": "self", **customer}
