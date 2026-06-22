"""API-key authentication for Agent Studio endpoints.

A single FastAPI dependency, `require_api_key`, that hashes the incoming
Bearer token, looks it up against the customer store from
`billing.checkout`, stamps `last_used_at`, and returns the customer
record (or 401s).

Free-tier endpoints — the scanner wedge, the SKU catalog, the entitlement
tier list, and read-only catalogs — stay open. Apply this dependency to
*write* endpoints (eval / red-team / supply-chain / runtime / api-keys),
where billing matters.

Local dev override:
    export AGENT_STUDIO_AUTH_DISABLED=1
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from plugins.agent_studio.billing.checkout import _CUSTOMERS, _persist


DEV_DISABLED_ENV = "AGENT_STUDIO_AUTH_DISABLED"
ADMIN_TOKEN_ENV = "ROBUSTIDPS_ADMIN_TOKEN"


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _extract_bearer(request: Request) -> str | None:
    """Accept either `Authorization: Bearer <key>` or `X-API-Key: <key>`."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None
    direct = request.headers.get("x-api-key")
    return direct.strip() if direct else None


def _lookup_by_hash(key_hash: str) -> tuple[dict, dict] | None:
    """Return (customer_dict, key_dict) on hit, else None."""
    for customer in _CUSTOMERS.values():
        for k in customer.api_keys:
            if k.get("hash") == key_hash and not k.get("revoked"):
                return customer.__dict__, k
    return None


def require_api_key(request: Request) -> dict:
    """FastAPI dependency: validate Bearer key, mark last_used_at, return customer."""
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

    hit = _lookup_by_hash(_hash_key(raw))
    if hit is None:
        raise HTTPException(401, "Invalid or revoked API key")

    customer, key = hit
    key["last_used_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _persist()
    return customer


def require_admin(request: Request) -> dict:
    """Admin-token gate for /admin/* endpoints. Distinct from customer keys."""
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


def require_self_or_admin(customer_id: str, request: Request) -> dict:
    """Allow if the Bearer key belongs to `customer_id`, or if the
    admin token is presented. Used for /customers/{id} + /api-keys/*."""
    if os.getenv(DEV_DISABLED_ENV, "").lower() in ("1", "true", "yes"):
        return {"_dev_bypass": True, "role": "self"}
    admin_token = os.getenv(ADMIN_TOKEN_ENV)
    raw = _extract_bearer(request) or request.headers.get("x-admin-token", "")
    if admin_token and raw and secrets.compare_digest(raw, admin_token):
        return {"role": "admin"}
    customer = require_api_key(request)
    if customer.get("customer_id") != customer_id:
        raise HTTPException(403, "Bearer key does not belong to this customer")
    return {"role": "self", **customer}
