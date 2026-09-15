"""Identity + access gating for Agent Studio endpoints.

Four identity sources, tried in priority order, so the same endpoint
can serve admins (unrestricted), authenticated platform users
(tier-scoped), Agent Studio API-key holders (tier-scoped to their
issued key), and anonymous demo visitors (read + scoped writes):

  1. AGENT_STUDIO_AUTH_DISABLED=1            → blanket dev bypass
  2. Platform JWT with role == "admin"        → unrestricted admin
  3. Platform JWT with role != "admin"        → tier-scoped per user.subscription_tier
  4. Agent Studio API key (rids_live_…)      → tier-scoped per customer
  5. Anonymous + AGENT_STUDIO_DEMO_MODE=1     → community-tier demo customer
  6. otherwise                                → 401

The "customer dict" surface the rest of the codebase consumes:

    {
        "customer_id":  str,         # cust_… | platform_admin | platform_<email> | demo_anon
        "email":        str,
        "tier":         "community" | "pro" | "enterprise",
        "role":         "admin" | "user" | "demo",
        "source":       "env_bypass" | "platform_jwt" | "api_key" | "demo_mode",
    }

require_admin() still gates ROBUSTIDPS_ADMIN_TOKEN — kept for back-compat
with admin grants — BUT now it also accepts a platform JWT whose user
has `role == "admin"`. So if an admin is logged in via the IDS web UI,
their session token works against the admin endpoints too.
"""
from __future__ import annotations

import datetime
import hashlib
import logging
import os
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from auth import get_current_user, SECRET_KEY, JWT_ALGORITHM
from database import User, get_db
from plugins.agent_studio.db_models import find_api_key_by_hash

logger = logging.getLogger("agent_studio.auth")


DEV_DISABLED_ENV = "AGENT_STUDIO_AUTH_DISABLED"
DEMO_MODE_ENV    = "AGENT_STUDIO_DEMO_MODE"
ADMIN_TOKEN_ENV  = "ROBUSTIDPS_ADMIN_TOKEN"

DEMO_CUSTOMER_ID = "demo_anon"
PLATFORM_ADMIN_CUSTOMER_ID = "platform_admin"


def _flag(name: str) -> bool:
    return os.getenv(name, "").lower() in ("1", "true", "yes", "on")


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _extract_bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None
    direct = request.headers.get("x-api-key")
    return direct.strip() if direct else None


def _is_platform_jwt(token: str) -> bool:
    """Heuristic: JWTs are header.payload.sig — three base64 chunks
    joined by dots. API keys use the rids_… prefix."""
    if token.startswith("rids_"):
        return False
    return token.count(".") == 2


def _decode_platform_user(token: str, db: Session) -> User | None:
    """Decode a platform JWT and resolve to a User row. Mirrors
    backend/auth.py::get_current_user but works against an arbitrary
    Bearer string (rather than the FastAPI oauth2_scheme dependency)."""
    try:
        import jwt
        from sqlalchemy import select
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None
    email = payload.get("sub")
    if not email:
        return None
    try:
        return db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    except Exception:
        return None


def _admin_customer_dict(user: User | None) -> dict:
    return {
        "customer_id": PLATFORM_ADMIN_CUSTOMER_ID,
        "email": (user.email if user else "admin@local"),
        "tier": "enterprise",
        "role": "admin",
        "source": "platform_jwt" if user else "env_bypass",
    }


def _platform_user_customer_dict(user: User) -> dict:
    tier = getattr(user, "subscription_tier", None) or "community"
    return {
        "customer_id": f"platform_{user.email}",
        "email": user.email,
        "tier": tier,
        "role": "user",
        "source": "platform_jwt",
    }


def _demo_customer_dict() -> dict:
    return {
        "customer_id": DEMO_CUSTOMER_ID,
        "email": "demo@robustidps.ai",
        "tier": "community",
        "role": "demo",
        "source": "demo_mode",
    }


def _api_key_customer_dict(db: Session, raw_key: str) -> dict | None:
    hit = find_api_key_by_hash(db, _hash_key(raw_key))
    if hit is None:
        return None
    customer, key = hit
    key.last_used_at = datetime.datetime.utcnow()
    db.commit()
    return {
        "customer_id": customer.customer_id,
        "email": customer.email,
        "tier": customer.tier,
        "role": "user",
        "source": "api_key",
        "stripe_customer_id": customer.stripe_customer_id,
        "stripe_subscription_id": customer.stripe_subscription_id,
    }


# ── Public dependencies ─────────────────────────────────────────────────

def require_api_key(request: Request,
                    db: Session = Depends(get_db)) -> dict:
    """Validate identity from the layered sources, return a customer dict."""

    # 1. Hard dev bypass
    if _flag(DEV_DISABLED_ENV):
        return _admin_customer_dict(None)

    raw = _extract_bearer(request)

    # 2 + 3. Platform JWT (admin or tier-scoped user)
    if raw and _is_platform_jwt(raw):
        user = _decode_platform_user(raw, db)
        if user is not None:
            if (user.role or "").lower() == "admin":
                return _admin_customer_dict(user)
            return _platform_user_customer_dict(user)
        # fall through if JWT didn't decode — might be a malformed key

    # 4. Agent Studio API key
    if raw and raw.startswith("rids_"):
        ckt = _api_key_customer_dict(db, raw)
        if ckt is not None:
            return ckt
        # fall through to demo only if explicitly enabled

    # 5. Anonymous demo mode (write-bounded by rate limiter)
    if _flag(DEMO_MODE_ENV):
        return _demo_customer_dict()

    # 6. Lock it
    raise HTTPException(
        401,
        "Authentication required: log in as a platform user, paste a "
        "rids_live_… key, or ask the admin to set AGENT_STUDIO_DEMO_MODE=1 "
        "for read-only demo access.",
    )


def require_admin(request: Request,
                  db: Session = Depends(get_db)) -> dict:
    """Admin gate — accepts either the env ADMIN_TOKEN or a logged-in
    platform admin's JWT."""
    if _flag(DEV_DISABLED_ENV):
        return _admin_customer_dict(None)

    raw = _extract_bearer(request) or request.headers.get("x-admin-token", "")

    expected = os.getenv(ADMIN_TOKEN_ENV)
    if expected and raw and secrets.compare_digest(raw, expected):
        return {"role": "admin", "source": "env_token"}

    if raw and _is_platform_jwt(raw):
        user = _decode_platform_user(raw, db)
        if user and (user.role or "").lower() == "admin":
            return {"role": "admin", "source": "platform_jwt", "email": user.email}

    if not expected:
        raise HTTPException(
            503,
            f"Admin endpoints disabled ({ADMIN_TOKEN_ENV} unset on server). "
            "Set the env var or log in as a platform admin user.",
        )
    raise HTTPException(401, "Invalid admin token")


CustomerDep = Annotated[dict, Depends(require_api_key)]
AdminDep = Annotated[dict, Depends(require_admin)]


def require_self_or_admin(customer_id: str, request: Request,
                          db: Session) -> dict:
    """Allow if the Bearer belongs to `customer_id`, OR if the caller is
    platform-admin / env-admin (which act as super-users)."""
    if _flag(DEV_DISABLED_ENV):
        return _admin_customer_dict(None)

    # Admin paths first (cheap)
    admin_token = os.getenv(ADMIN_TOKEN_ENV)
    raw = _extract_bearer(request) or request.headers.get("x-admin-token", "")
    if admin_token and raw and secrets.compare_digest(raw, admin_token):
        return {"role": "admin", "source": "env_token"}

    if raw and _is_platform_jwt(raw):
        user = _decode_platform_user(raw, db)
        if user and (user.role or "").lower() == "admin":
            return _admin_customer_dict(user)

    # Otherwise resolve identity normally and require self-match
    customer = require_api_key(request, db)
    if customer.get("role") == "admin":
        return customer
    if customer.get("customer_id") != customer_id:
        raise HTTPException(403, "Bearer key does not belong to this customer")
    return {"role": "self", **customer}


def access_info() -> dict:
    """Public probe: what access modes are configured on this server?
    The frontend uses this to show "Demo mode" / "Admin login required" /
    "API key required" banners on Agent Studio pages."""
    return {
        "auth_disabled": _flag(DEV_DISABLED_ENV),
        "demo_mode": _flag(DEMO_MODE_ENV),
        "admin_token_set": bool(os.getenv(ADMIN_TOKEN_ENV)),
        "sources_accepted": [
            "platform_jwt (admin → full / user → tier-scoped)",
            "agent_studio_api_key (rids_live_…)",
            *(["demo_mode (anonymous community-tier)"] if _flag(DEMO_MODE_ENV) else []),
            *(["env_bypass (AGENT_STUDIO_AUTH_DISABLED=1)"] if _flag(DEV_DISABLED_ENV) else []),
        ],
    }
