"""
Audit logging middleware and utilities.

Every significant action is logged to the audit_logs table with:
  - User identity (if authenticated)
  - Action type (LOGIN, UPLOAD, PREDICT, ABLATION, EXPORT, etc.)
  - Resource ID (job_id, model_id, etc.)
  - Client IP and User-Agent
  - Timestamp
"""

import logging
import time
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from sqlalchemy.orm import Session

from database import SessionLocal, AuditLog

logger = logging.getLogger("robustidps.audit")

# ── Map endpoints to action names ─────────────────────────────────────────

_ACTION_MAP = {
    ("POST", "/api/auth/login"): "LOGIN",
    ("POST", "/api/auth/register"): "REGISTER",
    ("POST", "/api/upload"): "UPLOAD",
    ("POST", "/api/predict"): "PREDICT",
    ("POST", "/api/predict_uncertain"): "PREDICT_UNCERTAIN",
    ("POST", "/api/ablation"): "ABLATION",
    ("GET", "/api/export"): "EXPORT",
    ("POST", "/api/models"): "MODEL_SWITCH",
    ("POST", "/api/firewall/generate"): "FIREWALL_GENERATE",
}


def _get_action(method: str, path: str) -> Optional[str]:
    """Determine the audit action for a request."""
    for (m, prefix), action in _ACTION_MAP.items():
        if method == m and path.startswith(prefix):
            return action
    return None


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For from nginx."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


# ── Direct audit log function (for use in endpoints) ─────────────────────

def log_audit(
    db: Session,
    action: str,
    resource: str = "",
    details: str = "",
    user_id: Optional[int] = None,
    ip_address: str = "",
    user_agent: str = "",
):
    """Write an audit log entry directly."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(entry)
    db.commit()
    logger.info(
        "AUDIT | action=%s resource=%s user_id=%s ip=%s details=%s",
        action, resource, user_id, ip_address, details,
    )


# ── Middleware: auto-log significant requests ─────────────────────────────

class AuditMiddleware(BaseHTTPMiddleware):
    """Automatically logs significant API actions to the audit_logs table."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 1)

        # Only log significant actions (not health checks, static files, etc.)
        action = _get_action(request.method, request.url.path)
        if action and response.status_code < 500:
            ip = _get_client_ip(request)
            ua = request.headers.get("user-agent", "")[:512]

            # Try to extract user_id from the auth token (non-blocking)
            user_id = None
            try:
                from auth import get_current_user, oauth2_scheme
                # We read the token from the Authorization header directly
                auth_header = request.headers.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    import jwt as pyjwt
                    from config import SECRET_KEY, JWT_ALGORITHM
                    payload = pyjwt.decode(
                        auth_header[7:], SECRET_KEY,
                        algorithms=[JWT_ALGORITHM],
                    )
                    email = payload.get("sub")
                    if email:
                        from database import User
                        from sqlalchemy import select
                        db = SessionLocal()
                        try:
                            u = db.execute(
                                select(User).where(User.email == email)
                            ).scalar_one_or_none()
                            if u:
                                user_id = u.id
                        finally:
                            db.close()
            except Exception:
                pass

            # Write audit log
            db = SessionLocal()
            try:
                entry = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource=request.url.path,
                    details=f"status={response.status_code} duration={duration_ms}ms",
                    ip_address=ip,
                    user_agent=ua,
                )
                db.add(entry)
                db.commit()
            except Exception:
                logger.exception("Failed to write audit log")
            finally:
                db.close()

            logger.info(
                "AUDIT | %s %s | user=%s ip=%s status=%s %sms",
                action, request.url.path, user_id, ip,
                response.status_code, duration_ms,
            )

        return response
