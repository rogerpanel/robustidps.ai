"""
Server-side session management — cross-tab / cross-device state sharing.

Provides:
  - Session creation on login (returns session_id stored client-side)
  - Heartbeat endpoint (keeps session alive, detects timeout)
  - Page state sync (persist/restore UI state like Live Monitor progress)
  - Logout invalidation (kills all sessions or a specific one)
  - Automatic cleanup of expired sessions

Design:
  Each login creates a UserSession row. The session_id is sent to the client
  alongside the JWT. The client includes it in an X-Session-ID header.
  All tabs/devices sharing the same user account can read/write shared
  page_state, so switching devices shows the same Live Monitor progress.
"""

import datetime
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, and_, delete
from sqlalchemy.orm import Session

from config import ACCESS_TOKEN_EXPIRE_MINUTES
from database import get_db, UserSession, User
from auth import require_auth

logger = logging.getLogger("robustidps.sessions")

router = APIRouter(prefix="/api/sessions", tags=["Sessions"])

SESSION_TIMEOUT_MINUTES = ACCESS_TOKEN_EXPIRE_MINUTES  # session lifetime matches JWT
HEARTBEAT_INTERVAL_SECONDS = 60  # client should heartbeat every 60s
STALE_THRESHOLD_MINUTES = 5  # session considered stale after 5 missed heartbeats


# ── Schemas ───────────────────────────────────────────────────────────────

class SessionInfo(BaseModel):
    session_id: str
    device_label: str
    ip_address: str
    is_active: bool
    last_heartbeat: datetime.datetime
    created_at: datetime.datetime
    expires_at: datetime.datetime


class PageStatePayload(BaseModel):
    page: str  # e.g. "live-monitor", "redteam"
    state: dict  # arbitrary JSON state to persist


class PageStateResponse(BaseModel):
    page: str
    state: dict
    updated_at: Optional[datetime.datetime] = None


# ── Helpers ───────────────────────────────────────────────────────────────

def create_session(
    user: User,
    db: Session,
    ip_address: str = "",
    device_label: str = "",
) -> UserSession:
    """Create a new server-side session for a user."""
    now = datetime.datetime.utcnow()
    expires = now + datetime.timedelta(minutes=SESSION_TIMEOUT_MINUTES)

    session = UserSession(
        session_id=secrets.token_urlsafe(48),
        user_id=user.id,
        device_label=device_label[:255] if device_label else "",
        ip_address=ip_address[:45] if ip_address else "",
        is_active=True,
        page_state={},
        last_heartbeat=now,
        created_at=now,
        expires_at=expires,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    logger.info("Session created: user=%s session=%s", user.email, session.session_id[:12])
    return session


def get_active_session(session_id: str, db: Session) -> Optional[UserSession]:
    """Retrieve an active, non-expired session."""
    now = datetime.datetime.utcnow()
    return db.execute(
        select(UserSession).where(
            and_(
                UserSession.session_id == session_id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        )
    ).scalar_one_or_none()


def invalidate_user_sessions(user_id: int, db: Session, except_session: str = "") -> int:
    """Invalidate all active sessions for a user, optionally keeping one."""
    sessions = db.execute(
        select(UserSession).where(
            and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True,
            )
        )
    ).scalars().all()

    count = 0
    for s in sessions:
        if s.session_id != except_session:
            s.is_active = False
            count += 1
    if count:
        db.commit()
    return count


def cleanup_expired_sessions(db: Session) -> int:
    """Remove sessions that have expired (background maintenance)."""
    now = datetime.datetime.utcnow()
    result = db.execute(
        delete(UserSession).where(UserSession.expires_at < now)
    )
    db.commit()
    return result.rowcount


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.post("/heartbeat")
def heartbeat(
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Client heartbeat — keeps session alive and returns session status.
    If no valid session exists, creates one automatically.
    """
    session_id = request.headers.get("X-Session-ID", "")
    now = datetime.datetime.utcnow()

    session = None
    if session_id:
        session = get_active_session(session_id, db)

    if not session:
        # Auto-create session if client doesn't have one yet
        ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "")
        ua = request.headers.get("User-Agent", "")[:255]
        session = create_session(user, db, ip_address=ip, device_label=ua)

    # Update heartbeat timestamp and extend expiry
    session.last_heartbeat = now
    session.expires_at = now + datetime.timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    db.commit()

    return {
        "ok": True,
        "session_id": session.session_id,
        "expires_at": session.expires_at.isoformat(),
        "timeout_minutes": SESSION_TIMEOUT_MINUTES,
        "heartbeat_interval_seconds": HEARTBEAT_INTERVAL_SECONDS,
    }


@router.get("/admin/active")
def admin_list_active_sessions(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Admin-only: list all active user sessions across all users."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    now = datetime.datetime.utcnow()
    sessions = db.execute(
        select(UserSession).where(
            and_(
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        ).order_by(UserSession.last_heartbeat.desc())
    ).scalars().all()

    active = []
    for s in sessions:
        last_seen = s.last_heartbeat
        if last_seen:
            idle_seconds = (now - last_seen).total_seconds()
        else:
            idle_seconds = 9999

        # Look up user email
        u = db.execute(
            select(User).where(User.id == s.user_id)
        ).scalar_one_or_none()

        active.append({
            "session_key": s.session_id,
            "user_id": s.user_id,
            "email": u.email if u else "unknown",
            "device_label": s.device_label,
            "ip_address": s.ip_address,
            "last_heartbeat": s.last_heartbeat.isoformat() if s.last_heartbeat else "",
            "idle_seconds": round(idle_seconds),
            "is_online": idle_seconds < 300,  # 5 min threshold
        })

    return {
        "sessions": active,
        "total": len(active),
        "online": sum(1 for s in active if s["is_online"]),
    }


@router.get("/active", response_model=list[SessionInfo])
def list_active_sessions(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """List all active sessions for the current user (cross-device visibility)."""
    now = datetime.datetime.utcnow()
    sessions = db.execute(
        select(UserSession).where(
            and_(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        ).order_by(UserSession.last_heartbeat.desc())
    ).scalars().all()

    return [
        SessionInfo(
            session_id=s.session_id,
            device_label=s.device_label,
            ip_address=s.ip_address,
            is_active=s.is_active,
            last_heartbeat=s.last_heartbeat,
            created_at=s.created_at,
            expires_at=s.expires_at,
        )
        for s in sessions
    ]


@router.post("/logout")
def logout_session(
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Invalidate the current session (or all sessions if ?all=true)."""
    logout_all = request.query_params.get("all", "false").lower() == "true"
    session_id = request.headers.get("X-Session-ID", "")

    if logout_all:
        count = invalidate_user_sessions(user.id, db)
        logger.info("All sessions invalidated for user=%s count=%d", user.email, count)
        return {"ok": True, "invalidated": count}

    if session_id:
        session = get_active_session(session_id, db)
        if session and session.user_id == user.id:
            session.is_active = False
            db.commit()
            logger.info("Session invalidated: user=%s session=%s", user.email, session_id[:12])
            return {"ok": True, "invalidated": 1}

    return {"ok": True, "invalidated": 0}


@router.put("/state")
def save_page_state(
    payload: PageStatePayload,
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Save page-level UI state to the server.
    State is stored per-user (not per-session), so all tabs/devices share it.
    """
    session_id = request.headers.get("X-Session-ID", "")

    # Find any active session for this user to store state
    now = datetime.datetime.utcnow()
    session = None
    if session_id:
        session = get_active_session(session_id, db)

    if not session:
        # Find the most recent active session for this user
        session = db.execute(
            select(UserSession).where(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.is_active == True,
                    UserSession.expires_at > now,
                )
            ).order_by(UserSession.last_heartbeat.desc())
        ).scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="No active session found")

    # Merge page state into existing state dict
    current_state = session.page_state or {}
    current_state[payload.page] = {
        "state": payload.state,
        "updated_at": now.isoformat(),
    }

    # Propagate to ALL active sessions for this user (cross-device sync)
    user_sessions = db.execute(
        select(UserSession).where(
            and_(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        )
    ).scalars().all()

    for s in user_sessions:
        s.page_state = dict(current_state)  # copy to avoid reference issues

    db.commit()

    return {"ok": True, "page": payload.page}


@router.get("/state/{page}")
def get_page_state(
    page: str,
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Retrieve saved page state. Looks across all active sessions for this user
    and returns the most recently updated state for the requested page.
    """
    now = datetime.datetime.utcnow()
    sessions = db.execute(
        select(UserSession).where(
            and_(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        ).order_by(UserSession.last_heartbeat.desc())
    ).scalars().all()

    best = None
    best_time = ""
    for s in sessions:
        ps = (s.page_state or {}).get(page)
        if ps and ps.get("updated_at", "") > best_time:
            best = ps
            best_time = ps.get("updated_at", "")

    if not best:
        return {"page": page, "state": {}, "updated_at": None}

    return {
        "page": page,
        "state": best.get("state", {}),
        "updated_at": best.get("updated_at"),
    }


@router.get("/state")
def get_all_page_states(
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Retrieve all saved page states for the current user."""
    now = datetime.datetime.utcnow()
    session = db.execute(
        select(UserSession).where(
            and_(
                UserSession.user_id == user.id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        ).order_by(UserSession.last_heartbeat.desc())
    ).scalar_one_or_none()

    if not session:
        return {"states": {}}

    return {"states": session.page_state or {}}


@router.delete("/expired")
def cleanup_sessions(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Admin endpoint to clean up expired sessions."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    count = cleanup_expired_sessions(db)
    return {"ok": True, "cleaned": count}
