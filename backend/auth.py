"""
JWT Authentication & Role-Based Access Control.

Roles:
  admin   — Full access: manage users, system settings, all operations
  analyst — Upload, analyse, view results, export
  viewer  — Read-only access to dashboard, analytics, datasets
"""

import datetime
import hashlib
import html
import logging
import os
import random
import re
import string
import time
from collections import defaultdict
from typing import Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from config import SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import get_db, User
from mailer import MailError, mail_configured, send_mail

logger = logging.getLogger("robustidps.auth")

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# ── Brute-Force Protection ───────────────────────────────────────────────
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5-minute lockout
_failed_attempts: dict[str, list[float]] = defaultdict(list)


def _check_lockout(email: str) -> None:
    """Raise 429 if the account has too many recent failed login attempts."""
    now = time.time()
    window = now - LOCKOUT_SECONDS
    attempts = _failed_attempts.get(email, [])
    # Prune old attempts outside the window
    recent = [t for t in attempts if t > window]
    _failed_attempts[email] = recent
    if len(recent) >= MAX_FAILED_ATTEMPTS:
        remaining = int(LOCKOUT_SECONDS - (now - recent[0]))
        logger.warning("Account locked out: %s (%d failed attempts)", email, len(recent))
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Try again in {remaining} seconds.",
        )


def _record_failed_attempt(email: str) -> None:
    _failed_attempts[email].append(time.time())


def _clear_failed_attempts(email: str) -> None:
    _failed_attempts.pop(email, None)


def _generate_robust_id(db: Session) -> str:
    """Generate a unique memorable RobustID like ROB-A7X2."""
    chars = string.ascii_uppercase + string.digits
    for _ in range(100):  # max attempts
        code = ''.join(random.choices(chars, k=4))
        rid = f"ROB-{code}"
        try:
            existing = db.execute(select(User).where(User.robust_id == rid)).scalar_one_or_none()
            if not existing:
                return rid
        except Exception:
            return rid  # Column doesn't exist yet — ID is unique enough
    return f"ROB-{''.join(random.choices(chars, k=6))}"  # fallback: 6-char


# ── Password Strength Validation ─────────────────────────────────────────

def validate_password_strength(password: str) -> None:
    """Enforce minimum password complexity requirements."""
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("one special character")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"Password too weak. Requires: {', '.join(errors)}.",
        )


# ── Schemas ───────────────────────────────────────────────────────────────

USE_CASE_OPTIONS = [
    "Industry Work",
    "Academic Research",
    "Evaluation & Assessment",
    "Government / Defense",
    "Personal / Self-Study",
]


class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str = ""
    organization: str = ""
    use_case: str = ""


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    organization: str
    use_case: str
    is_active: bool
    created_at: datetime.datetime
    robust_id: str = ""
    preferred_model: str = "surrogate"
    email_verified: bool = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ── Utilities ─────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (
        expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)


# ── Dependencies ──────────────────────────────────────────────────────────

def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Extract user from JWT token. Returns None if unauthenticated."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        if payload.get("purpose"):
            return None  # single-purpose tokens (e-mail confirmation) never authenticate
    except jwt.PyJWTError:
        return None
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is not None and user.email_verified is False:
        return None
    return user


def require_auth(user: Optional[User] = Depends(get_current_user)) -> User:
    """Require authentication — 401 if not logged in."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    return user


def require_role(*roles: str):
    """Dependency factory: require user to have one of the specified roles."""
    def checker(user: User = Depends(require_auth)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires role: {', '.join(roles)}",
            )
        return user
    return checker


# ── Helper: user → response ───────────────────────────────────────────────

def _user_response(u: User) -> UserResponse:
    return UserResponse(
        id=u.id, email=u.email, full_name=u.full_name,
        role=u.role, organization=u.organization or "",
        use_case=u.use_case or "", is_active=u.is_active,
        created_at=u.created_at,
        robust_id=getattr(u, 'robust_id', '') or "",
        preferred_model=getattr(u, 'preferred_model', 'surrogate') or "surrogate",
        email_verified=getattr(u, 'email_verified', True) is not False,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────

# ── Self-registration with e-mail confirmation ──────────────────────────
#
# REGISTRATION_MODE=closed (default): only admins create accounts.
# REGISTRATION_MODE=verify: anyone may register; the account can sign in
# once the link mailed to the address has been opened. Needs SMTP_* (mailer.py).

VERIFY_TOKEN_HOURS = 24
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
_PENDING_MESSAGE = ("If this address can be registered, we have sent a confirmation link to it. "
                    "Open the link within 24 hours, then sign in.")
_register_hits: dict[str, list[float]] = defaultdict(list)   # client ip -> times
_mail_hits: dict[str, list[float]] = defaultdict(list)       # e-mail -> times


def _registration_mode() -> str:
    mode = os.getenv("REGISTRATION_MODE", "closed").strip().lower()
    return "verify" if mode == "verify" and mail_configured() else "closed"


def _registration_role() -> str:
    role = os.getenv("REGISTRATION_ROLE", "viewer").strip().lower()
    return role if role in ("viewer", "analyst") else "viewer"


def _public_base_url() -> str:
    return os.getenv("PUBLIC_BASE_URL", "https://robustidps.ai").rstrip("/")


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _allow(store: dict[str, list[float]], key: str, limit: int, window: float) -> bool:
    """Sliding-window limiter; records the hit when allowed."""
    now = time.time()
    hits = [t for t in store.get(key, []) if t > now - window]
    if len(hits) >= limit:
        store[key] = hits
        return False
    hits.append(now)
    store[key] = hits
    return True


def _mail_allowed(email: str) -> bool:
    """At most one mail per address per minute and five per day."""
    recent = [t for t in _mail_hits.get(email, []) if t > time.time() - 60]
    if recent:
        return False
    return _allow(_mail_hits, email, 5, 24 * 3600)


# Confirmation links are signed with a key derived for that purpose only, so no
# decoder of login tokens (here, in main.py, in plugins) can ever accept one.
_VERIFY_KEY = hashlib.sha256(f"{SECRET_KEY}:verify-email".encode()).hexdigest()


def create_verification_token(email: str) -> str:
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=VERIFY_TOKEN_HOURS)
    return jwt.encode({"sub": email, "purpose": "verify-email", "exp": expire},
                      _VERIFY_KEY, algorithm=JWT_ALGORITHM)


def _send_verification(user: User) -> None:
    link = f"{_public_base_url()}/api/auth/verify-email?token={create_verification_token(user.email)}"
    name = user.full_name or "there"
    text = (f"Hello {name},\n\n"
            f"Confirm your RobustIDPS.ai account by opening this link within {VERIFY_TOKEN_HOURS} hours:\n\n"
            f"{link}\n\n"
            "If you did not register, ignore this message; the account stays inactive.\n\n"
            "RobustIDPS.ai")
    html_body = (f"<p>Hello {html.escape(name)},</p>"
                 f"<p>Confirm your RobustIDPS.ai account by opening this link within {VERIFY_TOKEN_HOURS} hours:</p>"
                 f'<p><a href="{html.escape(link)}">Confirm my e-mail address</a></p>'
                 "<p>If you did not register, ignore this message; the account stays inactive.</p>"
                 "<p>RobustIDPS.ai</p>")
    send_mail(user.email, "Confirm your RobustIDPS.ai account", text, html_body)


def _pending_response() -> JSONResponse:
    return JSONResponse(status_code=202, content={"status": "pending", "detail": _PENDING_MESSAGE})


@router.get("/registration")
def registration_info():
    """Whether self-registration is open (the sign-in page shows or hides 'Register')."""
    return {"mode": _registration_mode()}


@router.post("/register", status_code=202)
def register(body: UserCreate, request: Request, db: Session = Depends(get_db)):
    """Self-registration: creates an unconfirmed account and mails a confirmation link."""
    if _registration_mode() != "verify":
        raise HTTPException(status_code=403, detail="Registration is disabled. Contact your administrator for access.")
    if not _allow(_register_hits, _client_ip(request), 10, 3600) or not _allow(_register_hits, "*", 100, 3600):
        raise HTTPException(status_code=429, detail="Too many registration attempts. Try again later.")

    email = body.email.strip().lower()
    if not _EMAIL_RE.match(email) or len(email) > 255:
        raise HTTPException(status_code=400, detail="Enter a valid e-mail address")
    validate_password_strength(body.password)
    if body.use_case and body.use_case not in USE_CASE_OPTIONS:
        raise HTTPException(status_code=400, detail="Invalid use case selection")

    existing = db.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
    if existing:
        # Same answer whether or not the address is taken, so the form cannot be used to
        # discover accounts. An unconfirmed account gets a fresh link; its password is not
        # changed (otherwise anyone could set the password of an account its owner then confirms).
        if existing.email_verified is False and _mail_allowed(email):
            try:
                _send_verification(existing)
            except MailError:
                pass
        return _pending_response()

    user = User(
        email=email,
        password_hash=hash_password(body.password),
        full_name=body.full_name.strip()[:255],
        organization=body.organization.strip()[:255],
        use_case=body.use_case,
        role=_registration_role(),
        is_active=True,
        email_verified=False,
    )
    user.robust_id = _generate_robust_id(db)
    db.add(user)
    db.flush()
    _mail_allowed(email)
    try:
        _send_verification(user)
    except MailError:
        db.rollback()
        raise HTTPException(status_code=503, detail="We could not send the confirmation e-mail right now. "
                                                    "Please try again in a few minutes.")
    db.commit()
    logger.info("New registration (unconfirmed): %s (role=%s)", email, user.role)
    return _pending_response()


@router.get("/verify-email")
def verify_email(token: str = "", db: Session = Depends(get_db)):
    """Target of the link in the confirmation mail; redirects to the sign-in page."""
    try:
        payload = jwt.decode(token, _VERIFY_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("purpose") != "verify-email":
            raise jwt.InvalidTokenError("wrong purpose")
        email = str(payload.get("sub", ""))
    except jwt.ExpiredSignatureError:
        return RedirectResponse("/?verified=expired", status_code=303)
    except jwt.PyJWTError:
        return RedirectResponse("/?verified=invalid", status_code=303)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None:
        return RedirectResponse("/?verified=invalid", status_code=303)
    if user.email_verified is False:
        user.email_verified = True
        db.commit()
        logger.info("E-mail confirmed: %s", email)
    return RedirectResponse("/?verified=1", status_code=303)


class ResendBody(BaseModel):
    email: str


@router.post("/resend-verification", status_code=202)
def resend_verification(body: ResendBody, request: Request, db: Session = Depends(get_db)):
    """Mail a new confirmation link to an unconfirmed account (same answer for any address)."""
    if _registration_mode() != "verify":
        raise HTTPException(status_code=403, detail="Registration is disabled. Contact your administrator for access.")
    if not _allow(_register_hits, _client_ip(request), 10, 3600):
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    email = body.email.strip().lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is not None and user.email_verified is False and _mail_allowed(email):
        try:
            _send_verification(user)
        except MailError:
            raise HTTPException(status_code=503, detail="We could not send the e-mail right now. "
                                                        "Please try again in a few minutes.")
    return _pending_response()


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    session_id: str = ""


@router.post("/login", response_model=LoginResponse)
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Login with email + password, returns JWT + server-side session."""
    _check_lockout(form.username)

    user = db.execute(select(User).where(User.email == form.username)).scalar_one_or_none()
    if not user or not verify_password(form.password, user.password_hash):
        _record_failed_attempt(form.username)
        logger.warning("Failed login attempt: %s", form.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if user.email_verified is False:
        raise HTTPException(status_code=403, detail="Email not confirmed. Open the link we sent to your "
                                                    "address, or request a new one.")

    _clear_failed_attempts(form.username)
    user.last_login = datetime.datetime.utcnow()
    db.commit()

    # Create server-side session for cross-tab/device state sharing
    from sessions import create_session
    ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "")
    ua = request.headers.get("User-Agent", "")[:255]
    session = create_session(user, db, ip_address=ip, device_label=ua)

    logger.info("User logged in: %s (session=%s)", user.email, session.session_id[:12])
    token = create_access_token({"sub": user.email, "role": user.role})
    return LoginResponse(
        access_token=token,
        user=_user_response(user),
        session_id=session.session_id,
    )


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(require_auth)):
    """Return the current authenticated user."""
    return _user_response(user)


@router.get("/users", response_model=list[UserResponse])
def list_users(
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """List all users (admin only)."""
    users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
    return [_user_response(u) for u in users]


@router.patch("/users/{user_id}/role")
def update_role(
    user_id: int,
    role: str,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update a user's role (admin only)."""
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = role
    db.commit()
    logger.info("Admin %s changed user %s role to %s", admin.email, target.email, role)
    return {"ok": True, "user": _user_response(target)}


@router.patch("/users/{user_id}/password")
def reset_password(
    user_id: int,
    new_password: str,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Reset a user's password (admin only)."""
    validate_password_strength(new_password)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.password_hash = hash_password(new_password)
    db.commit()
    logger.info("Admin %s reset password for user %s", admin.email, target.email)
    return {"ok": True, "message": f"Password reset for {target.email}"}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Delete a user account (admin only). Cannot delete yourself."""
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    email = target.email
    db.delete(target)
    db.commit()
    logger.info("Admin %s deleted user %s", admin.email, email)
    return {"ok": True, "message": f"User {email} deleted"}


@router.patch("/users/{user_id}/deactivate")
def toggle_active(
    user_id: int,
    active: bool,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Activate or deactivate a user (admin only)."""
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_active = active
    db.commit()
    logger.info("Admin %s set user %s active=%s", admin.email, target.email, active)
    return {"ok": True, "user": _user_response(target)}


@router.patch("/users/{user_id}/confirm-email")
def confirm_email(
    user_id: int,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Mark a self-registered account's address as confirmed (admin only)."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.email_verified = True
    db.commit()
    logger.info("Admin %s confirmed e-mail of %s", admin.email, target.email)
    return {"ok": True, "user": _user_response(target)}


@router.post("/users", response_model=UserResponse)
def create_user(
    body: UserCreate,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a new user account (admin only). Replaces public registration."""
    existing = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    validate_password_strength(body.password)

    role = "analyst"  # new users default to analyst; admin can change via /users/{id}/role

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        organization=body.organization,
        use_case=body.use_case,
        role=role,
    )
    user.robust_id = _generate_robust_id(db)
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("Admin %s created user %s (role=%s)", admin.email, user.email, user.role)
    return _user_response(user)


# ── Startup: create default admin ─────────────────────────────────────────

def ensure_default_admin(db: Session):
    """Create or update the default admin account."""
    from config import ADMIN_EMAIL, ADMIN_PASSWORD
    if not ADMIN_PASSWORD:
        logger.warning("No ADMIN_PASSWORD set — skipping default admin creation")
        return

    existing = db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one_or_none()
    if existing:
        # Update password if it changed (re-hash and compare)
        if not verify_password(ADMIN_PASSWORD, existing.password_hash):
            existing.password_hash = hash_password(ADMIN_PASSWORD)
            db.commit()
            logger.info("Admin password updated for %s", ADMIN_EMAIL)
        if not getattr(existing, 'robust_id', None):
            try:
                existing.robust_id = _generate_robust_id(db)
            except Exception:
                pass  # Column may not exist yet in DB
            db.commit()
        return

    user_count = db.execute(select(func.count(User.id))).scalar()
    if user_count > 0:
        return  # other users exist but no admin with this email — don't auto-create

    admin = User(
        email=ADMIN_EMAIL,
        password_hash=hash_password(ADMIN_PASSWORD),
        full_name="System Administrator",
        role="admin",
    )
    admin.robust_id = _generate_robust_id(db)
    db.add(admin)
    db.commit()
    logger.info("Default admin created: %s", ADMIN_EMAIL)


# ── User Profile ──────────────────────────────────────────────────────

class ProfileUpdate(BaseModel):
    full_name: str = ""
    organization: str = ""
    specialization: str = ""
    bio: str = ""
    use_case: str = ""
    avatar_color: str = ""
    preferred_model: str = ""
    timezone: str = ""
    orcid: str = ""


@router.get("/profile")
async def get_profile(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Get current user's profile."""
    from database import Job, AuditLog
    job_count = db.execute(select(func.count(Job.id)).where(Job.user_id == user.id)).scalar() or 0
    audit_count = db.execute(select(func.count(AuditLog.id)).where(AuditLog.user_id == user.id)).scalar() or 0

    return {
        "id": user.id,
        "robust_id": getattr(user, 'robust_id', '') or f"ROB-{user.id:04d}",
        "email": user.email,
        "full_name": user.full_name or "",
        "role": user.role,
        "organization": user.organization or "",
        "specialization": user.specialization if hasattr(user, 'specialization') else "",
        "bio": user.bio if hasattr(user, 'bio') else "",
        "use_case": user.use_case or "",
        "avatar_color": user.avatar_color if hasattr(user, 'avatar_color') else "#3B82F6",
        "preferred_model": user.preferred_model if hasattr(user, 'preferred_model') else "surrogate",
        "timezone": user.timezone if hasattr(user, 'timezone') else "UTC",
        "orcid": user.orcid if hasattr(user, 'orcid') else "",
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "is_active": user.is_active,
        "stats": {
            "analyses_run": job_count,
            "actions_logged": audit_count,
        },
    }


@router.patch("/profile")
async def update_profile(update: ProfileUpdate, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Update current user's profile."""
    if update.full_name:
        user.full_name = update.full_name[:255]
    if update.organization:
        user.organization = update.organization[:255]
    if update.specialization:
        user.specialization = update.specialization[:100]
    if update.bio:
        user.bio = update.bio[:500]
    if update.use_case:
        user.use_case = update.use_case[:100]
    if update.avatar_color and update.avatar_color.startswith('#') and len(update.avatar_color) == 7:
        user.avatar_color = update.avatar_color
    if update.preferred_model:
        user.preferred_model = update.preferred_model[:50]
    if update.timezone:
        user.timezone = update.timezone[:50]
    if update.orcid is not None:
        # Validate ORCID format: 0000-0000-0000-0000
        orcid_clean = update.orcid.strip()
        if orcid_clean == "" or (len(orcid_clean) == 19 and orcid_clean.count('-') == 3):
            user.orcid = orcid_clean
    db.commit()
    return {"status": "ok", "message": "Profile updated"}


@router.get("/profile/{robust_id}")
async def get_public_profile(robust_id: str, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """View another user's public profile (for collaboration)."""
    from database import Job
    target = db.execute(select(User).where(User.robust_id == robust_id)).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "User not found")

    job_count = db.execute(select(func.count(Job.id)).where(Job.user_id == target.id)).scalar() or 0

    return {
        "robust_id": target.robust_id,
        "full_name": target.full_name or "Anonymous",
        "role": target.role,
        "organization": target.organization or "",
        "specialization": target.specialization if hasattr(target, 'specialization') else "",
        "bio": target.bio if hasattr(target, 'bio') else "",
        "avatar_color": target.avatar_color if hasattr(target, 'avatar_color') else "#3B82F6",
        "orcid": target.orcid if hasattr(target, 'orcid') else "",
        "member_since": target.created_at.isoformat() if target.created_at else None,
        "analyses_run": job_count,
    }


@router.patch("/users/{user_id}/profile")
async def admin_update_user_profile(
    user_id: int,
    update: ProfileUpdate,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Admin: update any user's profile fields."""
    if user.role != "admin":
        raise HTTPException(403, "Admin only")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if update.full_name:
        target.full_name = update.full_name[:255]
    if update.organization:
        target.organization = update.organization[:255]
    if update.specialization:
        target.specialization = update.specialization[:100]
    if update.bio:
        target.bio = update.bio[:500]
    if update.use_case:
        target.use_case = update.use_case[:100]
    if update.avatar_color and update.avatar_color.startswith('#'):
        target.avatar_color = update.avatar_color
    if update.preferred_model:
        target.preferred_model = update.preferred_model[:50]
    if update.timezone:
        target.timezone = update.timezone[:50]
    if update.orcid is not None:
        # Validate ORCID format: 0000-0000-0000-0000
        orcid_clean = update.orcid.strip()
        if orcid_clean == "" or (len(orcid_clean) == 19 and orcid_clean.count('-') == 3):
            target.orcid = orcid_clean
    db.commit()
    return {"status": "ok"}
