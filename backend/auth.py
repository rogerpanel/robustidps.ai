"""
JWT Authentication & Role-Based Access Control.

Roles:
  admin   — Full access: manage users, system settings, all operations
  analyst — Upload, analyse, view results, export
  viewer  — Read-only access to dashboard, analytics, datasets
"""

import datetime
import logging
import re
import time
from collections import defaultdict
from typing import Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from config import SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import get_db, User

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
    except jwt.PyJWTError:
        return None
    return db.execute(select(User).where(User.email == email)).scalar_one_or_none()


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
    )


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.post("/register", response_model=Token)
def register(body: UserCreate, db: Session = Depends(get_db)):
    """Register a new user account (public self-registration)."""
    existing = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    validate_password_strength(body.password)

    if body.use_case and body.use_case not in USE_CASE_OPTIONS:
        raise HTTPException(status_code=400, detail="Invalid use case selection")

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        organization=body.organization,
        use_case=body.use_case,
        role="viewer",  # public registrations get viewer role by default
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("New user registered: %s (role=viewer)", user.email)
    token = create_access_token({"sub": user.email, "role": user.role})
    return Token(access_token=token, user=_user_response(user))


@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login with email + password, returns JWT."""
    _check_lockout(form.username)

    user = db.execute(select(User).where(User.email == form.username)).scalar_one_or_none()
    if not user or not verify_password(form.password, user.password_hash):
        _record_failed_attempt(form.username)
        logger.warning("Failed login attempt: %s", form.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    _clear_failed_attempts(form.username)
    user.last_login = datetime.datetime.utcnow()
    db.commit()

    logger.info("User logged in: %s", user.email)
    token = create_access_token({"sub": user.email, "role": user.role})
    return Token(access_token=token, user=_user_response(user))


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
    db.add(admin)
    db.commit()
    logger.info("Default admin created: %s", ADMIN_EMAIL)
