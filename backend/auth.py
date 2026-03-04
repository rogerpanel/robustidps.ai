"""
JWT Authentication & Role-Based Access Control.

Roles:
  admin   — Full access: manage users, system settings, all operations
  analyst — Upload, analyse, view results, export
  viewer  — Read-only access to dashboard, analytics, datasets
"""

import datetime
import logging
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from config import SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import get_db, User

logger = logging.getLogger("robustidps.auth")

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


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
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


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
    """Register a new account. The first user becomes admin."""
    existing = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    # First user becomes admin
    is_first = db.execute(select(User)).scalar_one_or_none() is None

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        organization=body.organization,
        use_case=body.use_case,
        role="admin" if is_first else "analyst",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("User registered: %s (role=%s)", user.email, user.role)
    token = create_access_token({"sub": user.email, "role": user.role})
    return Token(access_token=token, user=_user_response(user))


@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login with email + password, returns JWT."""
    user = db.execute(select(User).where(User.email == form.username)).scalar_one_or_none()
    if not user or not verify_password(form.password, user.password_hash):
        logger.warning("Failed login attempt: %s", form.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

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
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
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


# ── Startup: create default admin ─────────────────────────────────────────

def ensure_default_admin(db: Session):
    """Create the default admin account if no users exist."""
    from config import ADMIN_EMAIL, ADMIN_PASSWORD
    if db.execute(select(User)).scalar_one_or_none() is not None:
        return  # users exist already
    if not ADMIN_PASSWORD:
        logger.warning("No ADMIN_PASSWORD set — skipping default admin creation")
        return
    admin = User(
        email=ADMIN_EMAIL,
        password_hash=hash_password(ADMIN_PASSWORD),
        full_name="System Administrator",
        role="admin",
    )
    db.add(admin)
    db.commit()
    logger.info("Default admin created: %s", ADMIN_EMAIL)
