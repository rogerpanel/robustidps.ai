"""
P0 — Authentication & Authorization
=====================================
Critical: JWT flow, password hashing, role checks, brute-force protection.
"""

import datetime
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth import (
    hash_password, verify_password, create_access_token,
    validate_password_strength, _check_lockout, _record_failed_attempt,
    _clear_failed_attempts, _failed_attempts,
)
from config import SECRET_KEY, JWT_ALGORITHM

import jwt as pyjwt


class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "SecurePass1!"
        hashed = hash_password(pw)
        assert hashed != pw
        assert verify_password(pw, hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("CorrectPass1!")
        assert not verify_password("WrongPass1!", hashed)

    def test_different_hashes_for_same_password(self):
        pw = "SamePass1!"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2  # bcrypt uses random salt
        assert verify_password(pw, h1)
        assert verify_password(pw, h2)

    def test_verify_invalid_hash_returns_false(self):
        assert not verify_password("test", "not-a-valid-hash")


class TestPasswordStrength:
    def test_strong_password_passes(self):
        # Should not raise
        validate_password_strength("StrongP@ss1")

    def test_too_short_fails(self):
        with pytest.raises(Exception):
            validate_password_strength("Ab1!")

    def test_no_uppercase_fails(self):
        with pytest.raises(Exception):
            validate_password_strength("lowercase1!")

    def test_no_lowercase_fails(self):
        with pytest.raises(Exception):
            validate_password_strength("UPPERCASE1!")

    def test_no_digit_fails(self):
        with pytest.raises(Exception):
            validate_password_strength("NoDigits!!")

    def test_no_special_char_fails(self):
        with pytest.raises(Exception):
            validate_password_strength("NoSpecial1a")


class TestJWTTokens:
    def test_create_and_decode_token(self):
        token = create_access_token({"sub": "user@test.com", "role": "analyst"})
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "user@test.com"
        assert payload["role"] == "analyst"
        assert "exp" in payload

    def test_token_expiry(self):
        token = create_access_token(
            {"sub": "user@test.com"},
            expires_delta=datetime.timedelta(seconds=1),
        )
        time.sleep(2)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            pyjwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

    def test_custom_expiry(self):
        token = create_access_token(
            {"sub": "user@test.com"},
            expires_delta=datetime.timedelta(hours=24),
        )
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        exp = datetime.datetime.fromtimestamp(payload["exp"], tz=datetime.timezone.utc)
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        assert (exp - now).total_seconds() > 23 * 3600

    def test_invalid_secret_fails(self):
        token = create_access_token({"sub": "user@test.com"})
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(token, "wrong-secret", algorithms=[JWT_ALGORITHM])


class TestBruteForceProtection:
    def setup_method(self):
        _failed_attempts.clear()

    def test_no_lockout_under_threshold(self):
        for _ in range(4):
            _record_failed_attempt("test@brute.com")
        # Should not raise
        _check_lockout("test@brute.com")

    def test_lockout_at_threshold(self):
        for _ in range(5):
            _record_failed_attempt("locked@brute.com")
        with pytest.raises(Exception) as exc_info:
            _check_lockout("locked@brute.com")
        assert "Too many failed" in str(exc_info.value.detail)

    def test_clear_attempts_resets(self):
        for _ in range(5):
            _record_failed_attempt("clear@brute.com")
        _clear_failed_attempts("clear@brute.com")
        # Should not raise after clearing
        _check_lockout("clear@brute.com")

    def test_unknown_email_no_lockout(self):
        _check_lockout("unknown@brute.com")  # Should not raise


class TestAuthEndpoints:
    """Integration tests for auth API endpoints."""

    def test_register_new_user(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "new@test.com",
            "password": "NewUser1!x",
            "full_name": "New User",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["email"] == "new@test.com"

    def test_register_duplicate_email(self, client):
        client.post("/api/auth/register", json={
            "email": "dup@test.com", "password": "DupUser1!x",
        })
        resp = client.post("/api/auth/register", json={
            "email": "dup@test.com", "password": "DupUser1!x",
        })
        assert resp.status_code == 400

    def test_register_weak_password(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "weak@test.com", "password": "123",
        })
        assert resp.status_code == 400

    def test_login_success(self, client, admin_user):
        resp = client.post("/api/auth/login", data={
            "username": admin_user.email,
            "password": "Admin1234!x",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_wrong_password(self, client, admin_user):
        resp = client.post("/api/auth/login", data={
            "username": admin_user.email,
            "password": "wrong",
        })
        assert resp.status_code == 401

    def test_me_authenticated(self, client, admin_user, admin_token):
        resp = client.get("/api/auth/me", headers={
            "Authorization": f"Bearer {admin_token}"
        })
        assert resp.status_code == 200
        assert resp.json()["email"] == admin_user.email

    def test_me_unauthenticated(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_invalid_token(self, client):
        resp = client.get("/api/auth/me", headers={
            "Authorization": "Bearer invalid-token"
        })
        assert resp.status_code == 401

    def test_first_user_becomes_admin(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "first@test.com", "password": "FirstUser1!x",
        })
        assert resp.status_code == 200
        assert resp.json()["user"]["role"] == "admin"


class TestRBAC:
    """Role-based access control tests."""

    def test_admin_can_list_users(self, client, admin_user, admin_token):
        resp = client.get("/api/auth/users", headers={
            "Authorization": f"Bearer {admin_token}"
        })
        assert resp.status_code == 200

    def test_analyst_cannot_list_users(self, client, analyst_user, analyst_token):
        resp = client.get("/api/auth/users", headers={
            "Authorization": f"Bearer {analyst_token}"
        })
        assert resp.status_code == 403

    def test_admin_can_update_role(self, client, admin_user, analyst_user, admin_token):
        resp = client.patch(
            f"/api/auth/users/{analyst_user.id}/role",
            params={"role": "viewer"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

    def test_admin_cannot_delete_self(self, client, admin_user, admin_token):
        resp = client.delete(
            f"/api/auth/users/{admin_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 400
