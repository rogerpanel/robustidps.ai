"""Self-registration with e-mail confirmation (auth router only; no ML stack needed)."""
import re
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import auth
from database import Base, User, get_db

pytestmark = pytest.mark.p0

GOOD = {"email": "New.User@Example.org", "password": "NewUser1!x", "full_name": "New User"}


@pytest.fixture
def env(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    def _db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    app.include_router(auth.router)
    app.dependency_overrides[get_db] = _db

    sent = []
    monkeypatch.setattr(auth, "send_mail", lambda to, subject, text, html=None: sent.append((to, text)))
    monkeypatch.setattr(auth, "mail_configured", lambda: True)
    monkeypatch.setenv("REGISTRATION_MODE", "verify")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://example.test")
    auth._register_hits.clear()
    auth._mail_hits.clear()
    with TestClient(app) as client:
        yield client, Session, sent
    engine.dispose()


def _token(text):
    link = re.search(r"https://example\.test/api/auth/verify-email\?token=\S+", text).group(0)
    return parse_qs(urlparse(link).query)["token"][0]


def _login(client, email, password):
    return client.post("/api/auth/login", data={"username": email, "password": password})


def test_closed_by_default(env, monkeypatch):
    client, _, sent = env
    monkeypatch.delenv("REGISTRATION_MODE")
    assert client.get("/api/auth/registration").json() == {"mode": "closed"}
    assert client.post("/api/auth/register", json=GOOD).status_code == 403
    assert sent == []


def test_closed_without_mail(env, monkeypatch):
    client, _, _ = env
    monkeypatch.setattr(auth, "mail_configured", lambda: False)
    assert client.get("/api/auth/registration").json() == {"mode": "closed"}
    assert client.post("/api/auth/register", json=GOOD).status_code == 403


def test_register_confirm_login(env):
    client, Session, sent = env
    resp = client.post("/api/auth/register", json=GOOD)
    assert resp.status_code == 202 and "access_token" not in resp.json()
    assert len(sent) == 1 and sent[0][0] == "new.user@example.org"
    with Session() as db:
        user = db.query(User).filter_by(email="new.user@example.org").one()
        assert user.email_verified is False and user.role == "viewer"

    # Unconfirmed: cannot sign in, and the link token is not a login token.
    resp = _login(client, "new.user@example.org", GOOD["password"])
    assert resp.status_code == 403 and "not confirmed" in resp.json()["detail"]
    token = _token(sent[0][1])
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    resp = client.get("/api/auth/verify-email", params={"token": token}, follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"] == "/?verified=1"
    resp = _login(client, "new.user@example.org", GOOD["password"])
    assert resp.status_code == 200 and resp.json()["user"]["email_verified"] is True


def test_bad_and_login_tokens_rejected(env):
    client, Session, _ = env
    client.post("/api/auth/register", json=GOOD)
    resp = client.get("/api/auth/verify-email", params={"token": "garbage"}, follow_redirects=False)
    assert resp.headers["location"] == "/?verified=invalid"
    # An ordinary login token for the address must not confirm it.
    login_token = auth.create_access_token({"sub": "new.user@example.org", "purpose": "verify-email"})
    resp = client.get("/api/auth/verify-email", params={"token": login_token}, follow_redirects=False)
    assert resp.headers["location"] == "/?verified=invalid"
    with Session() as db:
        assert db.query(User).filter_by(email="new.user@example.org").one().email_verified is False


def test_duplicate_does_not_leak_or_change_password(env):
    client, Session, sent = env
    client.post("/api/auth/register", json=GOOD)
    auth._mail_hits.clear()
    again = dict(GOOD, password="Other1234!x")
    resp = client.post("/api/auth/register", json=again)
    assert resp.status_code == 202
    assert len(sent) == 2  # a fresh link for the unconfirmed account
    with Session() as db:
        user = db.query(User).filter_by(email="new.user@example.org").one()
        assert auth.verify_password(GOOD["password"], user.password_hash)
    # A confirmed account gets the same answer and no mail.
    with Session() as db:
        db.add(User(email="old@example.org", password_hash=auth.hash_password("Old12345!x")))
        db.commit()
    resp = client.post("/api/auth/register", json=dict(GOOD, email="old@example.org"))
    assert resp.status_code == 202 and len(sent) == 2


def test_resend_is_throttled_and_generic(env):
    client, _, sent = env
    client.post("/api/auth/register", json=GOOD)
    assert client.post("/api/auth/resend-verification", json={"email": GOOD["email"]}).status_code == 202
    assert len(sent) == 1  # within a minute of the first mail
    assert client.post("/api/auth/resend-verification", json={"email": "nobody@example.org"}).status_code == 202


def test_mail_failure_rolls_back(env, monkeypatch):
    client, Session, _ = env

    def fail(*a, **k):
        raise auth.MailError("down")

    monkeypatch.setattr(auth, "send_mail", fail)
    assert client.post("/api/auth/register", json=GOOD).status_code == 503
    with Session() as db:
        assert db.query(User).filter_by(email="new.user@example.org").count() == 0


def test_validation(env):
    client, _, _ = env
    assert client.post("/api/auth/register", json=dict(GOOD, email="not-an-email")).status_code == 400
    assert client.post("/api/auth/register", json=dict(GOOD, password="weak")).status_code == 400


def test_legacy_rows_count_as_verified(env):
    client, Session, _ = env
    with Session() as db:
        db.add(User(email="legacy@example.org", password_hash=auth.hash_password("Legacy123!x"),
                    email_verified=None))
        db.commit()
    assert _login(client, "legacy@example.org", "Legacy123!x").status_code == 200
