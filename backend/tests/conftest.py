"""
Shared test fixtures for the RobustIDPS test suite.

Provides:
  - In-memory SQLite database engine and sessions
  - FastAPI TestClient with dependency overrides
  - Pre-created users (admin, analyst, viewer) with JWT tokens
  - Sample CSV file for upload-based endpoints
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Ensure backend is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Set test config BEFORE importing app modules
os.environ["DATABASE_URL"] = "sqlite://"  # in-memory
os.environ["SECRET_KEY"] = "test-secret-key-for-ci"
os.environ["ADMIN_EMAIL"] = "admin@test.local"
os.environ["ADMIN_PASSWORD"] = "Admin1234!x"

from database import Base, User, Job, get_db
from auth import hash_password, create_access_token


# ── Database fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """Per-test transactional session that rolls back after each test."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


# ── User fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def admin_user(db_session):
    user = User(
        email="admin@test.local",
        password_hash=hash_password("Admin1234!x"),
        full_name="Test Admin",
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def analyst_user(db_session):
    user = User(
        email="analyst@test.local",
        password_hash=hash_password("Analyst1234!x"),
        full_name="Test Analyst",
        role="analyst",
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def viewer_user(db_session):
    user = User(
        email="viewer@test.local",
        password_hash=hash_password("Viewer1234!x"),
        full_name="Test Viewer",
        role="viewer",
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def admin_token(admin_user):
    return create_access_token({"sub": admin_user.email, "role": admin_user.role})


@pytest.fixture
def analyst_token(analyst_user):
    return create_access_token({"sub": analyst_user.email, "role": analyst_user.role})


@pytest.fixture
def viewer_token(viewer_user):
    return create_access_token({"sub": viewer_user.email, "role": viewer_user.role})


# ── FastAPI TestClient ───────────────────────────────────────────────────

@pytest.fixture
def client(db_session):
    """TestClient with DB dependency override pointing to the test session."""
    from fastapi.testclient import TestClient
    from main import app

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ── Sample data fixtures ─────────────────────────────────────────────────

@pytest.fixture
def sample_csv(tmp_path):
    """Minimal CSV with CIC-IoT-2023-like features for upload tests."""
    import numpy as np
    import pandas as pd
    from features import CIC_IOT_2023_FEATURES

    n_rows = 20
    data = {col: np.random.rand(n_rows).tolist() for col in CIC_IOT_2023_FEATURES}
    labels = ["Benign"] * 15 + ["DDoS"] * 3 + ["Recon"] * 2
    data["label"] = labels
    df = pd.DataFrame(data)
    path = tmp_path / "test_traffic.csv"
    df.to_csv(path, index=False)
    return path


@pytest.fixture
def sample_job(db_session, admin_user):
    job = Job(
        id="test1234",
        user_id=admin_user.id,
        filename="test.csv",
        format_detected="cic-iot-2023",
        n_flows=100,
        n_threats=5,
        model_used="surrogate",
    )
    db_session.add(job)
    db_session.flush()
    return job
