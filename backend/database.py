"""
SQLAlchemy database — models, engine, and session management.

Supports SQLite (development) and PostgreSQL (production).
"""

import datetime

from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean,
    ForeignKey, Float, create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship, Session, sessionmaker

from config import DATABASE_URL


class Base(DeclarativeBase):
    pass


# ── Models ────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), default="")
    role = Column(String(50), default="analyst")  # admin | analyst | viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    jobs = relationship("Job", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String(8), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    filename = Column(String(255))
    format_detected = Column(String(50))
    n_flows = Column(Integer)
    n_threats = Column(Integer, default=0)
    model_used = Column(String(100))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="jobs")
    firewall_rules = relationship("FirewallRule", back_populates="job")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)   # LOGIN, UPLOAD, PREDICT, etc.
    resource = Column(String(255))                  # e.g. job_id, model_id
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")


class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(8), ForeignKey("jobs.id"))
    rule_type = Column(String(50))        # iptables | nftables | snort | suricata
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    action = Column(String(50))           # DROP | REJECT | LOG | ALERT
    threat_label = Column(String(100))
    severity = Column(String(20))
    confidence = Column(Float)
    rule_text = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    job = relationship("Job", back_populates="firewall_rules")


# ── Engine & Session ──────────────────────────────────────────────────────

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=connect_args, echo=False)
SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency — yields a DB session and auto-closes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
