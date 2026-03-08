"""
SQLAlchemy database — models, engine, and session management.

Supports SQLite (development) and PostgreSQL (production).
"""

import datetime

from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean,
    ForeignKey, Float, JSON, create_engine,
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
    organization = Column(String(255), default="")
    use_case = Column(String(100), default="")  # Industry Work | Academic Research | ...
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


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(20), unique=True, nullable=False, index=True)
    playbook_id = Column(String(100), nullable=False)
    playbook_name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    source_ip = Column(String(45))
    target_ip = Column(String(45))
    threat_label = Column(String(200))
    confidence = Column(Float)
    mode = Column(String(20), default="simulation")
    steps = Column(JSON, default=list)
    total_simulated_ms = Column(Integer, default=0)
    actual_execution_ms = Column(Float, default=0)
    effectiveness_score = Column(Float)
    false_positive_rate = Column(Float)
    triggered_by = Column(String(255))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(20), ForeignKey("incidents.incident_id"), nullable=False)
    author = Column(String(255))
    note = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    incident = relationship("Incident", back_populates="notes")


class CustomPlaybook(Base):
    __tablename__ = "custom_playbooks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    playbook_key = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    trigger_classes = Column(JSON, default=list)
    severity = Column(String(20), default="medium")
    auto_execute = Column(Boolean, default=False)
    requires_approval = Column(Boolean, default=True)
    response_chain = Column(JSON, default=list)
    estimated_response_ms = Column(Integer, default=0)
    effectiveness_score = Column(Float, default=0.80)
    false_positive_rate = Column(Float, default=0.05)
    created_by = Column(String(255))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


# ── Engine & Session ──────────────────────────────────────────────────────

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=connect_args, echo=False)
SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


def init_db():
    """Create all tables if they don't exist, and add missing columns."""
    Base.metadata.create_all(bind=engine)
    _migrate_columns()


def _migrate_columns():
    """Add any columns that are in the models but missing from the DB."""
    import sqlalchemy as sa
    inspector = sa.inspect(engine)
    for table_name, model_cls in [("users", User)]:
        if not inspector.has_table(table_name):
            continue
        existing = {c["name"] for c in inspector.get_columns(table_name)}
        for col in model_cls.__table__.columns:
            if col.name not in existing:
                col_type = col.type.compile(engine.dialect)
                default = "''" if isinstance(col.type, sa.String) else "NULL"
                with engine.begin() as conn:
                    conn.execute(sa.text(
                        f'ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type} DEFAULT {default}'
                    ))


def get_db():
    """FastAPI dependency — yields a DB session and auto-closes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
