"""SQLAlchemy models for the Agent Studio commercial vertical.

All models inherit from `database.Base` so `init_db()` creates them
alongside the IDS-side tables. Postgres + SQLite both work — the
plumbing matches what the rest of the platform already uses.

Tenant isolation strategy:
- Every customer-scoped table carries `customer_id` (FK to
  AgentStudioCustomer.customer_id).
- The route layer enforces "self or admin" via
  `auth.require_self_or_admin()` and a `scoped(query, customer_id)`
  helper here; PG-true RLS is documented in the docstring but kept
  optional so the same code runs on SQLite for dev.

JSON-fallback strategy (zero-downtime migration):
- On first read, if the DB tables are empty AND the legacy
  `weights/agent_studio_*.json` files exist, the helpers transparently
  load them into the DB once and then proceed normally. Subsequent
  reads come from the DB.

Why per-table json columns for findings/severity/etc.?
- Reports are mostly opaque blobs the UI renders verbatim; keeping
  them as JSON beats expanding 30+ scalar columns and the rate of
  schema evolution is high in this vertical.
"""
from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON,
    String, Text, UniqueConstraint, Index,
)
from sqlalchemy.orm import Query, Session, relationship

from database import Base

logger = logging.getLogger("agent_studio.db")


# ── Tables ──────────────────────────────────────────────────────────────

class AgentStudioCustomer(Base):
    __tablename__ = "agent_studio_customers"

    customer_id = Column(String(64), primary_key=True)
    email = Column(String(256), nullable=False, index=True)
    tier = Column(String(32), default="pro", nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    trial_ends_at = Column(String(32), nullable=True)        # ISO date
    stripe_customer_id = Column(String(128), nullable=True)
    stripe_subscription_id = Column(String(128), nullable=True)

    api_keys = relationship("AgentStudioApiKey", back_populates="customer",
                            cascade="all, delete-orphan")
    grants   = relationship("AgentStudioAdminGrant", back_populates="customer",
                            cascade="all, delete-orphan")
    deployments = relationship("AgentStudioDeployment", back_populates="customer",
                                cascade="all, delete-orphan")


class AgentStudioApiKey(Base):
    __tablename__ = "agent_studio_api_keys"
    __table_args__ = (
        Index("ix_agent_studio_api_keys_hash", "key_hash"),   # auth lookup
    )

    id = Column(String(64), primary_key=True)
    customer_id = Column(String(64), ForeignKey("agent_studio_customers.customer_id"),
                         nullable=False, index=True)
    label = Column(String(64), default="default", nullable=False)
    prefix = Column(String(32), nullable=False)               # 14-char display
    key_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False, nullable=False)

    customer = relationship("AgentStudioCustomer", back_populates="api_keys")


class AgentStudioAdminGrant(Base):
    __tablename__ = "agent_studio_admin_grants"

    grant_id = Column(String(64), primary_key=True)
    customer_id = Column(String(64), ForeignKey("agent_studio_customers.customer_id"),
                         nullable=False, index=True)
    email = Column(String(256), nullable=False)
    tier = Column(String(32), default="pro", nullable=False)
    months = Column(Integer, default=12, nullable=False)
    payment_rail = Column(String(32), default="comp", nullable=False, index=True)
    granted_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    granted_by = Column(String(64), default="admin", nullable=False)
    expires_at = Column(String(32), nullable=True)
    note = Column(Text, default="")
    revoked_at = Column(DateTime, nullable=True)

    customer = relationship("AgentStudioCustomer", back_populates="grants")


class AgentStudioDeployment(Base):
    __tablename__ = "agent_studio_deployments"

    deployment_id = Column(String(64), primary_key=True)
    customer_id = Column(String(64), ForeignKey("agent_studio_customers.customer_id"),
                         nullable=False, index=True)
    template_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    runtime_agent_id = Column(String(128), nullable=False, index=True)
    cloud = Column(String(32), default="other", nullable=False)
    region = Column(String(64), default="")
    tier = Column(String(16), default="dev", nullable=False)
    url = Column(String(512), nullable=True)
    git_sha = Column(String(64), nullable=True)
    deployed_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    deployed_by = Column(String(64), default="self")
    note = Column(Text, default="")
    retired_at = Column(DateTime, nullable=True)

    customer = relationship("AgentStudioCustomer", back_populates="deployments")


class AgentStudioSession(Base):
    __tablename__ = "agent_studio_sessions"

    session_id = Column(String(64), primary_key=True)
    customer_id = Column(String(64), index=True, nullable=False)
    template_id = Column(String(64), index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    aborted = Column(Boolean, default=False, nullable=False)

    messages = relationship("AgentStudioSessionMessage", back_populates="session",
                            cascade="all, delete-orphan",
                            order_by="AgentStudioSessionMessage.idx")


class AgentStudioSessionMessage(Base):
    __tablename__ = "agent_studio_session_messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), ForeignKey("agent_studio_sessions.session_id"),
                        nullable=False, index=True)
    idx = Column(Integer, nullable=False)                    # turn order
    role = Column(String(16), nullable=False)                # user / agent / system
    text = Column(Text, nullable=False)
    ts = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    decision = Column(String(16), default="allow", nullable=False)
    n_findings = Column(Integer, default=0, nullable=False)
    findings = Column(JSON, default=list)
    llm_meta = Column(JSON, nullable=True)

    session = relationship("AgentStudioSession", back_populates="messages")


class AgentStudioEvalRun(Base):
    """Stored as an opaque dict — the eval harness is iterating fast."""
    __tablename__ = "agent_studio_eval_runs"

    run_id = Column(String(64), primary_key=True)
    customer_id = Column(String(64), index=True, nullable=True)   # nullable: legacy data
    agent_name = Column(String(256))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    overall_score = Column(Float, default=0.0)
    overall_verdict = Column(String(16), default="warn")
    payload = Column(JSON, nullable=False)          # full RunRecord dict


class AgentStudioRedTeamRun(Base):
    __tablename__ = "agent_studio_red_team_runs"

    run_id = Column(String(64), primary_key=True)
    customer_id = Column(String(64), index=True, nullable=True)
    target_name = Column(String(256))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    n_probes = Column(Integer, default=0)
    n_findings = Column(Integer, default=0)
    payload = Column(JSON, nullable=False)


class AgentStudioSupplyChainScan(Base):
    __tablename__ = "agent_studio_supply_chain_scans"

    scan_id = Column(String(64), primary_key=True)
    customer_id = Column(String(64), index=True, nullable=True)
    model_id = Column(String(256), index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    risk_level = Column(String(16), default="low")
    risk_score = Column(Float, default=0.0)
    payload = Column(JSON, nullable=False)


class AgentStudioWorkspace(Base):
    """A user's saved in-progress build — wizard step + spec + env +
    selected platform models + chat history, etc.

    Owner identity is the `customer_id` returned by the auth layer:
      - platform_<email>  for platform-JWT users (incl. admins)
      - cust_<token>      for Agent Studio API key holders
      - platform_admin    shared admin id (admins generally manage
                          other users' workspaces, not their own)
      - demo_anon         demo mode — saving is refused at the API layer

    Strict per-user isolation: every list / read / update / delete
    enforces (owner_id == caller customer_id) OR caller is admin via
    the `scoped(...)` helper. Postgres-true RLS policies for this table
    are appended to RLS_POSTGRES.sql.
    """
    __tablename__ = "agent_studio_workspaces"
    __table_args__ = (
        Index("ix_workspaces_owner_template", "owner_id", "template_id"),
    )

    workspace_id = Column(String(64), primary_key=True)
    owner_id     = Column(String(64), nullable=False, index=True)
    owner_email  = Column(String(256), nullable=False)
    template_id  = Column(String(64), nullable=False, index=True)
    name         = Column(String(128), nullable=False)
    state        = Column(JSON, nullable=False)
    created_at   = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at   = Column(DateTime, default=datetime.datetime.utcnow,
                          onupdate=datetime.datetime.utcnow, nullable=False)
    archived_at  = Column(DateTime, nullable=True)
    note         = Column(Text, default="")


# ── Tenant scoping helper ───────────────────────────────────────────────

def scoped(query: Query, model_cls: type, customer: dict | None,
           customer_id_col: str = "customer_id") -> Query:
    """Apply application-level row-level security: limit the query to
    rows owned by the calling customer, unless the caller is admin
    (role == 'admin') in which case the query passes through.

    For Postgres-true RLS, see RLS_POSTGRES.sql; this stays the
    portable codepath that works on SQLite + Postgres alike.
    """
    if customer is None:
        return query        # internal / migration / admin codepaths
    if customer.get("role") == "admin":
        return query
    cid = customer.get("customer_id")
    if not cid:
        # Unauthenticated reach — never return anything
        return query.filter(getattr(model_cls, customer_id_col) == "__no_match__")
    return query.filter(getattr(model_cls, customer_id_col) == cid)


# ── One-shot JSON → DB migration ────────────────────────────────────────

JSON_FILES = {
    "customers":     Path("weights/agent_studio_customers.json"),
    "grants":        Path("weights/agent_studio_admin_grants.json"),
    "deployments":   Path("weights/agent_studio_deployments.json"),
    "sessions":      Path("weights/agent_studio_sessions.json"),
    "evals":         Path("weights/agent_studio_eval_runs.json"),
    "redteams":      Path("weights/agent_studio_red_team_runs.json"),
    "supply_chain":  Path("weights/agent_studio_supply_chain_scans.json"),
}


def _safe_dt(value: Any) -> datetime.datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def migrate_json_to_db(db: Session, *, dry_run: bool = False) -> dict:
    """Idempotent: only inserts rows that don't already exist (by PK).
    Returns counts per table. Safe to run on every boot.
    """
    counts: dict[str, int] = {}

    # 1. Customers + API keys
    path = JSON_FILES["customers"]
    if path.exists():
        records = _read_json(path)
        n_cust, n_keys = 0, 0
        for r in records:
            cid = r.get("customer_id")
            if not cid or db.get(AgentStudioCustomer, cid):
                continue
            db.add(AgentStudioCustomer(
                customer_id=cid, email=r.get("email", "unknown@local"),
                tier=r.get("tier", "pro"),
                created_at=_safe_dt(r.get("created_at")) or datetime.datetime.utcnow(),
                trial_ends_at=r.get("trial_ends_at"),
                stripe_customer_id=r.get("stripe_customer_id"),
                stripe_subscription_id=r.get("stripe_subscription_id"),
            ))
            n_cust += 1
            for k in (r.get("api_keys") or []):
                kid = k.get("id")
                if not kid:
                    continue
                # idempotency probe by hash, since id can collide on re-runs
                if db.query(AgentStudioApiKey).filter_by(key_hash=k.get("hash", "")).first():
                    continue
                db.add(AgentStudioApiKey(
                    id=kid, customer_id=cid,
                    label=k.get("label", "default"),
                    prefix=k.get("prefix", ""),
                    key_hash=k.get("hash", ""),
                    created_at=_safe_dt(k.get("created_at")) or datetime.datetime.utcnow(),
                    last_used_at=_safe_dt(k.get("last_used_at")),
                    revoked=bool(k.get("revoked", False)),
                ))
                n_keys += 1
        counts["customers"] = n_cust
        counts["api_keys"] = n_keys

    # 2. Admin grants
    path = JSON_FILES["grants"]
    if path.exists():
        n = 0
        for r in _read_json(path):
            gid = r.get("grant_id")
            if not gid or db.get(AgentStudioAdminGrant, gid):
                continue
            if not r.get("customer_id") or not db.get(AgentStudioCustomer, r["customer_id"]):
                continue
            db.add(AgentStudioAdminGrant(
                grant_id=gid, customer_id=r["customer_id"],
                email=r.get("email", ""), tier=r.get("tier", "pro"),
                months=int(r.get("months", 12)),
                payment_rail=r.get("payment_rail", "comp"),
                granted_at=_safe_dt(r.get("granted_at")) or datetime.datetime.utcnow(),
                granted_by=r.get("granted_by", "admin"),
                expires_at=r.get("expires_at"),
                note=r.get("note", ""),
                revoked_at=_safe_dt(r.get("revoked_at")),
            ))
            n += 1
        counts["grants"] = n

    # 3. Deployments
    path = JSON_FILES["deployments"]
    if path.exists():
        n = 0
        for r in _read_json(path):
            did = r.get("deployment_id")
            if not did or db.get(AgentStudioDeployment, did):
                continue
            if not r.get("customer_id") or not db.get(AgentStudioCustomer, r["customer_id"]):
                continue
            db.add(AgentStudioDeployment(
                deployment_id=did, customer_id=r["customer_id"],
                template_id=r.get("template_id", "blank"),
                name=r.get("name", "unnamed"),
                runtime_agent_id=r.get("runtime_agent_id", ""),
                cloud=r.get("cloud", "other"), region=r.get("region", ""),
                tier=r.get("tier", "dev"),
                url=r.get("url"), git_sha=r.get("git_sha"),
                deployed_at=_safe_dt(r.get("deployed_at")) or datetime.datetime.utcnow(),
                deployed_by=r.get("deployed_by", "self"),
                note=r.get("note", ""),
                retired_at=_safe_dt(r.get("retired_at")),
            ))
            n += 1
        counts["deployments"] = n

    # 4. Sessions + messages
    path = JSON_FILES["sessions"]
    if path.exists():
        n_sess, n_msg = 0, 0
        for r in _read_json(path):
            sid = r.get("session_id")
            if not sid or db.get(AgentStudioSession, sid):
                continue
            db.add(AgentStudioSession(
                session_id=sid,
                customer_id=r.get("customer_id", "anon"),
                template_id=r.get("template_id", "blank"),
                created_at=_safe_dt(r.get("created_at")) or datetime.datetime.utcnow(),
                aborted=bool(r.get("aborted", False)),
            ))
            for idx, m in enumerate(r.get("history") or []):
                db.add(AgentStudioSessionMessage(
                    session_id=sid, idx=idx,
                    role=m.get("role", "user"),
                    text=m.get("text", ""),
                    ts=_safe_dt(m.get("ts")) or datetime.datetime.utcnow(),
                    decision=m.get("decision", "allow"),
                    n_findings=int(m.get("n_findings", 0)),
                    findings=m.get("findings") or [],
                    llm_meta=m.get("llm_meta"),
                ))
                n_msg += 1
            n_sess += 1
        counts["sessions"] = n_sess
        counts["session_messages"] = n_msg

    # 5. Eval / red-team / supply-chain histories (opaque payloads)
    for key, model in [("evals", AgentStudioEvalRun),
                       ("redteams", AgentStudioRedTeamRun),
                       ("supply_chain", AgentStudioSupplyChainScan)]:
        path = JSON_FILES[key]
        if not path.exists():
            continue
        n = 0
        for r in _read_json(path):
            rid = (r.get("run_id") or r.get("scan_id"))
            if not rid or db.get(model, rid):
                continue
            common = {
                "customer_id": r.get("customer_id"),
                "timestamp": _safe_dt(r.get("timestamp")) or datetime.datetime.utcnow(),
                "payload": r,
            }
            if model is AgentStudioEvalRun:
                db.add(AgentStudioEvalRun(
                    run_id=rid, agent_name=r.get("agent_name", ""),
                    overall_score=float(r.get("overall_score", 0.0)),
                    overall_verdict=r.get("overall_verdict", "warn"),
                    **common,
                ))
            elif model is AgentStudioRedTeamRun:
                db.add(AgentStudioRedTeamRun(
                    run_id=rid, target_name=r.get("target_name", ""),
                    n_probes=int(r.get("n_probes", 0)),
                    n_findings=int(r.get("n_findings", 0)),
                    **common,
                ))
            else:
                db.add(AgentStudioSupplyChainScan(
                    scan_id=rid, model_id=r.get("model_id", ""),
                    risk_level=r.get("risk_level", "low"),
                    risk_score=float(r.get("risk_score", 0.0)),
                    **common,
                ))
            n += 1
        counts[key] = n

    if dry_run:
        db.rollback()
    else:
        db.commit()
    logger.info("agent_studio JSON→DB migration: %s", counts)
    return counts


def _read_json(path: Path) -> list:
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    return []


# ── Hash lookup for the auth dependency ─────────────────────────────────

def find_api_key_by_hash(db: Session, key_hash: str
                         ) -> tuple[AgentStudioCustomer, AgentStudioApiKey] | None:
    key = db.query(AgentStudioApiKey).filter_by(key_hash=key_hash, revoked=False).first()
    if key is None:
        return None
    return (key.customer, key)
