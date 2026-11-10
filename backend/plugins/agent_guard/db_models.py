"""Persistent state shared by the guard and the other Agent Security modules.

Created by `init_db()` at boot (importing this module registers the tables).
Rows are scoped by the Agent Studio customer id (platform user, API-key
customer, admin or demo), the identity every Agent Studio endpoint uses.
"""
from __future__ import annotations

import datetime

from sqlalchemy import JSON, Column, DateTime, Integer, String, Text, UniqueConstraint

from database import Base


class GuardToolset(Base):
    """One version of a registered tool set (an MCP server's tools/list, or an agent's tools)."""
    __tablename__ = "agent_guard_toolsets"
    __table_args__ = (UniqueConstraint("customer_id", "name", "version", name="uq_guard_toolset_version"),)

    id = Column(String(32), primary_key=True)
    customer_id = Column(String(255), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    version = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    pinned = Column(Integer, default=0)                # 1 = the approved version the gateway checks against
    digest = Column(String(64), nullable=False)        # over all tool fingerprints
    tools = Column(JSON, nullable=False)               # [{name, description, input_schema, fingerprint, hidden}]
    scan = Column(JSON, nullable=True)                 # scanner summary of the raw text
    diff = Column(JSON, nullable=True)                 # against the previous version


class GuardApproval(Base):
    """A call the guard answered with 'ask', waiting for a human."""
    __tablename__ = "agent_guard_approvals"

    id = Column(String(32), primary_key=True)
    customer_id = Column(String(255), nullable=False, index=True)
    session_id = Column(String(128), nullable=False)
    call_key = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False, default="pending", index=True)  # pending|approved|denied|used|expired
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    decided_at = Column(DateTime, nullable=True)
    decided_by = Column(String(255), default="")
    note = Column(Text, default="")
    request = Column(JSON, nullable=False)             # tool, canonical args, policy id/version, agent, framework
    preview = Column(JSON, nullable=False)             # what the reviewer sees (targets, tier, reasons, ...)


class GuardEvidence(Base):
    """Append-only, hash-chained record of decisions, approvals, pins, scans and evaluations."""
    __tablename__ = "agent_guard_evidence"
    __table_args__ = (UniqueConstraint("customer_id", "seq", name="uq_guard_evidence_seq"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(String(255), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    kind = Column(String(32), nullable=False, index=True)
    summary = Column(String(500), default="")
    payload = Column(JSON, nullable=False)
    payload_digest = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False)
