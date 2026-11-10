"""Environment model for the predictive layer: the defender's asset inventory.

The rule layers judge a call by itself. The predictive layer asks what the call
would do to the environment: which assets become unavailable, how many things
depend on them, and whether a redundancy group would fall below the number of
members that must stay up. All of this comes from an inventory the defender
maintains (names, roles, dependents, groups), not from text an attacker wrote.

An inventory is JSON:

    {"groups": {"domain-controllers": {"min_available": 1, "description": "..."}},
     "assets": [
       {"name": "DC-01", "kind": "host", "ip": "10.0.0.10", "role": "domain controller",
        "group": "domain-controllers", "dependents": 900},
       {"name": "svc-backup", "kind": "account", "role": "backup service account", "dependents": 300},
       {"name": "SRV-DB-01", "kind": "host", "services": [
           {"name": "crm-database", "process": "sqlservr.exe", "path": "C:\\\\Program Files\\\\SQL\\\\sqlservr.exe",
            "group": "crm-db", "dependents": 40}]}]}

`available: false` marks an asset that is already down or contained. An optional
`"internal": ["10.0.0.0/8", "*.corp.example", "*@corp.example"]` lists destinations
inside the organisation for the information-flow rules (sending there is not egress).
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import threading
from typing import Literal

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import JSON, Column, DateTime, Integer, String
from sqlalchemy.orm import Session

from database import Base

MAX_ASSETS = 5000

AssetKind = Literal["host", "account", "ip", "domain"]


class Group(BaseModel):
    min_available: int = Field(1, ge=0)
    description: str = ""


class Service(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    process: str = Field("", max_length=256)
    path: str = Field("", max_length=1024)
    group: str | None = None
    dependents: int = Field(0, ge=0)


class Asset(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    kind: AssetKind = "host"
    ip: str = ""
    aliases: list[str] = Field(default_factory=list)
    role: str = ""
    group: str | None = None
    dependents: int = Field(0, ge=0, description="Users, hosts or services that stop working without it")
    available: bool = True
    services: list[Service] = Field(default_factory=list)


class Environment(BaseModel):
    groups: dict[str, Group] = Field(default_factory=dict)
    assets: list[Asset] = Field(default_factory=list, max_length=MAX_ASSETS)
    internal: list[str] = Field(default_factory=list, max_length=200,
                                description="Networks, hosts and addresses inside the organisation (10.0.0.0/8, "
                                            "*.corp.example, *@corp.example); sending data there is not egress "
                                            "for the information-flow rules")

    @model_validator(mode="after")
    def _consistent(self) -> "Environment":
        for entry in self.internal:
            if "/" in entry:
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    raise ValueError(f"internal: '{entry}' is not a valid network") from None
        names = [a.name.lower() for a in self.assets]
        if len(set(names)) != len(names):
            raise ValueError("asset names must be unique")
        used = {a.group for a in self.assets if a.group} | {s.group for a in self.assets for s in a.services if s.group}
        missing = sorted(g for g in used if g not in self.groups)
        if missing:
            raise ValueError(f"groups used by assets but not defined: {', '.join(missing)}")
        return self

    # ── lookup ─────────────────────────────────────────────────────────

    def find(self, kind: str, value: str) -> Asset | None:
        v = value.strip().lower()
        if not v:
            return None
        for a in self.assets:
            if kind == "ip":
                if a.ip and a.ip.lower() == v:
                    return a
                if a.kind == "ip" and a.name.lower() == v:
                    return a
            elif a.kind == kind and (a.name.lower() == v or v in (x.lower() for x in a.aliases)
                                     or (kind == "host" and a.ip and a.ip.lower() == v)):
                return a
        return None

    def members(self, group: str) -> list[str]:
        """Member ids (asset or asset/service) of a redundancy group, and whether each is available."""
        out = []
        for a in self.assets:
            if a.group == group:
                out.append(a.name.lower())
            for s in a.services:
                if s.group == group:
                    out.append(f"{a.name.lower()}/{s.name.lower()}")
        return out

    def unavailable_ids(self) -> set[str]:
        down = set()
        for a in self.assets:
            if not a.available:
                down.add(a.name.lower())
                down.update(f"{a.name.lower()}/{s.name.lower()}" for s in a.services)
        return down


# ── persistence (per tenant) ───────────────────────────────────────────

class GuardEnvironment(Base):
    __tablename__ = "agent_guard_environments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(String(255), nullable=False, unique=True, index=True)
    version = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_by = Column(String(255), default="")
    data = Column(JSON, nullable=False)


_cache: dict[str, tuple[int, Environment]] = {}
_lock = threading.Lock()


def load(db: Session, customer_id: str) -> tuple[Environment | None, int]:
    row = db.query(GuardEnvironment).filter_by(customer_id=customer_id).one_or_none()
    if row is None:
        return None, 0
    with _lock:
        hit = _cache.get(customer_id)
        if hit and hit[0] == row.version:
            return hit[1], row.version
    env = Environment.model_validate(row.data)
    with _lock:
        _cache[customer_id] = (row.version, env)
    return env, row.version


def save(db: Session, customer_id: str, env: Environment, actor: str) -> int:
    row = db.query(GuardEnvironment).filter_by(customer_id=customer_id).one_or_none()
    data = json.loads(env.model_dump_json())
    if row is None:
        row = GuardEnvironment(customer_id=customer_id, version=1, data=data, updated_by=actor)
        db.add(row)
    else:
        row.version += 1
        row.data = data
        row.updated_by = actor
        row.updated_at = datetime.datetime.utcnow()
    db.commit()
    return row.version


EXAMPLE = {
    "groups": {
        "domain-controllers": {"min_available": 1, "description": "Authentication for the site"},
        "dns-resolvers": {"min_available": 1, "description": "Internal name resolution"},
        "crm-db": {"min_available": 1, "description": "CRM database service"},
    },
    "assets": [
        {"name": "DC-01", "kind": "host", "ip": "10.0.0.10", "role": "domain controller",
         "group": "domain-controllers", "dependents": 900},
        {"name": "DNS-01", "kind": "host", "ip": "10.0.0.53", "role": "internal DNS resolver",
         "group": "dns-resolvers", "dependents": 900},
        {"name": "SRV-DB-01", "kind": "host", "ip": "10.0.2.20", "role": "database server", "dependents": 40,
         "services": [{"name": "crm-database", "process": "sqlservr.exe", "group": "crm-db", "dependents": 40}]},
        {"name": "SRV-FILE-02", "kind": "host", "ip": "10.0.2.30", "role": "file server", "dependents": 300,
         "services": [{"name": "backup-agent", "path": "C:\\Program Files\\Backup\\agent.exe", "dependents": 300}]},
        {"name": "WS-0412", "kind": "host", "ip": "10.0.4.12", "role": "workstation", "dependents": 1},
        {"name": "WS-0413", "kind": "host", "ip": "10.0.4.13", "role": "workstation", "dependents": 1},
        {"name": "svc-backup", "kind": "account", "role": "backup service account", "dependents": 300},
        {"name": "jdoe", "kind": "account", "role": "user", "dependents": 1},
        {"name": "login.microsoftonline.com", "kind": "domain", "role": "company sign-in (SaaS)", "dependents": 900},
    ],
    "internal": ["10.0.0.0/8", "*.corp.example", "*@corp.example"],
}
