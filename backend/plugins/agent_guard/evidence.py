"""Evidence ledger: an append-only, hash-chained record per customer.

Each record's hash covers its sequence number, kind, timestamp, payload digest
and the previous record's hash, so editing or deleting any earlier record
breaks every later hash. verify() recomputes the chain; the head hash can be
quoted in a dossier or paper as a commitment to the whole history.

Kinds: guard_decision (deny / ask / modify only; allows are counted, not
stored), approval, toolset_pin, toolset_register, toolset_drift, session_reset,
evaluation, evaluation_compare.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import threading
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from plugins.agent_guard.db_models import GuardEvidence

GENESIS = "0" * 64
_lock = threading.Lock()  # one writer per process keeps seq dense (single backend worker)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _record_hash(seq: int, kind: str, created_at: datetime.datetime, payload_digest: str, prev: str) -> str:
    material = f"{seq}|{kind}|{created_at.isoformat(timespec='microseconds')}|{payload_digest}|{prev}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def append(db: Session, customer_id: str, kind: str, payload: dict, summary: str = "") -> GuardEvidence:
    with _lock:
        last = db.execute(select(GuardEvidence).where(GuardEvidence.customer_id == customer_id)
                          .order_by(GuardEvidence.seq.desc()).limit(1)).scalar_one_or_none()
        seq = (last.seq + 1) if last else 1
        prev = last.hash if last else GENESIS
        created = datetime.datetime.utcnow().replace(tzinfo=None)
        pdig = digest(payload)
        row = GuardEvidence(customer_id=customer_id, seq=seq, created_at=created, kind=kind,
                            summary=summary[:500], payload=payload, payload_digest=pdig, prev_hash=prev,
                            hash=_record_hash(seq, kind, created, pdig, prev))
        db.add(row)
        db.commit()
        return row


def verify(db: Session, customer_id: str) -> dict:
    rows = db.execute(select(GuardEvidence).where(GuardEvidence.customer_id == customer_id)
                      .order_by(GuardEvidence.seq)).scalars().all()
    prev = GENESIS
    for i, row in enumerate(rows, start=1):
        problems = []
        if row.seq != i:
            problems.append(f"sequence gap at {i}")
        if row.prev_hash != prev:
            problems.append("previous-hash mismatch")
        if digest(row.payload) != row.payload_digest:
            problems.append("payload changed")
        if _record_hash(row.seq, row.kind, row.created_at, row.payload_digest, row.prev_hash) != row.hash:
            problems.append("record hash mismatch")
        if problems:
            return {"valid": False, "records": len(rows), "broken_at": row.seq, "problems": problems,
                    "head": rows[-1].hash}
        prev = row.hash
    return {"valid": True, "records": len(rows), "head": prev if rows else GENESIS}


def as_dict(row: GuardEvidence, with_payload: bool = False) -> dict:
    out = {"seq": row.seq, "created_at": row.created_at.isoformat() + "Z", "kind": row.kind,
           "summary": row.summary, "payload_digest": row.payload_digest, "prev_hash": row.prev_hash,
           "hash": row.hash}
    if with_payload:
        out["payload"] = row.payload
    return out


def listing(db: Session, customer_id: str, kind: str | None = None, limit: int = 100) -> list[dict]:
    q = select(GuardEvidence).where(GuardEvidence.customer_id == customer_id)
    if kind:
        q = q.where(GuardEvidence.kind == kind)
    rows = db.execute(q.order_by(GuardEvidence.seq.desc()).limit(limit)).scalars().all()
    return [as_dict(r) for r in rows]


def payloads(db: Session, customer_id: str, kind: str, limit: int = 1000) -> list[dict]:
    rows = db.execute(select(GuardEvidence.payload).where(GuardEvidence.customer_id == customer_id,
                                                          GuardEvidence.kind == kind)
                      .order_by(GuardEvidence.seq.desc()).limit(limit)).all()
    return [r[0] or {} for r in rows]


def export(db: Session, customer_id: str) -> dict:
    rows = db.execute(select(GuardEvidence).where(GuardEvidence.customer_id == customer_id)
                      .order_by(GuardEvidence.seq)).scalars().all()
    return {"customer_id": customer_id, "verification": verify(db, customer_id),
            "records": [as_dict(r, with_payload=True) for r in rows]}


def summary(db: Session, customer_id: str) -> dict:
    counts = dict(db.execute(select(GuardEvidence.kind, func.count()).where(GuardEvidence.customer_id == customer_id)
                             .group_by(GuardEvidence.kind)).all())
    verdicts: dict[str, int] = {}
    for (payload,) in db.execute(select(GuardEvidence.payload).where(
            GuardEvidence.customer_id == customer_id, GuardEvidence.kind == "guard_decision")).all():
        v = (payload or {}).get("decision", "?")
        verdicts[v] = verdicts.get(v, 0) + 1
    latest_eval = db.execute(select(GuardEvidence).where(
        GuardEvidence.customer_id == customer_id, GuardEvidence.kind == "evaluation")
        .order_by(GuardEvidence.seq.desc()).limit(1)).scalar_one_or_none()
    return {"counts": counts, "stored_decisions_by_verdict": verdicts, "verification": verify(db, customer_id),
            "latest_evaluation": latest_eval.payload.get("summary") if latest_eval else None}
