"""Calibrated deferral: decide which 'ask' verdicts a person really needs to see.

Every 'ask' goes to the approval queue. People approve most of them, and a
queue full of routine requests trains reviewers to click approve. This module
learns from the tenant's own decided approvals which requests are routine,
with a guarantee chosen by the tenant:

  Each 'ask' gets a transparent risk score (blast radius, unknown targets,
  tools the policy does not classify, denials earlier in the session). From
  past decided approvals (approved = 0, denied = 1), Learn then Test
  (Angelopoulos, Bates, Candes, Jordan and Lei, 2021) picks the threshold:
  thresholds are tested from the lowest score upwards, and each is accepted
  only if an exact binomial test shows that, among past requests at or
  below it, the share a person denied is below alpha (at significance
  delta); testing stops at the first threshold that fails.

  Guarantee: with probability at least 1 - delta, among future requests at
  or below the threshold (the ones auto-approved), the share a person would
  have denied is at most alpha, as long as future requests resemble the past
  ones (exchangeability). It is a statistical guarantee about the tenant's
  own reviewers, not about attacks: requests chosen by an adversary to sit
  just under the threshold are why the eligibility rules below exist.

Modes (per tenant, changed only by a signed-in person):
  off      nothing changes (default)
  shadow   every ask still goes to a person; the decision records whether it
           would have been auto-approved, to build evidence before switching
  auto     eligible asks under the threshold are allowed without a person

Never eligible, whatever the score: anything the rules deny, calls with
hidden characters, unsafe or unknown-effect predictions, information-flow
rules (an outbound send after untrusted and sensitive reads), tiers marked not
reversible, repeated or escalated sessions, and calls under an approval
that was explicitly requested by another rule (repaired calls included).
"""
from __future__ import annotations

import datetime
import math
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Float, Integer, String
from sqlalchemy.orm import Session

from database import Base
from plugins.agent_guard.contract import Decision
from plugins.agent_guard.policy import Policy

# Rules whose 'ask' must always reach a person.
NEVER_AUTO_RULES = {
    "hidden-characters-args", "hidden-characters-tool", "session-escalated", "repeat-of-denied-call",
    "predicted-unknown-target", "predicted-group-loss", "predicted-blast-radius", "predicted-session-blast-radius",
}


class DeferralSettings(BaseModel):
    mode: str = Field("off", pattern="^(off|shadow|auto)$")
    alpha: float = Field(0.05, gt=0, lt=0.5, description="Highest acceptable share of auto-approved calls a person would deny")
    delta: float = Field(0.1, gt=0, lt=0.5, description="Allowed probability that the guarantee fails (confidence 1 - delta)")
    min_samples: int = Field(50, ge=20, le=100_000, description="Decided approvals needed before calibrating")


class GuardSettings(Base):
    __tablename__ = "agent_guard_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(String(255), nullable=False, unique=True, index=True)
    deferral_mode = Column(String(16), nullable=False, default="off")
    alpha = Column(Float, nullable=False, default=0.05)
    delta = Column(Float, nullable=True, default=0.1)
    min_samples = Column(Integer, nullable=False, default=50)
    updated_by = Column(String(255), default="")
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)


def load_settings(db: Session, customer_id: str) -> DeferralSettings:
    row = db.query(GuardSettings).filter_by(customer_id=customer_id).one_or_none()
    if row is None:
        return DeferralSettings()
    return DeferralSettings(mode=row.deferral_mode, alpha=row.alpha, delta=row.delta or 0.1,
                            min_samples=row.min_samples)


def save_settings(db: Session, customer_id: str, s: DeferralSettings, actor: str) -> None:
    row = db.query(GuardSettings).filter_by(customer_id=customer_id).one_or_none()
    if row is None:
        row = GuardSettings(customer_id=customer_id)
        db.add(row)
    row.deferral_mode, row.alpha, row.delta, row.min_samples = s.mode, s.alpha, s.delta, s.min_samples
    row.updated_by, row.updated_at = actor[:255], datetime.datetime.utcnow()
    db.commit()


# ── score and eligibility ─────────────────────────────────────────────

def features(decision: Decision, policy: Policy, session_denials: int) -> dict[str, Any]:
    p = decision.prediction or {}
    return {
        "tier": decision.tier,
        "tier_known": decision.tier != policy.default_tier,
        "blast_radius": int(p.get("blast_radius") or 0),
        "unknown_targets": len(p.get("unknown") or []),
        "session_denials": session_denials,
        "predicted": bool(p),
    }


def risk_score(f: dict[str, Any]) -> float:
    """Higher means riskier. Deliberately simple so a reviewer can recompute it."""
    return round(math.log1p(f["blast_radius"]) + 2.0 * min(f["unknown_targets"], 3)
                 + (0.0 if f["tier_known"] else 1.5) + 0.5 * f["session_denials"], 4)


def eligible(decision: Decision, policy: Policy) -> tuple[bool, str]:
    if decision.decision != "ask":
        return False, "not an ask"
    if decision.hidden_characters:
        return False, "hidden characters"
    rules = {f.rule_id for f in decision.findings if f.verdict == "ask"}
    blocked = rules & NEVER_AUTO_RULES
    if blocked:
        return False, f"rule {sorted(blocked)[0]} always needs a person"
    if any(r.startswith("flow:") for r in rules):
        return False, "information-flow rules always need a person"
    if not any(r.startswith("tier:") for r in rules):
        return False, "asked by a rule other than the action tier"
    other = sorted(r for r in rules if not r.startswith("tier:"))
    if other:  # e.g. a scan over its size limits, an out-of-scope target, an exhausted budget
        return False, f"rule {other[0]} always needs a person"
    tier = policy.tiers.get(decision.tier)
    if tier is None or tier.reversible is not True:
        return False, "the action tier is not marked reversible"
    p = decision.prediction
    if p is not None and not p.get("safe", False):
        return False, "the predicted effect is not safe"
    return True, ""


# ── Learn then Test (fixed-sequence binomial tests) ──────────────────

def binom_cdf(k: int, n: int, p: float) -> float:
    """P(Binomial(n, p) <= k), computed in log space."""
    if k >= n:
        return 1.0
    if k < 0:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    terms = [math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
             for i in range(k + 1)]
    top = max(terms)
    return min(1.0, math.exp(top) * sum(math.exp(t - top) for t in terms))


def calibrate(scores: list[float], denied: list[bool], alpha: float, min_samples: int,
              delta: float = 0.1) -> dict[str, Any]:
    n = len(scores)
    base = {"n": n, "alpha": alpha, "delta": delta, "min_samples": min_samples,
            "denial_rate": round(sum(denied) / n, 4) if n else None, "method": "learn-then-test"}
    if n < min_samples:
        return {**base, "ready": False, "threshold": None, "auto_share": 0.0,
                "reason": f"{n} decided approvals; {min_samples} needed"}
    pairs = sorted(zip(scores, denied))
    # Smallest group in which zero denials could be significant: (1 - alpha)^m <= delta. Thresholds with
    # fewer requests under them cannot pass and are not tested; this depends on the scores only, never on
    # the outcomes, so the fixed-sequence test stays valid.
    m_star = math.ceil(math.log(delta) / math.log1p(-alpha))
    best, best_m, best_k = None, 0, 0
    m = k = 0
    i = 0
    while i < n:
        s = pairs[i][0]
        while i < n and pairs[i][0] == s:       # requests with the same score are approved together
            k += int(pairs[i][1])
            m += 1
            i += 1
        if m < m_star:
            continue
        # H0: the denial share among requests scoring <= s is at least alpha. Reject when few were denied.
        if binom_cdf(k, m, alpha) <= delta:
            best, best_m, best_k = s, m, k
        else:
            break                                # fixed sequence: stop at the first threshold not accepted
    base["min_group"] = m_star
    if best is None:
        return {**base, "ready": False, "threshold": None, "auto_share": 0.0,
                "reason": "not enough evidence yet that the lowest-risk requests are almost always approved"}
    return {**base, "ready": True, "threshold": best, "auto_share": round(best_m / n, 4),
            "historical_miss_rate": round(best_k / best_m, 4),
            "reason": f"auto-approving scores <= {best} covers {best_m} of {n} past requests, "
                      f"{best_k} of which a person denied"}


def calibration_data(db: Session, customer_id: str) -> tuple[list[float], list[bool]]:
    from plugins.agent_guard.db_models import GuardApproval
    rows = db.query(GuardApproval).filter(GuardApproval.customer_id == customer_id,
                                          GuardApproval.status.in_(("approved", "used", "denied"))).all()
    scores, denied = [], []
    for r in rows:
        score = (r.request or {}).get("risk_score")
        if score is None or (r.request or {}).get("deferral_eligible") is False:
            continue
        scores.append(float(score))
        denied.append(r.status == "denied")
    return scores, denied
