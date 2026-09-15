"""Tier catalog + entitlement helpers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

TierName = Literal["community", "pro", "enterprise"]


@dataclass(frozen=True)
class Tier:
    name: TierName
    display: str
    price_usd_per_month: int | None
    seats: int | str
    features: frozenset[str] = field(default_factory=frozenset)


# Single source of truth — features keyed by short identifiers, matched
# by feature_unlocked() in API handlers and surfaced in the React UI
# as locked/unlocked indicators.
TIERS: dict[TierName, Tier] = {
    "community": Tier(
        name="community", display="Community", price_usd_per_month=0, seats=1,
        features=frozenset([
            "scanner.public",
            "scanner.checks.basic",
            "dossier.preview",
            "uav.read",
        ]),
    ),
    "pro": Tier(
        name="pro", display="Pro", price_usd_per_month=399, seats=5,
        features=frozenset([
            "scanner.public",
            "scanner.checks.basic",
            "scanner.checks.extended",
            "scanner.batch",
            "scanner.api",
            "dossier.preview",
            "dossier.generate",
            "uav.read",
            "uav.attack_run",
            "aegis_kit.runtime",
            "support.email",
        ]),
    ),
    "enterprise": Tier(
        name="enterprise", display="Enterprise", price_usd_per_month=2499, seats="unlimited",
        features=frozenset([
            "scanner.public",
            "scanner.checks.basic",
            "scanner.checks.extended",
            "scanner.batch",
            "scanner.api",
            "scanner.sla.4h",
            "dossier.preview",
            "dossier.generate",
            "dossier.iso42001",
            "dossier.eu_ai_act",
            "uav.read",
            "uav.attack_run",
            "uav.phase_b",
            "aegis_kit.runtime",
            "aegis_kit.airgap",
            "support.slack",
            "support.dedicated_se",
            "sso.scim",
        ]),
    ),
}


def tier_of(user) -> TierName:
    """Resolve a user object to a tier name.

    The user model can attach a `subscription_tier` attribute (set by
    the Stripe webhook on subscription create/update). Defaults to
    Community when unauthenticated or unset.
    """
    if user is None:
        return "community"
    name = getattr(user, "subscription_tier", None) or "community"
    if name not in TIERS:
        return "community"
    return name  # type: ignore[return-value]


def feature_unlocked(user, feature: str) -> bool:
    return feature in TIERS[tier_of(user)].features


def require_tier(user, feature: str) -> None:
    """Raise an HTTP 402 (Payment Required) if the user's tier doesn't
    include the named feature. Use as a one-line guard at the top of
    a paid endpoint."""
    from fastapi import HTTPException
    if not feature_unlocked(user, feature):
        current = tier_of(user)
        # Find the cheapest tier that unlocks the feature
        upgrade = next(
            (t for t in ("pro", "enterprise") if feature in TIERS[t].features),
            None,
        )
        raise HTTPException(
            status_code=402,
            detail={
                "error": "tier_required",
                "feature": feature,
                "current_tier": current,
                "upgrade_to": upgrade,
                "message": f"This action requires the {upgrade or 'higher'} tier.",
            },
        )


def public_catalog() -> dict:
    """Serialisable tier catalog for the React portal."""
    return {
        "tiers": [
            {
                "name": t.name, "display": t.display,
                "price_usd_per_month": t.price_usd_per_month,
                "seats": t.seats,
                "features": sorted(t.features),
            }
            for t in TIERS.values()
        ]
    }
