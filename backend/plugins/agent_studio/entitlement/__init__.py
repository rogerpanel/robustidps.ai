"""Three-tier entitlement (Community / Pro / Enterprise) for the Agent
Studio commercial vertical.

Reads the tier off the authenticated user's record (or defaults to
Community when no auth is present), exposes a `requires(feature)`
decorator-like helper for FastAPI dependency injection, and surfaces
the catalog via /api/agent-studio/entitlement/tiers so the UI can show
upgrade CTAs alongside locked features.
"""
from plugins.agent_studio.entitlement.tiers import (
    TIERS, Tier, TierName,
    feature_unlocked, public_catalog, require_tier, tier_of,
)

__all__ = [
    "TIERS", "Tier", "TierName",
    "feature_unlocked", "public_catalog", "require_tier", "tier_of",
]
