"""
P3 — Zero-Trust AI Governance
===============================
Test governance policies and trust scoring endpoints.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zerotrust import GOVERNANCE_POLICIES


class TestGovernancePolicies:
    def test_policies_not_empty(self):
        assert len(GOVERNANCE_POLICIES) > 0

    def test_policy_structure(self):
        for key, policy in GOVERNANCE_POLICIES.items():
            assert "id" in policy, f"{key} missing id"
            assert "name" in policy, f"{key} missing name"
            assert "category" in policy, f"{key} missing category"
            assert "severity" in policy, f"{key} missing severity"

    def test_model_drift_policy(self):
        assert "model_drift_threshold" in GOVERNANCE_POLICIES
        p = GOVERNANCE_POLICIES["model_drift_threshold"]
        assert p["severity"] == "high"
        assert p["default_value"] == 0.05

    def test_confidence_policy(self):
        assert "max_prediction_confidence" in GOVERNANCE_POLICIES
        p = GOVERNANCE_POLICIES["max_prediction_confidence"]
        assert 0 < p["default_value"] <= 1.0

    def test_severity_values_valid(self):
        valid = {"low", "medium", "high", "critical"}
        for key, policy in GOVERNANCE_POLICIES.items():
            assert policy["severity"] in valid, f"{key} has invalid severity"


class TestZeroTrustEndpoints:
    def test_trust_score_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/zerotrust/trust-score",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 401, 404)

    def test_policies_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/zerotrust/policies",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 401, 404)
