"""
P2 — Firewall Rule Generation
===============================
Test rule generators for iptables, nftables, snort, suricata.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from firewall import (
    _iptables_rule, _nftables_rule, _snort_rule,
    SEVERITY_ORDER, GenerateRequest,
)


class TestIptablesRules:
    def test_drop_rule(self):
        rule = _iptables_rule("10.0.0.1", "DROP", "DDoS", 1001)
        assert "iptables" in rule
        assert "10.0.0.1" in rule
        assert "DROP" in rule
        assert "DDoS" in rule

    def test_reject_rule(self):
        rule = _iptables_rule("192.168.1.1", "REJECT", "Brute Force", 1002)
        assert "REJECT" in rule

    def test_log_rule(self):
        rule = _iptables_rule("172.16.0.1", "LOG", "Recon", 1003)
        assert "LOG" in rule
        assert "RIDPS" in rule


class TestNftablesRules:
    def test_drop_rule(self):
        rule = _nftables_rule("10.0.0.1", "DROP", "DDoS", 1001)
        assert "nft" in rule
        assert "drop" in rule
        assert "10.0.0.1" in rule

    def test_reject_rule(self):
        rule = _nftables_rule("10.0.0.1", "REJECT", "DDoS", 1001)
        assert "reject" in rule


class TestSnortRules:
    def test_drop_rule(self):
        rule = _snort_rule("10.0.0.1", "DROP", "DDoS", 1001)
        assert "drop" in rule or "alert" in rule
        assert "10.0.0.1" in rule

    def test_alert_rule(self):
        rule = _snort_rule("10.0.0.1", "LOG", "Recon", 1001)
        assert "alert" in rule


class TestSeverityOrder:
    def test_severity_ordering(self):
        assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"]
        assert SEVERITY_ORDER["high"] > SEVERITY_ORDER["medium"]
        assert SEVERITY_ORDER["medium"] > SEVERITY_ORDER["low"]
        assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["benign"]


class TestGenerateRequestSchema:
    def test_default_values(self):
        req = GenerateRequest(job_id="test123")
        assert req.rule_type == "iptables"
        assert req.min_confidence == 0.7
        assert req.action == "DROP"

    def test_custom_values(self):
        req = GenerateRequest(
            job_id="test123",
            rule_type="snort",
            min_confidence=0.9,
            min_severity="critical",
            action="REJECT",
        )
        assert req.rule_type == "snort"
        assert req.min_confidence == 0.9


class TestFirewallEndpoints:
    def test_generate_endpoint_requires_job(self, client, admin_token):
        resp = client.post(
            "/api/firewall/generate",
            json={"job_id": "nonexistent"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # Should fail with 404 for non-existent job or 400
        assert resp.status_code in (404, 400, 500)
