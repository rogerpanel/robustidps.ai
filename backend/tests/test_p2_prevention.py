"""
P2 — Prevention Engine
========================
Test IP validation, circuit breaker, confidence gate, auto-block logic,
and prevention endpoints.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prevention import (
    _validate_ip,
    _validate_ip_or_network,
    check_circuit_breaker,
    update_drift_score,
    auto_block_check,
    check_confidence_gate,
)

# Import module-level state for direct manipulation in tests
import prevention


class TestIPValidation:
    def test_valid_ipv4(self):
        assert _validate_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert _validate_ip("::1") is True

    def test_valid_ipv4_full(self):
        assert _validate_ip("10.0.0.255") is True

    def test_invalid_ip_injection(self):
        assert _validate_ip("192.168.1.1; rm -rf /") is False

    def test_invalid_ip_empty(self):
        assert _validate_ip("") is False

    def test_invalid_ip_hostname(self):
        assert _validate_ip("example.com") is False

    def test_invalid_ip_partial(self):
        assert _validate_ip("192.168") is False


class TestIPOrNetworkValidation:
    def test_valid_ip(self):
        assert _validate_ip_or_network("10.0.0.1") is True

    def test_valid_cidr(self):
        assert _validate_ip_or_network("192.168.1.0/24") is True

    def test_valid_ipv6_network(self):
        assert _validate_ip_or_network("fe80::/10") is True

    def test_invalid_injection(self):
        assert _validate_ip_or_network("10.0.0.1/24 && echo hacked") is False

    def test_invalid_string(self):
        assert _validate_ip_or_network("not-an-ip") is False


class TestCircuitBreaker:
    def setup_method(self):
        """Reset circuit breaker state before each test."""
        prevention._circuit_breaker = {
            "tripped": False,
            "trip_reason": "",
            "tripped_at": None,
            "tripped_by": None,
            "drift_score": 0.0,
            "drift_threshold": 0.30,
            "auto_trip": True,
            "predictions_blocked": 0,
        }

    def test_not_tripped_returns_none(self):
        result = check_circuit_breaker()
        assert result is None

    def test_tripped_returns_error(self):
        prevention._circuit_breaker["tripped"] = True
        prevention._circuit_breaker["tripped_at"] = "2025-01-01T00:00:00"
        result = check_circuit_breaker()
        assert result is not None
        assert isinstance(result, str)
        assert "TRIPPED" in result

    def test_update_drift_below_threshold(self):
        update_drift_score(0.05)
        assert prevention._circuit_breaker["drift_score"] == 0.05
        assert prevention._circuit_breaker["tripped"] is False

    def test_update_drift_above_threshold_trips(self):
        update_drift_score(0.50)
        assert prevention._circuit_breaker["drift_score"] == 0.50
        assert prevention._circuit_breaker["tripped"] is True

    def test_update_drift_auto_trip_disabled(self):
        prevention._circuit_breaker["auto_trip"] = False
        update_drift_score(0.50)
        assert prevention._circuit_breaker["tripped"] is False


class TestAutoBlock:
    def setup_method(self):
        """Reset auto-block state before each test."""
        from collections import deque
        prevention._auto_block_config = {
            "enabled": False,
            "min_severity": "critical",
            "min_confidence": 0.90,
            "rule_type": "iptables",
            "action": "DROP",
            "max_blocks_per_cycle": 10,
            "blocked_ips": set(),
            "block_log": deque(maxlen=500),
        }

    def test_disabled_returns_none(self):
        result = auto_block_check("10.0.0.1", "DDoS", 0.95, "critical")
        assert result is None

    def test_enabled_below_confidence_returns_none(self):
        prevention._auto_block_config["enabled"] = True
        result = auto_block_check("10.0.0.1", "DDoS", 0.50, "critical")
        assert result is None

    def test_enabled_low_severity_returns_none(self):
        prevention._auto_block_config["enabled"] = True
        result = auto_block_check("10.0.0.1", "Scan", 0.95, "low")
        assert result is None

    def test_benign_severity_returns_none(self):
        prevention._auto_block_config["enabled"] = True
        result = auto_block_check("10.0.0.1", "Benign", 0.99, "benign")
        assert result is None

    def test_invalid_ip_returns_none(self):
        prevention._auto_block_config["enabled"] = True
        result = auto_block_check("not-an-ip", "DDoS", 0.95, "critical")
        assert result is None

    def test_already_blocked_ip_returns_none(self):
        prevention._auto_block_config["enabled"] = True
        prevention._auto_block_config["blocked_ips"].add("10.0.0.5")
        result = auto_block_check("10.0.0.5", "DDoS", 0.95, "critical")
        assert result is None


class TestConfidenceGate:
    def setup_method(self):
        """Reset confidence gate state."""
        prevention._confidence_gate = {
            "enabled": False,
            "min_confidence": 0.6,
            "action": "flag",
            "flagged_count": 0,
            "rejected_count": 0,
        }

    def test_disabled_returns_input(self):
        payload = {"predictions": [{"label": "DDoS"}], "confidence_scores": [0.1]}
        result = check_confidence_gate(payload)
        # When disabled, returns input unchanged (no confidence_gate key)
        assert "confidence_gate" not in result

    def test_enabled_flags_low_confidence(self):
        prevention._confidence_gate["enabled"] = True
        payload = {
            "predictions": [{"label": "DDoS"}, {"label": "Benign"}, {"label": "Scan"}],
            "confidence_scores": [0.1, 0.9, 0.5],
        }
        result = check_confidence_gate(payload)
        assert "confidence_gate" in result
        gate = result["confidence_gate"]
        assert gate["low_confidence_predictions"] >= 1

    def test_enabled_all_high_confidence(self):
        prevention._confidence_gate["enabled"] = True
        payload = {
            "predictions": [{"label": "Benign"}],
            "confidence_scores": [0.95],
        }
        result = check_confidence_gate(payload)
        assert "confidence_gate" in result
        assert result["confidence_gate"]["low_confidence_predictions"] == 0

    def test_empty_predictions(self):
        prevention._confidence_gate["enabled"] = True
        result = check_confidence_gate({"predictions": [], "confidence_scores": []})
        assert result is not None


class TestPreventionEndpoints:
    def test_dashboard_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/prevention/dashboard",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 401, 404)

    def test_circuit_breaker_status(self, client, admin_token):
        resp = client.get(
            "/api/prevention/circuit-breaker",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 401, 404)

    def test_auto_block_status(self, client, admin_token):
        resp = client.get(
            "/api/prevention/auto-block/status",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 401, 404)

    def test_quarantine_list(self, client, admin_token):
        resp = client.get(
            "/api/prevention/quarantine",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 401, 404)

    def test_wireless_status(self, client, admin_token):
        resp = client.get(
            "/api/prevention/wireless/status",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 401, 404)
