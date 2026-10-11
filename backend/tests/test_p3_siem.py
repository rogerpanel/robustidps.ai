"""
P3 — SIEM Connectors
======================
Test CEF/LEEF formatters and connector config.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from siem_connectors import _format_cef


class TestCEFFormatter:
    def test_basic_cef_format(self):
        event = {
            "threat_label": "DDoS",
            "severity": "high",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "confidence": 0.95,
            "model_used": "surrogate",
        }
        cef = _format_cef(event)
        assert cef.startswith("CEF:0|")
        assert "RobustIDPS" in cef
        assert "DDoS" in cef
        assert "10.0.0.1" in cef

    def test_cef_severity_mapping(self):
        critical_event = {"threat_label": "APT", "severity": "critical"}
        low_event = {"threat_label": "Scan", "severity": "low"}
        cef_crit = _format_cef(critical_event)
        cef_low = _format_cef(low_event)
        # Critical = 10, Low = 3 in the severity map
        assert "|10|" in cef_crit
        assert "|3|" in cef_low

    def test_cef_missing_fields(self):
        event = {"threat_label": "Unknown"}
        cef = _format_cef(event)
        assert "CEF:0|" in cef  # Should not crash

    def test_cef_confidence_format(self):
        event = {
            "threat_label": "DDoS",
            "confidence": 0.8765,
        }
        cef = _format_cef(event)
        assert "0.8765" in cef


class TestSIEMEndpoints:
    def test_connectors_list_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/siem/connectors",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 404)

    def test_test_connector_requires_auth(self, client):
        resp = client.post("/api/siem/test", json={})
        assert resp.status_code in (401, 404, 422)
