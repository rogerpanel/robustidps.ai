"""
P2 — Audit Logging
====================
Test audit trail utilities and action mapping.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit import _get_action, _get_client_ip, _ACTION_MAP


class TestActionMapping:
    def test_login_action(self):
        assert _get_action("POST", "/api/auth/login") == "LOGIN"

    def test_register_action(self):
        assert _get_action("POST", "/api/auth/register") == "REGISTER"

    def test_upload_action(self):
        assert _get_action("POST", "/api/upload") == "UPLOAD"

    def test_predict_action(self):
        assert _get_action("POST", "/api/predict") == "PREDICT"

    def test_unknown_action(self):
        assert _get_action("GET", "/api/nonexistent") is None

    def test_ablation_action(self):
        assert _get_action("POST", "/api/ablation") == "ABLATION"

    def test_action_map_not_empty(self):
        assert len(_ACTION_MAP) > 0


class TestClientIP:
    def test_forwarded_for(self):
        class MockRequest:
            headers = {"x-forwarded-for": "1.2.3.4, 5.6.7.8"}
            client = None
        assert _get_client_ip(MockRequest()) == "1.2.3.4"

    def test_real_ip(self):
        class MockRequest:
            headers = {"x-real-ip": "9.8.7.6"}
            client = None
        assert _get_client_ip(MockRequest()) == "9.8.7.6"

    def test_direct_client(self):
        class MockClient:
            host = "127.0.0.1"
        class MockRequest:
            headers = {}
            client = MockClient()
        assert _get_client_ip(MockRequest()) == "127.0.0.1"

    def test_no_client(self):
        class MockRequest:
            headers = {}
            client = None
        assert _get_client_ip(MockRequest()) == "unknown"
