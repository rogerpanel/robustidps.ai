"""
P3 — SDK Client
=================
Test the SDK client class (unit tests, no live server).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))

from robustidps.client import Client, APIError


class TestClientInit:
    def test_default_base_url(self):
        c = Client()
        assert c.base_url == "http://localhost:8000"

    def test_custom_base_url(self):
        c = Client("https://example.com/")
        assert c.base_url == "https://example.com"  # trailing slash stripped

    def test_token_stored(self):
        c = Client(token="my-jwt-token")
        assert c._token == "my-jwt-token"

    def test_headers_without_token(self):
        c = Client()
        assert c._headers == {}

    def test_headers_with_token(self):
        c = Client(token="abc123")
        headers = c._headers
        assert headers["Authorization"] == "Bearer abc123"

    def test_context_manager(self):
        with Client() as c:
            assert c.base_url == "http://localhost:8000"


class TestAPIError:
    def test_error_format(self):
        err = APIError(404, "Not found")
        assert err.status == 404
        assert err.detail == "Not found"
        assert "404" in str(err)
        assert "Not found" in str(err)

    def test_error_is_exception(self):
        err = APIError(500, "Server error")
        assert isinstance(err, Exception)
