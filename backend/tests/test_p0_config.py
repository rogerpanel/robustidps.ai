"""
P0 — Configuration & Environment
=================================
Critical: ensure config loads correctly and has sane defaults.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config


class TestConfigDefaults:
    """Verify default configuration values are set correctly."""

    def test_database_url_default(self):
        assert config.DATABASE_URL is not None
        assert len(config.DATABASE_URL) > 0

    def test_secret_key_exists(self):
        assert config.SECRET_KEY is not None
        assert len(config.SECRET_KEY) > 0

    def test_jwt_algorithm(self):
        assert config.JWT_ALGORITHM == "HS256"

    def test_access_token_expire_minutes_positive(self):
        assert config.ACCESS_TOKEN_EXPIRE_MINUTES > 0

    def test_cors_origins_is_list(self):
        assert isinstance(config.CORS_ORIGINS, list)
        assert len(config.CORS_ORIGINS) > 0

    def test_rate_limit_default_format(self):
        # Should be like "100/minute"
        assert "/" in config.RATE_LIMIT_DEFAULT

    def test_rate_limit_heavy_format(self):
        assert "/" in config.RATE_LIMIT_HEAVY

    def test_max_upload_size_positive(self):
        assert config.MAX_UPLOAD_SIZE_MB > 0

    def test_allowed_extensions(self):
        assert ".csv" in config.ALLOWED_EXTENSIONS
        assert ".pcap" in config.ALLOWED_EXTENSIONS

    def test_device_valid(self):
        assert config.DEVICE in ("cpu", "cuda", "mps")

    def test_mc_passes_positive(self):
        assert config.MC_PASSES > 0

    def test_max_rows_positive(self):
        assert config.MAX_ROWS > 0

    def test_datasets_dir_is_path(self):
        assert isinstance(config.DATASETS_DIR, Path)

    def test_admin_email_set(self):
        assert config.ADMIN_EMAIL is not None
        assert "@" in config.ADMIN_EMAIL
