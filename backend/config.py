"""
Centralised configuration loaded from environment variables / .env file.
"""

import os
import secrets
import logging
from pathlib import Path

_cfg_logger = logging.getLogger("robustidps.config")

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass  # python-dotenv not installed — use env vars directly

# ── Environment ───────────────────────────────────────────────────────────
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# ── Database ──────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./robustidps.db")

# ── Authentication ────────────────────────────────────────────────────────
_DEFAULT_SECRET = "dev-only-change-in-production"
SECRET_KEY = os.getenv("SECRET_KEY", _DEFAULT_SECRET)
if SECRET_KEY == _DEFAULT_SECRET:
    if ENVIRONMENT == "production":
        raise RuntimeError(
            "SECRET_KEY must be set in production. Set the SECRET_KEY environment variable."
        )
    _cfg_logger.critical(
        "SECRET_KEY is using the default value! "
        "Set a strong SECRET_KEY environment variable in production. "
        "Generating a random ephemeral key for this session."
    )
    SECRET_KEY = secrets.token_urlsafe(64)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

# ── Security ──────────────────────────────────────────────────────────────
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS",
        "https://robustidps.ai,http://localhost:3000,http://localhost:5173",
    ).split(",")
]
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "100/minute")
RATE_LIMIT_HEAVY = os.getenv("RATE_LIMIT_HEAVY", "10/minute")
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "350"))
MAX_LIVE_CAPTURE_SIZE_MB = int(os.getenv("MAX_LIVE_CAPTURE_SIZE_MB", "500"))
ALLOWED_EXTENSIONS = {".csv", ".pcap", ".pcapng"}

# ── Application ───────────────────────────────────────────────────────────
DEVICE = os.getenv("DEVICE", "cpu")
MC_PASSES = int(os.getenv("MC_PASSES", "20"))
MAX_ROWS = int(os.getenv("MAX_ROWS", "20000"))
MAX_ROWS_ADVERSARIAL = int(os.getenv("MAX_ROWS_ADVERSARIAL", "5000"))
MAX_ROWS_REDTEAM = int(os.getenv("MAX_ROWS_REDTEAM", "5000"))

# ── Datasets ──────────────────────────────────────────────────────────────
DATASETS_DIR = Path(os.getenv("DATASETS_DIR", str(Path(__file__).parent / "datasets")))

# ── Default Admin (created on first startup if DB is empty) ───────────────
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@robustidps.ai")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD:
    _cfg_logger.warning(
        "ADMIN_PASSWORD not set — default admin will not be created. "
        "Set ADMIN_PASSWORD to a strong value (min 8 chars, mixed case, digit, special char)."
    )

# ── AI Copilot ───────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
