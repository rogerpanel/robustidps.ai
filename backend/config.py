"""
Centralised configuration loaded from environment variables / .env file.
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass  # python-dotenv not installed — use env vars directly

# ── Database ──────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./robustidps.db")

# ── Authentication ────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-in-production")
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
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "100"))
ALLOWED_EXTENSIONS = {".csv", ".pcap", ".pcapng"}

# ── Application ───────────────────────────────────────────────────────────
DEVICE = os.getenv("DEVICE", "cpu")
MC_PASSES = int(os.getenv("MC_PASSES", "20"))
MAX_ROWS = int(os.getenv("MAX_ROWS", "10000"))

# ── Default Admin (created on first startup if DB is empty) ───────────────
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@robustidps.ai")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "robustidps2024")
