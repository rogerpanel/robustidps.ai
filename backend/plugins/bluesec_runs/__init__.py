"""BlueSec Runs: store and review traces written by the BlueSec agent (bluesec/).

The API is imported as `plugins.bluesec_runs.api` from main.py after the
limiter is defined. Importing this package registers the table with
`database.Base`, so `init_db()` creates it at boot.
"""
from plugins.bluesec_runs import db_models  # noqa: F401
