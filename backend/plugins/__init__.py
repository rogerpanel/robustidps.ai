"""Optional plugins mounted into the RobustIDPS.ai FastAPI app.

Each plugin lives in its own subpackage and exposes a `router` symbol
that backend/main.py mounts via `app.include_router(...)`. The kernel
remains untouched (chapter 6 §6.7 plugin convention).
"""
