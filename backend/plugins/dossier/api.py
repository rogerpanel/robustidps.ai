"""FastAPI router for the assurance-dossier generator.

Mount point: /api/dossier/*. Endpoints:
  GET  /verticals               available verticals
  POST /generate                assemble a canonical dossier JSON

The /dossier React route renders the JSON in the existing Print theme;
hitting Cmd+P in that view yields a paper-ready PDF without any
server-side PDF dependency. For headless / CI-time PDF, run the same
route through Playwright or wkhtmltopdf.
"""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db

from plugins.dossier import assemble_dossier, list_verticals

router = APIRouter(prefix="/api/dossier", tags=["Assurance Dossier"])


class DossierRequest(BaseModel):
    vertical: Literal["uav", "agent_studio"]
    audience: Literal["operator", "auditor", "investor"] = "auditor"
    scan_report: Optional[dict] = Field(None, description="Required for agent_studio vertical; ignored for uav")


@router.get("/verticals")
async def verticals() -> dict:
    return {"verticals": list_verticals()}


def _runtime_safety(request: Request, db: Session) -> dict | None:
    """The caller's Agent Guard evidence, computed server-side, when the request carries an identity."""
    try:
        from plugins.agent_guard import evidence, registry
        from plugins.agent_guard.api import tenant
        from plugins.agent_studio.auth import require_api_key
        customer = require_api_key(request, db)
    except HTTPException:
        return None
    except Exception:  # noqa: BLE001 — the dossier never fails because of this section
        return None
    tid = tenant(customer)
    summary = evidence.summary(db, tid)
    pinned = [{"name": t["name"], "version": t["version"], "digest": t["digest"]}
              for t in registry.listing(db, tid) if t["pinned"]]
    return {**summary, "pinned_toolsets": pinned,
            "note": "Counts and the ledger head hash at generation time; the full chain is in "
                    "GET /api/agent-guard/evidence/export and can be re-verified independently."}


@router.post("/generate")
async def generate(req: DossierRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    return assemble_dossier(
        vertical=req.vertical,
        audience=req.audience,
        scan_report=req.scan_report,
        runtime_safety=_runtime_safety(request, db) if req.vertical == "agent_studio" else None,
    )
