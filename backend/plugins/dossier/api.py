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

from fastapi import APIRouter
from pydantic import BaseModel, Field

from plugins.dossier import assemble_dossier, list_verticals

router = APIRouter(prefix="/api/dossier", tags=["Assurance Dossier"])


class DossierRequest(BaseModel):
    vertical: Literal["uav", "agent_studio"]
    audience: Literal["operator", "auditor", "investor"] = "auditor"
    scan_report: Optional[dict] = Field(None, description="Required for agent_studio vertical; ignored for uav")


@router.get("/verticals")
async def verticals() -> dict:
    return {"verticals": list_verticals()}


@router.post("/generate")
async def generate(req: DossierRequest) -> dict:
    return assemble_dossier(
        vertical=req.vertical,
        audience=req.audience,
        scan_report=req.scan_report,
    )
