"""``/healthz`` for the Kubernetes probes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sp_rtk_portal.context import portal_context

router = APIRouter()


@router.get("/healthz", include_in_schema=False)
async def healthz(request: Request) -> JSONResponse:
    if await portal_context(request).db.ping():
        return JSONResponse({"status": "ok"})
    return JSONResponse({"status": "database unreachable"}, status_code=503)
