"""Server-rendered pages (Jinja2) and their static files.

Pages extend ``base.html``. No inline scripts or styles: the CSP allows only
``'self'``. Behaviour lives in ``static/portal.js``; forms that change state
carry ``data-action="/path"`` and the script posts them as JSON.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import HTMLResponse

_HERE = Path(__file__).parent

templates = Jinja2Templates(directory=_HERE / "templates")


def utc(value: datetime, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """``{{ when | utc("%H:%M") }}``: a timestamp in UTC, whatever the
    database session's time zone."""
    return value.astimezone(UTC).strftime(fmt)


templates.env.filters["utc"] = utc


def static_files() -> StaticFiles:
    return StaticFiles(directory=_HERE / "static")


def render(
    request: Request, name: str, status_code: int = 200, **context: Any
) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context, status_code=status_code)
