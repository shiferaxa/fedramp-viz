"""HTTP API and static dashboard.

Security posture for self hosting:
  * binds to 127.0.0.1 unless you say otherwise (see cli.py)
  * optional bearer token: set FEDRAMP_VIZ_TOKEN and every /api route requires
    `Authorization: Bearer <token>`; the dashboard asks for it once per tab
  * strict Content-Security-Policy, no external scripts, fonts or styles
  * read only: the only mutating route is POST /api/rescan, which re-reads the
    configured inventory source; nothing is ever written to the cloud
  * assessment data lives in process memory only; nothing is persisted
"""

from __future__ import annotations

import hmac
import os
import threading
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .baselines import Catalog, load_catalog
from .engine import assess
from .models import ImpactLevel, Resource
from .providers import Provider
from .rules import all_rules

WEB_DIR = Path(__file__).parent / "web"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class State:
    """Inventory plus cached assessments, guarded by a lock for rescans."""

    def __init__(self, provider: Provider, catalog: Catalog | None = None):
        self.provider = provider
        self.catalog = catalog or load_catalog()
        self.lock = threading.Lock()
        self.resources: list[Resource] = []
        self.cache: dict[str, dict[str, Any]] = {}
        self.last_error: str | None = None

    def scan(self) -> None:
        with self.lock:
            try:
                self.resources = self.provider.resources()
                self.last_error = None
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"
                raise
            self.cache = {}

    def assessment(self, level: ImpactLevel) -> dict[str, Any]:
        with self.lock:
            if level.value not in self.cache:
                self.cache[level.value] = assess(self.resources, level, self.catalog).to_dict()
            return self.cache[level.value]


def _require_token(request: Request) -> None:
    expected = os.environ.get("FEDRAMP_VIZ_TOKEN")
    if not expected:
        return
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.strip(), expected):
        raise HTTPException(status_code=401, detail="bearer token required")


def create_app(provider: Provider, catalog: Catalog | None = None, scan_on_start: bool = True) -> FastAPI:
    state = State(provider, catalog)
    if scan_on_start:
        state.scan()

    app = FastAPI(title="fedramp-viz", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.assessment_state = state

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    auth = [Depends(_require_token)]

    @app.get("/api/meta", dependencies=auth)
    def meta():
        return {
            "version": __version__,
            "provider": state.provider.name,
            "source": getattr(state.provider, "path", None) and str(state.provider.path),
            "resources": len(state.resources),
            "rules": len(all_rules()),
            "catalog_source": state.catalog.source,
            "levels": [lvl.value for lvl in ImpactLevel],
            "auth_required": bool(os.environ.get("FEDRAMP_VIZ_TOKEN")),
            "last_error": state.last_error,
        }

    @app.get("/api/assessment", dependencies=auth)
    def assessment(level: str = Query("moderate")):
        try:
            lvl = ImpactLevel.parse(level)
        except ValueError:
            raise HTTPException(status_code=400, detail="level must be low, moderate or high")
        return state.assessment(lvl)

    @app.get("/api/levels", dependencies=auth)
    def levels():
        return {lvl.value: state.assessment(lvl)["summary"] for lvl in ImpactLevel}

    @app.get("/api/rules", dependencies=auth)
    def rules():
        return [r.to_dict() for r in all_rules()]

    @app.post("/api/rescan", dependencies=auth)
    def rescan():
        try:
            state.scan()
        except Exception as e:
            return JSONResponse(status_code=502, content={"detail": f"rescan failed: {type(e).__name__}: {e}"})
        return {"resources": len(state.resources)}

    @app.get("/")
    def index():
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    return app
