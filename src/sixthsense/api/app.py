"""FastAPI application factory."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from sixthsense.api.routes import router
from sixthsense.config import get_settings
from sixthsense.db.session import init_db, session_scope
from sixthsense.services.rules import get_chain_settings

log = logging.getLogger("sixthsense")


def _find_ui_dist() -> Path | None:
    """Locate the built React app.

    The path differs between a source checkout and an installed package, and getting this
    wrong is invisible: the API keeps working and only the web app 404s. So the candidates
    are explicit and a miss is logged rather than skipped quietly.

    * ``SS_UI_DIST`` wins, for anyone mounting the assets somewhere else.
    * ``parents[3]`` is the repository root under the ``src`` layout, for development.
    * The working directory covers the container, where the package installs into
      ``site-packages`` and the assets are copied next to it at ``/app/ui/dist``.
    """
    override = os.environ.get("SS_UI_DIST")
    candidates = [
        Path(override) if override else None,
        Path(__file__).resolve().parents[3] / "ui" / "dist",
        Path.cwd() / "ui" / "dist",
    ]
    for candidate in candidates:
        if candidate is not None and (candidate / "index.html").is_file():
            return candidate
    return None


UI_DIST = _find_ui_dist()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    init_db()
    with session_scope() as session:
        chain_settings = get_chain_settings(session)

    # D-01: the active mode is announced at startup. A fail-closed proxy that nobody
    # realized was fail-closed is the failure this line exists to prevent.
    log.warning(
        "sixthsense control plane starting: default_action=%s shadow_mode=%s auth=%s bypass=%s",
        chain_settings.default_action,
        chain_settings.shadow_mode,
        settings.auth_mode,
        settings.dev_auth_bypass,
    )
    if settings.dev_auth_bypass:
        log.warning("DEV AUTH BYPASS IS ENABLED. Loopback only. Never in production.")
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="sixthsense control plane",
        version="0.1.0",
        description=(
            "Control plane for a CEF/syslog filtering proxy. The data plane is Vector; "
            "this service compiles rules, publishes bundles, and serves the UI."
        ),
        lifespan=lifespan,
    )

    app.include_router(router)

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    if UI_DIST is None:
        # Loud on purpose. A silent skip here is how the container shipped an API that
        # answered /api/health and 404'd the web app it exists to serve.
        log.warning(
            "no built UI found, serving the API only. Run 'npm run build' in ui/, or set "
            "SS_UI_DIST to the directory holding index.html."
        )
        return app

    ui_dist = UI_DIST.resolve()
    log.info("serving the web app from %s", ui_dist)
    app.mount("/assets", StaticFiles(directory=ui_dist / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> Response:
        # Confine the join to the asset directory before serving anything.
        #
        # Uvicorn does not normalize ".." in the request path, and it is right not to: the
        # raw path is the application's to interpret. So without this check the catch-all
        # serves any file the process can read. That is the database, with every password
        # hash in it, and .env, with the token signing key.
        #
        # `TestClient` will not catch a regression here. httpx normalizes the path before it
        # is sent, so the traversal never reaches the app. The test for this goes through a
        # real socket: see `test_the_spa_catch_all_cannot_escape_the_asset_directory`.
        candidate = (ui_dist / full_path).resolve()
        if full_path and candidate.is_relative_to(ui_dist) and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(ui_dist / "index.html")

    return app


app = create_app()
