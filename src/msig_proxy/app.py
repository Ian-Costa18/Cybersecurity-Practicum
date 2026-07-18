"""FastAPI application factory.

Run under Uvicorn with the factory entrypoint::

    uvicorn msig_proxy.app:create_app --factory

Building the app in a factory (rather than a module-level singleton) keeps
imports side-effect-free: nothing touches the database or requires configuration
until an app is explicitly constructed, which is what lets tests build isolated
apps over throwaway databases.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from msig_proxy import (
    __version__,
)
from msig_proxy.accounts import admin, enroll, portal
from msig_proxy.approvals import approve, pending
from msig_proxy.audit import subscriber as audit_subscriber
from msig_proxy.auth import login
from msig_proxy.core import crypto, models  # noqa: F401 - registers ORM on Base
from msig_proxy.core.config import AppConfig, Settings, load_config
from msig_proxy.core.db import create_db_engine, create_session_factory
from msig_proxy.core.events import EventBus
from msig_proxy.deps import get_session
from msig_proxy.notifications import subscriber
from msig_proxy.service_types.forward_auth import access, gate
from msig_proxy.service_types.one_time import upload


def create_app(settings: Settings | None = None, config: AppConfig | None = None) -> FastAPI:
    """Construct and wire the FastAPI application.

    ``settings`` and ``config`` can be injected (tests do this); otherwise they
    are loaded from the environment and the config file, validated at startup.
    """
    settings = settings or Settings()
    config = config or load_config(settings.config_file)

    app = FastAPI(title="Multi-Party Authorization Proxy", version=__version__)

    # Security headers on every response, set in-app rather than trusting a reverse proxy
    # the deployment may not have. Anti-framing (VOTE-3 UI-redress leg, #127): the approve
    # page is where a disguised click becomes a signed vote; forbidding the app from being
    # framed kills the clickjacking overlay that ambient-credential-free voting cannot.
    # nosniff (VOTE-5, #154): the artifact download serves requester-supplied bytes for
    # review as an octet-stream attachment; forbidding content-type sniffing stops a browser
    # from re-interpreting those bytes as active content it would render or run.
    @app.middleware("http")
    async def set_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    engine = create_db_engine(settings.database_url)
    app.state.settings = settings
    app.state.config = config
    app.state.db_engine = engine
    app.state.session_factory = create_session_factory(engine)

    # The lifecycle event seam is an app-owned instance (ADR 0005): emit sites reach it
    # via DI (deps.get_event_bus), and each app gets a fresh bus. Two consumers subscribe
    # to it (docs/architecture.md): Audit is the *critical* consumer (records every event;
    # registered first so the trail is written before best-effort work), Notifications the
    # *best-effort* one (turns events into email). The approval flow only emits.
    bus = EventBus()
    app.state.event_bus = bus
    # Audit rows are chained under a dedicated key HKDF-derived from server.secret_key
    # (#121), domain-separated from the session-cookie MAC that keys HMAC on the raw
    # secret. Derived once at wiring and threaded to the recorder.
    audit_subscriber.register(
        bus, app.state.session_factory, crypto.derive_audit_key(config.server.secret_key)
    )
    subscriber.register(bus, app.state.session_factory, config)

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness probe: proves the stack is wired and serving."""
        return {"status": "ok", "version": __version__}

    # Readiness is distinct from liveness: it proves the persistence seam actually
    # round-trips a query, not just that the process is up.
    @app.get("/health/db")
    def health_db(session: Session = Depends(get_session)) -> dict[str, str]:
        """Readiness probe: proves the persistence seam round-trips."""
        session.execute(text("SELECT 1"))
        return {"status": "ok", "database": "ok"}

    app.include_router(upload.router)
    app.include_router(approve.router)
    app.include_router(login.router)
    app.include_router(access.router)
    app.include_router(pending.router)
    app.include_router(gate.router)
    app.include_router(admin.router)
    app.include_router(enroll.router)
    app.include_router(portal.router)

    return app
