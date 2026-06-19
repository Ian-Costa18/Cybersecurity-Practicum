"""FastAPI application factory.

Run under Uvicorn with the factory entrypoint::

    uvicorn msig_proxy.app:create_app --factory

Building the app in a factory (rather than a module-level singleton) keeps
imports side-effect-free: nothing touches the database or requires configuration
until an app is explicitly constructed, which is what lets tests build isolated
apps over throwaway databases.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from msig_proxy import (  # noqa: F401 - models registers ORM on Base
    __version__,
    approve,
    gate,
    login,
    models,
    pending,
    pypi,
)
from msig_proxy.config import AppConfig, Settings, load_config
from msig_proxy.db import create_db_engine, create_session_factory
from msig_proxy.deps import get_session


def create_app(settings: Settings | None = None, config: AppConfig | None = None) -> FastAPI:
    """Construct and wire the FastAPI application.

    ``settings`` and ``config`` can be injected (tests do this); otherwise they
    are loaded from the environment and the config file, validated at startup.
    """
    settings = settings or Settings()
    config = config or load_config(settings.config_file)

    app = FastAPI(title="Multi-Signature Authentication Web Proxy", version=__version__)

    engine = create_db_engine(settings.database_url)
    app.state.settings = settings
    app.state.config = config
    app.state.db_engine = engine
    app.state.session_factory = create_session_factory(engine)

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness probe: proves the stack is wired and serving."""
        return {"status": "ok", "version": __version__}

    # The session dependency is wired and exercised by the test harness even
    # though no domain route consumes it yet (Phase 0 has no domain behavior).
    @app.get("/health/db")
    def health_db(session: Session = Depends(get_session)) -> dict[str, str]:
        """Readiness probe: proves the persistence seam round-trips."""
        session.execute(text("SELECT 1"))
        return {"status": "ok", "database": "ok"}

    app.include_router(pypi.router)
    app.include_router(approve.router)
    app.include_router(login.router)
    app.include_router(pending.router)
    app.include_router(gate.router)

    return app
