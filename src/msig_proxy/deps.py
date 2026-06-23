"""Shared FastAPI request providers (the cross-cutting DI seam).

These live outside :mod:`msig_proxy.app` so routers (e.g. the PyPI upload route)
can depend on them without importing the app factory — which would import the
routers back, a cycle. The app factory and every router both import from here.

Only the type-agnostic providers (the DB session, the config) live here. The
identity guards that build on them — ``current_session_user`` / ``require_session_user``
/ ``require_admin`` — belong to the auth slice and live in :mod:`msig_proxy.auth.guards`.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from msig_proxy.core.config import AppConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.events import EventBus


def get_session(request: Request) -> Iterator[Session]:
    """Request-scoped DB session dependency.

    Declared as a sync generator so FastAPI runs it (and any sync endpoint that
    depends on it) in the threadpool, matching the sync-DB posture in ADR 0011.
    """
    factory = request.app.state.session_factory
    yield from session_scope(factory)


def get_config(request: Request) -> AppConfig:
    """The validated application config wired onto the app at startup."""
    return request.app.state.config


def get_event_bus(request: Request) -> EventBus:
    """The application-owned lifecycle :class:`EventBus` wired onto the app at startup.

    Emit sites depend on this rather than a module global, so each app (prod or test)
    emits against its own bus (ADR 0005).
    """
    return request.app.state.event_bus
