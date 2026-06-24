"""Shared FastAPI request providers (the cross-cutting DI seam).

These live outside :mod:`msig_proxy.app` so routers (e.g. the PyPI upload route)
can depend on them without importing the app factory — which would import the
routers back, a cycle. The app factory and every router both import from here.

Only the type-agnostic providers (the DB session, the config) live here. The
identity guards that build on them — ``current_session_user`` / ``require_session_user``
/ ``require_admin`` — belong to the auth slice and live in :mod:`msig_proxy.auth.guards`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.events import EventBus


async def get_session(request: Request) -> AsyncIterator[Session]:
    """Request-scoped DB session dependency that also binds the lifecycle event session.

    Declared ``async`` so the bind lands in the request's *task* context — the one
    :func:`run_in_threadpool` copies into the sync endpoint and everything it calls,
    including ``bus.emit``. A *sync* yield-dependency runs in its own throwaway
    threadpool context whose contextvar writes never reach the endpoint, so binding the
    event session there (or in ``core.db.session_scope``) would be silently invisible to
    emit. Binding once here is what lets every emit site drop its ``session=`` argument
    (#102). The DB work (open/commit/rollback/close) still runs on the threadpool, so
    the sync-DB posture of ADR 0011 is preserved.
    """
    factory = request.app.state.session_factory
    session: Session = await run_in_threadpool(factory)
    token = events.bind_active_session(session)
    try:
        yield session
        await run_in_threadpool(session.commit)
    except Exception:
        await run_in_threadpool(session.rollback)
        raise
    finally:
        events.reset_active_session(token)
        await run_in_threadpool(session.close)


def get_config(request: Request) -> AppConfig:
    """The validated application config wired onto the app at startup."""
    return request.app.state.config


def get_event_bus(request: Request) -> EventBus:
    """The application-owned lifecycle :class:`EventBus` wired onto the app at startup.

    Emit sites depend on this rather than a module global, so each app (prod or test)
    emits against its own bus (ADR 0005).
    """
    return request.app.state.event_bus
