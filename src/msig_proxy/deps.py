"""Shared FastAPI request dependencies.

These live outside :mod:`msig_proxy.app` so routers (e.g. the PyPI upload route)
can depend on them without importing the app factory — which would import the
routers back, a cycle. The app factory and every router both import from here.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from msig_proxy.config import AppConfig
from msig_proxy.db import session_scope


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
