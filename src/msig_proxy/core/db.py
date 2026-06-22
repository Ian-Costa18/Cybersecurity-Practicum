"""Persistence seam: SQLAlchemy 2.0 over SQLite, used in the explicit style.

The database is a single logical Store (``docs/architecture.md``) and is *never*
mocked in tests (``docs/mvp.md``). DB work runs synchronously in a threadpool —
FastAPI executes sync ``def`` endpoints and dependencies in a worker thread, so
no request path holds a long-lived async connection (ADR 0011). Keeping the
engine/session construction behind these factories is the clean access seam for
the future Postgres swap.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Declarative base for all ORM models. Domain tables arrive in later phases."""


def create_db_engine(database_url: str) -> Engine:
    """Build a sync :class:`~sqlalchemy.Engine` for ``database_url``.

    SQLite needs ``check_same_thread=False`` because the threadpool hands a
    connection to whichever worker thread serves the request.
    """
    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(database_url, connect_args=connect_args, future=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build a :class:`~sqlalchemy.orm.sessionmaker` bound to ``engine``."""
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def session_scope(factory: sessionmaker[Session]) -> Generator[Session]:
    """Yield a session, committing on success and rolling back on error.

    Used as the body of the FastAPI request dependency; running it from a sync
    ``def`` dependency keeps the DB work on the threadpool.
    """
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
