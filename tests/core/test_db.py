"""The persistence seam is real and round-trips."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from msig_proxy.core.db import create_db_engine, create_session_factory, session_scope


def test_engine_executes_a_query() -> None:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar_one() == 1
    finally:
        engine.dispose()


def test_session_scope_yields_a_working_session() -> None:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    factory = create_session_factory(engine)
    try:
        sessions = session_scope(factory)
        session = next(sessions)
        assert session.execute(text("SELECT 1")).scalar_one() == 1
        # Exhaust the generator so commit/close run.
        with pytest.raises(StopIteration):
            next(sessions)
    finally:
        engine.dispose()


def test_session_scope_rolls_back_on_error() -> None:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    factory = create_session_factory(engine)
    try:
        generator = session_scope(factory)
        next(generator)
        with pytest.raises(ValueError, match="boom"):
            generator.throw(ValueError("boom"))
    finally:
        engine.dispose()
