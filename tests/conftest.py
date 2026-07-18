"""Shared test harness.

Posture (``docs/mvp.md``): real DB, real crypto, real HTTP, and a *real*
in-process SMTP server. The only mocked boundary is the outbound PyPI publish.
Every fixture here keeps that contract: the database is a throwaway temp SQLite
file (never mocked), ``smtp_server`` is a live ``aiosmtpd`` controller, and
``mock_pypi`` is the single ``respx`` seam standing in for ``upload.pypi.org``.

Plain helpers and constants live in ``tests/support.py``.
"""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path

import httpx
import pytest
import respx
from aiosmtpd.controller import Controller
from fastapi import FastAPI

from msig_proxy.app import create_app
from msig_proxy.core.config import AppConfig, ServerConfig, Settings
from msig_proxy.core.db import Base
from msig_proxy.core.events import EventBus
from tests.support import PYPI_UPLOAD_URL, CollectingHandler, SmtpProbe, free_port, step_up_data

# The password every admin-portal test seeds ``root`` with; the step-up fixture
# re-proves it on a #135-gated action.
_ADMIN_PW = "admin-pw-12345"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Deploy settings pointed at a throwaway SQLite file under the test tmp dir."""
    db_path = tmp_path / "test.db"
    return Settings(database_url=f"sqlite+pysqlite:///{db_path.as_posix()}")


@pytest.fixture
def app_config() -> AppConfig:
    """A valid application config, constructed directly (no file needed)."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        )
    )


@pytest.fixture
def app(settings: Settings, app_config: AppConfig) -> Iterator[FastAPI]:
    """A wired FastAPI app over the temp DB, with the schema created.

    Disposes the engine on teardown so pooled SQLite connections are closed rather
    than reclaimed at GC (which raises ``ResourceWarning: unclosed database``)."""
    application = create_app(settings=settings, config=app_config)
    Base.metadata.create_all(application.state.db_engine)
    try:
        yield application
    finally:
        application.state.db_engine.dispose()


@pytest.fixture
def event_bus(app: FastAPI) -> EventBus:
    """The app's lifecycle event bus (ADR 0005). Subscribe a recorder here to observe
    events an HTTP-driven flow emits; it is fresh per test, so nothing leaks between
    cases and there is nothing to clear."""
    return app.state.event_bus


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Async HTTP client driving the app's real ASGI surface."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client


@pytest.fixture
def smtp_server() -> Iterator[SmtpProbe]:
    """A real in-process SMTP server (aiosmtpd) — the boundary that is NOT mocked."""
    handler = CollectingHandler()
    port = free_port()
    controller = Controller(handler, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        yield SmtpProbe(host="127.0.0.1", port=port, messages=handler.messages)
    finally:
        controller.stop()


@pytest.fixture
def admin_step_up(app: FastAPI) -> Callable[[], dict[str, str]]:
    """Fresh step-up credentials for the seeded ``root`` admin on a #135-gated action.

    Sensitive Admin Portal actions (create · edit · activate · reset · regenerate-link ·
    deactivate · delete) now require fresh password + single-use TOTP step-up
    re-authentication (VOTE-1). This returns a **zero-arg callable**; each call yields
    ``root``'s password plus a *distinct* TOTP (an incrementing 30s step) so several
    sensitive actions in one test window are not rejected as replays (#73). Requires a
    ``root`` admin seeded with :data:`_ADMIN_PW` and a config whose ``auth.totp_window``
    spans the number of calls (the admin test fixtures widen it)."""
    steps = itertools.count(1)

    def _creds() -> dict[str, str]:
        return step_up_data(app.state.session_factory, "root", _ADMIN_PW, offset=next(steps))

    return _creds


@pytest.fixture
def mock_pypi() -> Iterator[respx.MockRouter]:
    """The single mocked boundary: the PyPI legacy upload endpoint.

    Defaults to a 200; individual tests override the response and read
    ``router["pypi_upload"].calls`` as the assertion oracle.
    """
    with respx.mock(assert_all_called=False) as router:
        router.post(PYPI_UPLOAD_URL, name="pypi_upload").mock(
            return_value=httpx.Response(200, text="OK")
        )
        yield router
