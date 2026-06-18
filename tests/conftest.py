"""Shared test harness.

Posture (``docs/mvp.md``): real DB, real crypto, real HTTP, and a *real*
in-process SMTP server. The only mocked boundary is the outbound PyPI publish.
Every fixture here keeps that contract: the database is a throwaway temp SQLite
file (never mocked), ``smtp_server`` is a live ``aiosmtpd`` controller, and
``mock_pypi`` is the single ``respx`` seam standing in for ``upload.pypi.org``.

Plain helpers and constants live in ``tests/support.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
import respx
from aiosmtpd.controller import Controller
from fastapi import FastAPI

from msig_proxy.app import create_app
from msig_proxy.config import AppConfig, ServerConfig, Settings
from msig_proxy.db import Base
from tests.support import PYPI_UPLOAD_URL, CollectingHandler, SmtpProbe, free_port


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
def app(settings: Settings, app_config: AppConfig) -> FastAPI:
    """A wired FastAPI app over the temp DB, with the schema created."""
    application = create_app(settings=settings, config=app_config)
    Base.metadata.create_all(application.state.db_engine)
    return application


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
