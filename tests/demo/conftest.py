"""Harness for the demo's backing checks: the demo library on ``sys.path``, plus the
**live proxy** the demo flow drives.

Two things differ from the rest of the suite, and both follow from #158:

* ``demo/notebooks`` goes on ``sys.path`` so ``demo_lib``/``demo_flow`` import by module
  name — they are presentation scaffolding, not part of the ``msig_proxy`` package.
  Mirrors ``tests/tools/conftest.py``, which does the same for the ``tools/`` scripts.
* The app is served by **uvicorn on a real localhost socket** rather than an in-process
  Starlette ``TestClient``, because ``ProxyDriver.upload`` publishes with real ``twine``
  in a subprocess, which cannot post through an ASGI app object. The rest of the posture
  is unchanged (``docs/mvp.md``): real DB, real crypto, real in-process SMTP, and the
  outbound PyPI publish as the single mocked boundary.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
import uvicorn
from fastapi import FastAPI

from tests.support import PYPI_UPLOAD_URL, free_port

_DEMO_NOTEBOOKS = Path(__file__).resolve().parents[2] / "demo" / "notebooks"
if str(_DEMO_NOTEBOOKS) not in sys.path:
    sys.path.insert(0, str(_DEMO_NOTEBOOKS))

import demo_flow  # noqa: E402 - importable only once demo/notebooks is on sys.path

# How long to wait for the server thread to bind, and to wind down afterwards.
_SERVER_TIMEOUT_SECONDS = 10


@pytest.fixture
def live_proxy(provisioned: FastAPI) -> Iterator[str]:
    """Serve the provisioned app with uvicorn on an ephemeral port; yield its base URL.

    A background thread, not a subprocess, so the app keeps the test's own temp SQLite file
    and — crucially — stays inside the ``respx`` patch that stands in for ``upload.pypi.org``.
    Uvicorn skips its signal handlers off the main thread, so this needs no special casing.
    """
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(provisioned, host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + _SERVER_TIMEOUT_SECONDS
    while not server.started:  # pragma: no branch - the loop exits on the first poll or two
        if not thread.is_alive() or time.monotonic() > deadline:  # pragma: no cover
            raise RuntimeError(f"the demo proxy never bound 127.0.0.1:{port}")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=_SERVER_TIMEOUT_SECONDS)


@pytest.fixture
def driver(provisioned: FastAPI, live_proxy: str) -> Iterator[demo_flow.ProxyDriver]:
    """A :class:`demo_flow.ProxyDriver` pointed at the live proxy.

    ``follow_redirects`` matches what ``TestClient`` did and what a browser does; the
    session cookie is ``Secure``, so ``ProxyDriver.login`` reads it off the response and
    forwards it as an explicit header rather than relying on the client's cookie jar.
    """
    with httpx.Client(base_url=live_proxy, timeout=30, follow_redirects=True) as client:
        yield demo_flow.ProxyDriver(
            client=client, sessions=provisioned.state.session_factory, base_url=live_proxy
        )


@pytest.fixture
def mock_pypi() -> Iterator[respx.MockRouter]:
    """``tests/conftest.py``'s single mocked boundary, plus a hole for the live proxy.

    ``respx`` intercepts every ``httpx`` request in the process, including the driver's
    real calls to the uvicorn server on loopback. Those must reach the socket, so they are
    routed to ``pass_through``; the outbound publish to ``upload.pypi.org`` — fired by the
    Executor from inside the server thread, still under this patch — remains mocked and is
    the tests' assertion oracle.
    """
    with respx.mock(assert_all_called=False) as router:
        router.route(host="127.0.0.1").pass_through()
        router.post(PYPI_UPLOAD_URL, name="pypi_upload").mock(
            return_value=httpx.Response(200, text="OK")
        )
        yield router
