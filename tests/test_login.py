"""End-to-end: browser login issues a revocable Proxy Session; logout revokes it.

Real DB, real HTTP, real crypto. The session cookie is ``Secure``, so over the
test's http transport it is forwarded explicitly on the follow-up request.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from msig_proxy.db import session_scope
from msig_proxy.models import ProxySession
from msig_proxy.seed import seed_user
from msig_proxy.sessions import SESSION_COOKIE

_USERNAME = "alice"
_PASSWORD = "pw-alice-123"


@pytest.fixture
def seeded_user(app: FastAPI) -> None:
    for session in session_scope(app.state.session_factory):
        seed_user(session, username=_USERNAME, email="alice@example.com", password=_PASSWORD)


def _cookie_header(response: httpx.Response) -> dict[str, str]:
    """The Secure session cookie, forwarded explicitly (http transport drops it)."""
    return {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE]}"}


def _session_count(app: FastAPI) -> int:
    for session in session_scope(app.state.session_factory):
        return session.scalar(select(func.count()).select_from(ProxySession)) or 0
    return 0  # pragma: no cover


async def test_valid_login_issues_a_session_and_me_returns_the_user(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: None
) -> None:
    login = await client.post("/login", data={"username": _USERNAME, "password": _PASSWORD})

    assert login.status_code == 200
    assert login.cookies.get(SESSION_COOKIE)  # signed session_id cookie set
    assert _session_count(app) == 1  # a server-side record exists

    me = await client.get("/me", headers=_cookie_header(login))
    assert me.status_code == 200
    assert me.json()["username"] == _USERNAME


async def test_invalid_password_returns_401_and_creates_no_session(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: None
) -> None:
    response = await client.post("/login", data={"username": _USERNAME, "password": "wrong"})

    assert response.status_code == 401
    assert response.cookies.get(SESSION_COOKIE) is None
    assert _session_count(app) == 0


async def test_unknown_user_returns_401(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: None
) -> None:
    response = await client.post("/login", data={"username": "nobody", "password": _PASSWORD})

    assert response.status_code == 401
    assert _session_count(app) == 0


async def test_me_without_a_session_is_401(client: httpx.AsyncClient, seeded_user: None) -> None:
    assert (await client.get("/me")).status_code == 401


async def test_logout_revokes_the_session_immediately(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: None
) -> None:
    login = await client.post("/login", data={"username": _USERNAME, "password": _PASSWORD})
    auth = _cookie_header(login)
    assert (await client.get("/me", headers=auth)).status_code == 200  # works before logout

    logout = await client.post("/logout", headers=auth)
    assert logout.status_code == 200
    assert _session_count(app) == 0  # the record is gone

    # The same cookie no longer authenticates — revocation is immediate.
    assert (await client.get("/me", headers=auth)).status_code == 401
