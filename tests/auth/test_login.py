"""End-to-end: browser login issues a revocable Proxy Session; logout revokes it.

Real DB, real HTTP, real crypto. The session cookie is ``Secure``, so over the
test's http transport it is forwarded explicitly on the follow-up request.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ProxySession
from tests.support import totp_code

_USERNAME = "alice"
_PASSWORD = "pw-alice-123"


@pytest.fixture
def seeded_user(app: FastAPI) -> str:
    """Seed the login user and return its TOTP secret (the enforced second factor, #16)."""
    secret = ""
    # NB: let the loop complete so session_scope commits (an early ``return`` here
    # skips the post-yield commit and the user is rolled back, never persisted).
    for session in session_scope(app.state.session_factory):
        secret = seed_user(
            session, username=_USERNAME, email="alice@example.com", password=_PASSWORD
        ).totp_secret
    return secret


def _cookie_header(response: httpx.Response) -> dict[str, str]:
    """The Secure session cookie, forwarded explicitly (http transport drops it)."""
    return {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE]}"}


def _session_count(app: FastAPI) -> int:
    for session in session_scope(app.state.session_factory):
        return session.scalar(select(func.count()).select_from(ProxySession)) or 0
    return 0  # pragma: no cover


async def test_valid_login_issues_a_session_and_me_returns_the_user(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: str
) -> None:
    login = await client.post(
        "/login",
        data={"username": _USERNAME, "password": _PASSWORD, "totp": totp_code(seeded_user)},
    )

    assert login.status_code == 200
    assert login.cookies.get(SESSION_COOKIE)  # signed session_id cookie set
    assert _session_count(app) == 1  # a server-side record exists

    me = await client.get("/me", headers=_cookie_header(login))
    assert me.status_code == 200
    assert me.json()["username"] == _USERNAME


async def test_invalid_password_returns_401_and_creates_no_session(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: str
) -> None:
    response = await client.post("/login", data={"username": _USERNAME, "password": "wrong"})

    assert response.status_code == 401
    assert response.cookies.get(SESSION_COOKIE) is None
    assert _session_count(app) == 0


async def test_correct_password_without_valid_totp_is_rejected(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: str
) -> None:
    # Two factors, no fallback (#16): the right password but a wrong/missing TOTP fails.
    response = await client.post(
        "/login", data={"username": _USERNAME, "password": _PASSWORD, "totp": "000000"}
    )

    assert response.status_code == 401
    assert _session_count(app) == 0


async def test_unknown_user_returns_401(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: str
) -> None:
    response = await client.post("/login", data={"username": "nobody", "password": _PASSWORD})

    assert response.status_code == 401
    assert _session_count(app) == 0


async def test_me_without_a_session_is_401(client: httpx.AsyncClient, seeded_user: str) -> None:
    assert (await client.get("/me")).status_code == 401


async def test_logout_revokes_the_session_immediately(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: str
) -> None:
    login = await client.post(
        "/login",
        data={"username": _USERNAME, "password": _PASSWORD, "totp": totp_code(seeded_user)},
    )
    auth = _cookie_header(login)
    assert (await client.get("/me", headers=auth)).status_code == 200  # works before logout

    logout = await client.post("/logout", headers=auth)
    assert logout.status_code == 200
    assert _session_count(app) == 0  # the record is gone

    # The same cookie no longer authenticates — revocation is immediate.
    assert (await client.get("/me", headers=auth)).status_code == 401
