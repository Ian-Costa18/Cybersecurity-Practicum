"""Adversarial: the one-time upload edge caps request creation per requester
(DOS-1 flooding legs — noise + retry amplification, #32).

Black-box tier (``docs/threat-model/CONTRIBUTING.md`` §bucket): the attack is
driven through the real ``POST /pypi/legacy/`` HTTP surface. One leaked requester
credential (L2) is the whole precondition; this proves that a *single
authenticated seat* can no longer flood the proxy with publish requests — once
the per-requester budget trips the burst is refused with ``429 + Retry-After``,
while a *different* requester creating requests at a normal rate is untouched
(the quota is per-requester, deliberately not global — one abusive seat must not
deny service to every honest publisher).

The per-requester creation cap reuses the shared ``core/rate_limit`` primitive
(#123) under its own ``request-creation`` scope, keyed by the authenticated
requester's identity rather than by IP — the flood rides one valid token, so the
token's owner, not its source address, is the thing to meter.

Real DB, real HTTP, real crypto (``docs/mvp.md`` posture).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.core.config import AppConfig, AuthConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest, User

# A small per-requester budget keeps the burst cheap to drive; the defense is the
# same at 3/window as at 30/window.
_REQUEST_LIMIT = 3
_BACKOFF_SECONDS = 120


@pytest.fixture
def app_config() -> AppConfig:
    """A one-time PyPI service with a tight per-requester request-creation cap and
    generous storage caps (so this test isolates the *flooding* leg, not #126's
    storage leg)."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        auth=AuthConfig(
            request_rate_limit_attempts=_REQUEST_LIMIT,
            request_rate_limit_window_seconds=60,
            request_rate_limit_backoff_seconds=_BACKOFF_SECONDS,
        ),
        services={
            "pypi": ServiceConfig(
                type="one-time",
                action="publish-to-pypi",
                quorum=2,
                approvers=["*"],  # every seeded user is eligible; voting isn't under test
                max_staged_artifacts=1000,
            )
        },
    )


@pytest.fixture
def tokens(app: FastAPI) -> dict[str, str]:
    """Seed two independent requesters; return each one's API-token plaintext."""
    result: dict[str, str] = {}
    for session in session_scope(app.state.session_factory):
        result["attacker"] = seed_user(
            session, username="attacker", email="attacker@example.com", password="pw-attacker-1"
        ).api_token
        result["victim"] = seed_user(
            session, username="victim", email="victim@example.com", password="pw-victim-12"
        ).api_token
    return result


def _twine_form(version: str) -> dict[str, str]:
    return {":action": "file_upload", "name": "foo", "version": version}


def _file_part() -> dict[str, tuple[str, bytes, str]]:
    return {"content": ("foo.tar.gz", b"a wheel's worth of bytes", "application/octet-stream")}


async def _upload(client: httpx.AsyncClient, token: str, version: str) -> httpx.Response:
    return await client.post(
        "/pypi/legacy/",
        data=_twine_form(version),
        files=_file_part(),
        auth=("__token__", token),
    )


def _request_count(app: FastAPI, username: str) -> int:
    """How many pending requests this requester managed to create."""
    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == username)).one()
        return (
            session.scalar(
                select(func.count())
                .select_from(ApprovalRequest)
                .where(ApprovalRequest.requester_id == user.id)
            )
            or 0
        )
    return 0  # pragma: no cover - session_scope always yields once


async def test_a_request_creation_flood_from_one_requester_is_throttled_while_a_low_rate_requester_is_unaffected(  # noqa: E501
    client: httpx.AsyncClient, app: FastAPI, tokens: dict[str, str]
) -> None:
    # The attacker's leaked token creates requests up to its per-requester budget.
    for n in range(_REQUEST_LIMIT):
        ok = await _upload(client, tokens["attacker"], version=f"1.0.{n}")
        assert ok.status_code == 200

    # The very next request from the same seat is refused before it is staged —
    # the flood is capped, with a Retry-After telling the client to back off.
    over_limit = await _upload(client, tokens["attacker"], version="1.0.99")
    assert over_limit.status_code == 429
    assert int(over_limit.headers["Retry-After"]) == _BACKOFF_SECONDS

    # The backoff holds: further attempts from the throttled seat stay refused.
    still_blocked = await _upload(client, tokens["attacker"], version="1.0.100")
    assert still_blocked.status_code == 429

    # Only the in-budget requests landed; the flood never grew the pending queue
    # past the cap.
    assert _request_count(app, "attacker") == _REQUEST_LIMIT

    # A different requester, publishing at a normal rate, is entirely unaffected —
    # the quota is per-requester, so one abusive seat cannot deny the honest one.
    honest = await _upload(client, tokens["victim"], version="2.0.0")
    assert honest.status_code == 200
    assert _request_count(app, "victim") == 1
