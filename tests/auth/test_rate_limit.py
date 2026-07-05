"""Adversarial: the auth endpoints throttle per-IP bursts (IDENT-5, #123).

Black-box through the real HTTP surface (``docs/mvp.md`` posture): a
credential-stuffing burst from one source IP is rejected with ``429 +
Retry-After`` before it can grind the TOTP space or saturate bcrypt, while a
different IP — and the honest Deny path — stay unthrottled. Client IPs are
simulated via ``X-Forwarded-For`` behind a declared trusted proxy (the ASGI
test client's socket peer, ``127.0.0.1``), exactly the deployment shape the
limiter trusts XFF in.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from msig_proxy.accounts.seed import seed_user
from msig_proxy.app import create_app
from msig_proxy.core.config import AppConfig, AuthConfig, ServerConfig, ServiceConfig, Settings
from msig_proxy.core.db import Base, session_scope
from msig_proxy.core.models import DENIED, ApprovalRequest
from msig_proxy.service_types.one_time.intake import create_publish_request
from tests.support import totp_code

_USERNAME = "alice"
_PASSWORD = "pw-alice-123"

# Small threshold so a "burst" is cheap to drive; mirrors auth.rate_limit_* config.
_ATTEMPTS = 3
_BACKOFF_SECONDS = 120


@pytest.fixture
def app_config() -> AppConfig:
    """Override: a tight limiter window + the ASGI client declared a trusted proxy."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        auth=AuthConfig(
            rate_limit_attempts=_ATTEMPTS,
            rate_limit_window_seconds=60,
            rate_limit_backoff_seconds=_BACKOFF_SECONDS,
            rate_limit_trusted_proxies=["127.0.0.1"],
        ),
    )


@pytest.fixture
def seeded_user(app: FastAPI) -> str:
    """Seed the target user; return the plaintext TOTP secret."""
    secret = ""
    for session in session_scope(app.state.session_factory):
        secret = seed_user(
            session, username=_USERNAME, email="alice@example.com", password=_PASSWORD
        ).totp_secret
    return secret


def _from_ip(ip: str) -> dict[str, str]:
    """Simulate a distinct source IP via XFF (the socket peer is the trusted proxy)."""
    return {"X-Forwarded-For": ip}


async def _stuff_credentials(client: httpx.AsyncClient, ip: str, times: int) -> None:
    """Drive ``times`` bogus login attempts from ``ip``, all expected 401 (not yet 429)."""
    for _ in range(times):
        response = await client.post(
            "/login",
            data={"username": _USERNAME, "password": "wrong", "totp": "000000"},
            headers=_from_ip(ip),
        )
        assert response.status_code == 401  # under the threshold: plain auth failure


async def test_a_credential_stuffing_burst_against_login_is_rejected_with_429(
    client: httpx.AsyncClient, seeded_user: str
) -> None:
    # The stuffing burst: bogus credentials, one source IP, unlimited ambition.
    await _stuff_credentials(client, "203.0.113.9", _ATTEMPTS)

    over_limit = await client.post(
        "/login",
        data={"username": _USERNAME, "password": "wrong", "totp": "000000"},
        headers=_from_ip("203.0.113.9"),
    )
    assert over_limit.status_code == 429
    assert int(over_limit.headers["Retry-After"]) == _BACKOFF_SECONDS

    # The backoff holds: even the CORRECT credentials from the blocked IP are
    # refused — this is what defeats the online TOTP guessing rate (IDENT-5).
    still_blocked = await client.post(
        "/login",
        data={"username": _USERNAME, "password": _PASSWORD, "totp": totp_code(seeded_user)},
        headers=_from_ip("203.0.113.9"),
    )
    assert still_blocked.status_code == 429


async def test_a_burst_from_one_ip_does_not_throttle_another(
    client: httpx.AsyncClient, seeded_user: str
) -> None:
    # Attacker exhausts one IP's budget...
    await _stuff_credentials(client, "203.0.113.9", _ATTEMPTS)
    blocked = await client.post(
        "/login",
        data={"username": _USERNAME, "password": "wrong", "totp": "000000"},
        headers=_from_ip("203.0.113.9"),
    )
    assert blocked.status_code == 429

    # ...while the honest approver on a different network logs in untouched —
    # per-IP throttling, deliberately not a per-account lockout.
    login = await client.post(
        "/login",
        data={"username": _USERNAME, "password": _PASSWORD, "totp": totp_code(seeded_user)},
        headers=_from_ip("198.51.100.7"),
    )
    assert login.status_code == 200


async def test_api_token_guessing_at_the_upload_endpoint_is_throttled(
    client: httpx.AsyncClient, seeded_user: str
) -> None:
    # The third choke point: POST /pypi/legacy/ resolves Twine API tokens. Guessed
    # tokens draw on the same per-IP budget as the interactive endpoints.
    for guess in range(_ATTEMPTS):
        response = await client.post(
            "/pypi/legacy/",
            auth=("__token__", f"not-a-real-token-{guess}"),
            data={":action": "file_upload", "name": "foo", "version": "1.0.0"},
            files={"content": ("foo-1.0.0.tar.gz", b"bytes")},
            headers=_from_ip("203.0.113.9"),
        )
        assert response.status_code == 401

    over_limit = await client.post(
        "/pypi/legacy/",
        auth=("__token__", "not-a-real-token-final"),
        data={":action": "file_upload", "name": "foo", "version": "1.0.0"},
        files={"content": ("foo-1.0.0.tar.gz", b"bytes")},
        headers=_from_ip("203.0.113.9"),
    )
    assert over_limit.status_code == 429
    assert "Retry-After" in over_limit.headers


async def test_spoofed_forwarded_for_cannot_mint_fresh_ips_without_a_trusted_proxy(
    tmp_path: Path,
) -> None:
    # No declared reverse proxy → X-Forwarded-For is attacker-controlled noise and
    # must be ignored: every attempt lands on the socket IP's one budget, however
    # many forged client addresses the flood claims to come from.
    config = AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        auth=AuthConfig(
            rate_limit_attempts=_ATTEMPTS,
            rate_limit_window_seconds=60,
            rate_limit_backoff_seconds=_BACKOFF_SECONDS,
            rate_limit_trusted_proxies=[],  # direct exposure: trust no XFF
        ),
    )
    db_path = tmp_path / "direct.db"
    application = create_app(
        settings=Settings(database_url=f"sqlite+pysqlite:///{db_path.as_posix()}"),
        config=config,
    )
    Base.metadata.create_all(application.state.db_engine)
    try:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as direct:
            for attempt in range(_ATTEMPTS):
                response = await direct.post(
                    "/login",
                    data={"username": _USERNAME, "password": "wrong", "totp": "000000"},
                    headers=_from_ip(f"203.0.113.{attempt}"),  # a fresh forged IP each try
                )
                assert response.status_code == 401

            over_limit = await direct.post(
                "/login",
                data={"username": _USERNAME, "password": "wrong", "totp": "000000"},
                headers=_from_ip("203.0.113.250"),
            )
            assert over_limit.status_code == 429  # forged XFF bought nothing
    finally:
        application.state.db_engine.dispose()


@pytest.fixture
def pending_request_id(app: FastAPI, seeded_user: str) -> str:
    """One pending publish request with the seeded user among its approvers."""
    request_id = ""
    for session in session_scope(app.state.session_factory):
        requester = seed_user(
            session, username="publisher", email="publisher@example.com", password="pub-pw-123"
        ).user
        service = ServiceConfig(
            type="one-time",
            action="publish-to-pypi",
            quorum=2,
            approvers=[_USERNAME, "publisher"],
        )
        request = create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=service,
            package_name="foo",
            package_version="1.2.3",
            filename="foo-1.2.3.tar.gz",
            content=b"artifact bytes",
        )
        request_id = str(request.id)
    return request_id


async def test_vote_credential_burst_is_throttled_but_a_deny_never_is(
    client: httpx.AsyncClient, app: FastAPI, seeded_user: str, pending_request_id: str
) -> None:
    # Exhaust the IP's budget with bogus approve attempts against the vote route
    # (the shared verifier surface: same guard family as /login).
    for _ in range(_ATTEMPTS):
        response = await client.post(
            f"/approve/{pending_request_id}",
            data={
                "username": _USERNAME,
                "password": "wrong",
                "totp": "000000",
                "decision": "approve",
            },
            headers=_from_ip("203.0.113.9"),
        )
        assert response.status_code == 401

    over_limit = await client.post(
        f"/approve/{pending_request_id}",
        data={
            "username": _USERNAME,
            "password": "wrong",
            "totp": "000000",
            "decision": "approve",
        },
        headers=_from_ip("203.0.113.9"),
    )
    assert over_limit.status_code == 429  # approve attempts are throttled

    # The Deny path is NEVER throttled: the honest "2 a.m. deny" from the very same
    # over-budget IP still authenticates and lands — refusing it would trade
    # IDENT-5 for a denial-of-service on the one action that stops an attack.
    deny = await client.post(
        f"/approve/{pending_request_id}",
        data={
            "username": _USERNAME,
            "password": _PASSWORD,
            "totp": totp_code(seeded_user),
            "decision": "deny",
        },
        headers=_from_ip("203.0.113.9"),
    )
    assert deny.status_code == 200
    for session in session_scope(app.state.session_factory):
        request = session.get(ApprovalRequest, uuid.UUID(pending_request_id))
        assert request is not None
        assert request.state == DENIED  # the deny was recorded, not just tolerated


async def test_online_totp_guessing_with_a_known_password_is_throttled(
    client: httpx.AsyncClient, seeded_user: str
) -> None:
    # The L2 head: the attacker already holds the password and grinds the 6-digit
    # code space. The budget runs out long before ~10^6/3 expected guesses.
    for guess in range(_ATTEMPTS):
        response = await client.post(
            "/login",
            data={"username": _USERNAME, "password": _PASSWORD, "totp": f"{guess:06d}"},
            headers=_from_ip("203.0.113.9"),
        )
        assert response.status_code == 401

    over_limit = await client.post(
        "/login",
        data={"username": _USERNAME, "password": _PASSWORD, "totp": "000003"},
        headers=_from_ip("203.0.113.9"),
    )
    assert over_limit.status_code == 429
    assert "Retry-After" in over_limit.headers
