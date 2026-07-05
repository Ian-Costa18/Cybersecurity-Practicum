"""Admin-created user + enrollment link, keypair at enrollment (issue #15).

Real DB, real crypto, real HTTP, **real in-process SMTP**. Drives the full
provisioning flow: an admin creates a credential-less account, the proxy emails a
single-use expiring link, the enrollee follows it to set their password (the proxy
generates the keypair + TOTP at that moment), and the account can then authenticate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.accounts import keys
from msig_proxy.accounts.seed import seed_user
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core import crypto, events
from msig_proxy.core.config import (
    AppConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
)
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import EnrollmentToken, User
from tests.support import SmtpProbe, current_totp, current_totp_at, envelope_as_message

_ADMIN_PW = "admin-pw-12345"


@pytest.fixture
def app_config(smtp_server: SmtpProbe) -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        notifications=NotificationsConfig(
            email=EmailConfig(
                enabled=True,
                smtp_host=smtp_server.host,
                smtp_port=smtp_server.port,
                from_address="Proxy <proxy@example.com>",
                tls=False,
            )
        ),
    )


async def _seed_admin(app: FastAPI) -> None:
    for session in session_scope(app.state.session_factory):
        seed_user(
            session, username="root", email="root@example.com", password=_ADMIN_PW, is_admin=True
        )


async def _admin_session(client: httpx.AsyncClient, app: FastAPI) -> dict[str, str]:
    login = await client.post(
        "/login",
        data={
            "username": "root",
            "password": _ADMIN_PW,
            "totp": current_totp(app.state.session_factory, "root", _ADMIN_PW),
        },
        follow_redirects=False,
    )
    return {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}


async def _create_user(
    client: httpx.AsyncClient, auth: dict[str, str], username: str, email: str
) -> httpx.Response:
    return await client.post(
        "/admin/users", data={"username": username, "email": email}, headers=auth
    )


def _token_from_url(url: str) -> str:
    return url.rsplit("/", 1)[-1]


# --- admin create -----------------------------------------------------------


async def test_admin_create_user_emails_a_single_use_enrollment_link(
    client: httpx.AsyncClient, app: FastAPI, smtp_server: SmtpProbe, event_bus: events.EventBus
) -> None:
    await _seed_admin(app)
    auth = await _admin_session(client, app)

    recorded: list[events.Event] = []
    event_bus.subscribe(recorded.append)
    response = await _create_user(client, auth, "alice", "alice@example.com")

    assert response.status_code == 201
    body = response.json()
    assert "/enroll/" in body["enrollment_url"]
    assert [type(e) for e in recorded] == [events.EnrollmentIssued]

    # The link was emailed to the new user (account.enrollment_issued → affected User).
    # A second message is the IDENT-1 admin-action alarm to the acting admin (#125).
    to_alice = [m for m in smtp_server.messages if "alice@example.com" in m.rcpt_tos]
    assert len(to_alice) == 1
    assert body["enrollment_url"] in envelope_as_message(to_alice[0]).get_content()

    # The account exists but is credential-less and inactive until enrollment.
    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == "alice")).one()
        assert user.is_active is False
        assert user.password_hash is None and user.enrolled_at is None


async def test_non_admin_and_anonymous_cannot_create_users(
    client: httpx.AsyncClient, app: FastAPI
) -> None:
    for session in session_scope(app.state.session_factory):
        seed_user(session, username="bob", email="bob@example.com", password="bob-pw-12345")

    # Anonymous → 401.
    assert (await _create_user(client, {}, "x", "x@example.com")).status_code == 401

    # Authenticated non-admin → 403.
    login = await client.post(
        "/login",
        data={
            "username": "bob",
            "password": "bob-pw-12345",
            "totp": current_totp(app.state.session_factory, "bob", "bob-pw-12345"),
        },
        follow_redirects=False,
    )
    auth = {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}
    assert (await _create_user(client, auth, "x", "x@example.com")).status_code == 403


async def test_duplicate_username_is_a_conflict(client: httpx.AsyncClient, app: FastAPI) -> None:
    await _seed_admin(app)
    auth = await _admin_session(client, app)

    assert (await _create_user(client, auth, "alice", "alice@example.com")).status_code == 201
    dup = await _create_user(client, auth, "alice", "other@example.com")
    assert dup.status_code == 409


# --- enrollment -------------------------------------------------------------


async def test_enroll_sets_password_keypair_and_totp(
    client: httpx.AsyncClient, app: FastAPI
) -> None:
    await _seed_admin(app)
    auth = await _admin_session(client, app)
    created = await _create_user(client, auth, "alice", "alice@example.com")
    token = _token_from_url(created.json()["enrollment_url"])

    assert (await client.get(f"/enroll/{token}")).status_code == 200  # the set-password form

    done = await client.post(f"/enroll/{token}", data={"password": "alice-pw-12345"})
    assert done.status_code == 200

    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == "alice")).one()
        assert user.password_hash is not None  # bcrypt verifier set
        key = keys.active_key(session, user)  # keypair generated, normalized into user_keys (#53)
        assert key is not None
        assert key.public_key is not None and len(key.public_key) == 32
        assert key.encrypted_private_key is not None and key.key_salt is not None
        assert key.revoked_at is None  # active
        assert user.totp_secret is not None  # TOTP provisioned (not enforced — #16)
        # Enrolled but pending-confirmation (IDENT-2, #128): the seat stays
        # inactive until an admin activates it after out-of-band confirmation.
        assert user.enrolled_at is not None and user.is_active is False
        token_row = session.scalars(select(EnrollmentToken)).one()
        assert token_row.consumed_at is not None  # single-use: consumed


async def test_password_below_minimum_length_is_rejected_and_link_survives(
    client: httpx.AsyncClient, app: FastAPI
) -> None:
    # The documented security control (auth.password_min_length, default 12): a
    # too-short password is refused at enrollment, the account stays un-enrolled, and
    # the single-use link is *not* consumed so the user can retry (#75).
    await _seed_admin(app)
    auth = await _admin_session(client, app)
    created = await _create_user(client, auth, "grace", "grace@example.com")
    token = _token_from_url(created.json()["enrollment_url"])

    too_short = await client.post(f"/enroll/{token}", data={"password": "short"})
    assert too_short.status_code == 400

    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == "grace")).one()
        assert user.password_hash is None and user.enrolled_at is None  # not enrolled
        token_row = session.scalars(select(EnrollmentToken)).one()
        assert token_row.consumed_at is None  # link survives for a retry

    # A compliant password on the same link now succeeds.
    ok = await client.post(f"/enroll/{token}", data={"password": "grace-pw-12345"})
    assert ok.status_code == 200


async def test_expired_link_is_rejected(client: httpx.AsyncClient, app: FastAPI) -> None:
    plaintext = crypto.generate_enrollment_token()
    for session in session_scope(app.state.session_factory):
        user = seed_user(
            session, username="carol", email="carol@example.com", password="carol-pw-1234"
        ).user
        session.add(
            EnrollmentToken(
                user_id=user.id,
                token_hash=crypto.hash_enrollment_token(plaintext),
                expires_at=datetime.now(UTC) - timedelta(hours=1),  # already expired
            )
        )

    assert (await client.get(f"/enroll/{plaintext}")).status_code == 400
    assert (
        await client.post(f"/enroll/{plaintext}", data={"password": "x-pw-123456"})
    ).status_code == 400


async def test_used_link_cannot_be_replayed(client: httpx.AsyncClient, app: FastAPI) -> None:
    await _seed_admin(app)
    auth = await _admin_session(client, app)
    created = await _create_user(client, auth, "dave", "dave@example.com")
    token = _token_from_url(created.json()["enrollment_url"])

    assert (
        await client.post(f"/enroll/{token}", data={"password": "dave-pw-12345"})
    ).status_code == 200
    # Second use of the same link is refused (atomic single-use).
    replay = await client.post(f"/enroll/{token}", data={"password": "evil-pw-12345"})
    assert replay.status_code == 400


# --- end to end -------------------------------------------------------------


async def test_full_flow_create_capture_enroll_then_authenticate(
    client: httpx.AsyncClient, app: FastAPI, smtp_server: SmtpProbe
) -> None:
    await _seed_admin(app)
    auth = await _admin_session(client, app)

    # Admin creates the account; the enrollee finds the link in their inbox.
    await _create_user(client, auth, "erin", "erin@example.com")
    message = envelope_as_message(smtp_server.messages[-1]).get_content()
    enroll_url = next(line for line in message.splitlines() if "/enroll/" in line).strip()
    token = _token_from_url(enroll_url)

    # Enrollee sets their own password...
    assert (
        await client.post(f"/enroll/{token}", data={"password": "erin-pw-123456"})
    ).status_code == 200

    # ...but the seat is pending-confirmation (IDENT-2, #128): even valid
    # credentials cannot authenticate until an admin activates the account.
    pending = await client.post(
        "/login",
        data={
            "username": "erin",
            "password": "erin-pw-123456",
            "totp": current_totp(app.state.session_factory, "erin", "erin-pw-123456"),
        },
        follow_redirects=False,
    )
    assert pending.cookies.get(SESSION_COOKIE) is None

    # The admin confirms out-of-band that erin enrolled, and activates the seat.
    for session in session_scope(app.state.session_factory):
        erin_id = session.scalars(select(User).where(User.username == "erin")).one().id
    assert (await client.post(f"/admin/users/{erin_id}/activate", headers=auth)).status_code == 200

    login = await client.post(
        "/login",
        data={
            "username": "erin",
            "password": "erin-pw-123456",
            # A distinct still-valid TOTP step: the refused attempt burned nothing,
            # but a same-step repeat could race the single-use ledger (#73).
            "totp": current_totp_at(app.state.session_factory, "erin", 1, "erin-pw-123456"),
        },
        follow_redirects=False,
    )
    assert login.cookies.get(SESSION_COOKIE)  # a Proxy Session was issued

    # A still-unenrolled account cannot log in.
    await _create_user(client, auth, "frank", "frank@example.com")
    nope = await client.post(
        "/login", data={"username": "frank", "password": "anything-12345"}, follow_redirects=False
    )
    assert nope.cookies.get(SESSION_COOKIE) is None
