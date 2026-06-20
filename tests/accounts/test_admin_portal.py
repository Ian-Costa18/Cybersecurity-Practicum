"""The Admin Portal: user lifecycle + SMTP fallback link (issue #17).

Real DB, real crypto, real HTTP, real in-process SMTP. Exercises the admin-only
``/admin/*`` surface — list, deactivate (with session + login/vote revocation),
delete (key handling), reset, regenerate-link, token revoke — and the
recover-the-link-when-SMTP-is-down path.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import httpx
import pyotp
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy import intake, votes
from msig_proxy.accounts import keys
from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import events, models
from msig_proxy.core.config import (
    AppConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApiToken, User, UserKey
from msig_proxy.sessions import SESSION_COOKIE
from tests.support import SmtpProbe, current_totp, free_port

_ADMIN_PW = "admin-pw-12345"
_ALICE_PW = "alice-pw-12345"


@pytest.fixture(autouse=True)
def _isolate_event_subscribers() -> Iterator[None]:
    yield
    events.clear_subscribers()


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


@pytest.fixture
def seeded(app: FastAPI) -> None:
    for session in session_scope(app.state.session_factory):
        seed_user(
            session, username="root", email="root@example.com", password=_ADMIN_PW, is_admin=True
        )
        seed_user(session, username="alice", email="alice@example.com", password=_ALICE_PW)


async def _admin_auth(client: httpx.AsyncClient, app: FastAPI) -> dict[str, str]:
    login = await client.post(
        "/login",
        data={
            "username": "root",
            "password": _ADMIN_PW,
            "totp": current_totp(app.state.session_factory, "root"),
        },
        follow_redirects=False,
    )
    return {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}


def _user_id(app: FastAPI, username: str) -> str:
    for session in session_scope(app.state.session_factory):
        return str(session.scalars(select(User.id).where(User.username == username)).one())
    raise AssertionError  # pragma: no cover


# --- authorization ----------------------------------------------------------


async def test_admin_portal_requires_admin(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    assert (await client.get("/admin")).status_code == 401  # anonymous

    alice_login = await client.post(
        "/login",
        data={
            "username": "alice",
            "password": _ALICE_PW,
            "totp": current_totp(app.state.session_factory, "alice"),
        },
        follow_redirects=False,
    )
    alice_auth = {"Cookie": f"{SESSION_COOKIE}={alice_login.cookies[SESSION_COOKIE]}"}
    assert (await client.get("/admin", headers=alice_auth)).status_code == 403  # non-admin

    admin_auth = await _admin_auth(client, app)
    page = await client.get("/admin", headers=admin_auth)
    assert page.status_code == 200
    assert "alice" in page.text and "root" in page.text  # the user list


# --- deactivate -------------------------------------------------------------


async def test_deactivate_revokes_session_and_blocks_login(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    # Alice logs in and holds a live session.
    alice_login = await client.post(
        "/login",
        data={
            "username": "alice",
            "password": _ALICE_PW,
            "totp": current_totp(app.state.session_factory, "alice"),
        },
        follow_redirects=False,
    )
    alice_auth = {"Cookie": f"{SESSION_COOKIE}={alice_login.cookies[SESSION_COOKIE]}"}
    assert (await client.get("/me", headers=alice_auth)).status_code == 200

    admin_auth = await _admin_auth(client, app)
    resp = await client.post(
        f"/admin/users/{_user_id(app, 'alice')}/deactivate", headers=admin_auth
    )
    assert resp.status_code == 200
    assert resp.json()["sessions_revoked"] == 1

    # Her existing session is revoked immediately, and she cannot log in again.
    assert (await client.get("/me", headers=alice_auth)).status_code == 401
    relogin = await client.post(
        "/login",
        data={
            "username": "alice",
            "password": _ALICE_PW,
            "totp": current_totp(app.state.session_factory, "alice"),
        },
        follow_redirects=False,
    )
    assert relogin.cookies.get(SESSION_COOKIE) is None  # deactivated → login refused


def test_a_deactivated_approver_cannot_vote(app: FastAPI) -> None:
    # In-flight approval links stop authenticating once the approver is deactivated.
    for session in session_scope(app.state.session_factory):
        secret = seed_user(
            session, username="alice", email="alice@example.com", password=_ALICE_PW
        ).totp_secret
        requester = seed_user(
            session, username="pub", email="pub@example.com", password="pub-pw-12345"
        ).user
        svc = ServiceConfig(
            type="one-time", action="publish-to-pypi", quorum=1, approvers=["alice"]
        )
        request = intake.create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=svc,
            package_name="foo",
            package_version="1.0.0",
            filename="foo.tar.gz",
            content=b"bytes",
        )
        alice = session.scalars(select(User).where(User.username == "alice")).one()
        alice.is_active = False  # deactivated
        session.flush()

        with pytest.raises(votes.AuthenticationFailed):
            votes.cast_vote(
                session,
                request=request,
                approver=alice,
                password=_ALICE_PW,
                totp=pyotp.TOTP(secret).now(),
                totp_valid_window=1,
                decision=models.APPROVE,
            )


# --- delete / reset / regenerate -------------------------------------------


async def test_delete_drops_private_key_but_keeps_public_key(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    resp = await client.delete(f"/admin/users/{_user_id(app, 'alice')}", headers=admin_auth)
    assert resp.status_code == 200

    for session in session_scope(app.state.session_factory):
        alice = session.scalars(select(User).where(User.username == "alice")).one()
        assert alice.is_active is False
        assert keys.active_key(session, alice) is None  # no signable key remains
        key = session.scalars(select(UserKey).where(UserKey.user_id == alice.id)).one()
        assert key.revoked_at is not None  # retired, not destroyed
        assert key.encrypted_private_key is None and key.key_salt is None  # private half dropped
        assert key.public_key is not None  # retained for audit of past votes


async def test_reset_clears_credentials_and_issues_a_fresh_link(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    resp = await client.post(f"/admin/users/{_user_id(app, 'alice')}/reset", headers=admin_auth)
    assert resp.status_code == 200
    assert "/enroll/" in resp.json()["enrollment_url"]

    for session in session_scope(app.state.session_factory):
        alice = session.scalars(select(User).where(User.username == "alice")).one()
        assert alice.password_hash is None and alice.totp_secret is None
        assert alice.enrolled_at is None
        assert keys.active_key(session, alice) is None  # active key retired on reset
        key = session.scalars(select(UserKey).where(UserKey.user_id == alice.id)).one()
        assert key.revoked_at is not None and key.public_key is not None  # kept for audit


async def test_regenerate_link_lets_a_pending_user_enroll(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    created = await client.post(
        "/admin/users",
        data={"username": "newbie", "email": "newbie@example.com"},
        headers=admin_auth,
    )
    user_id = created.json()["user_id"]

    regen = await client.post(f"/admin/users/{user_id}/enrollment-link", headers=admin_auth)
    assert regen.status_code == 200
    token = regen.json()["enrollment_url"].rsplit("/", 1)[-1]

    # The regenerated link enrolls the account.
    done = await client.post(f"/enroll/{token}", data={"password": "newbie-pw-1234"})
    assert done.status_code == 200


# --- token revoke -----------------------------------------------------------


async def test_admin_revokes_a_users_api_token(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    for session in session_scope(app.state.session_factory):
        alice = session.scalars(select(User).where(User.username == "alice")).one()
        token = session.scalars(select(ApiToken).where(ApiToken.user_id == alice.id)).one()
        token_id, user_id = str(token.id), str(alice.id)

    resp = await client.delete(f"/admin/users/{user_id}/tokens/{token_id}", headers=admin_auth)
    assert resp.status_code == 200

    for session in session_scope(app.state.session_factory):
        token = session.get(ApiToken, uuid.UUID(token_id))
        assert token is not None and token.revoked_at is not None  # revoked, not deleted


async def test_token_revoke_is_admin_only(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    fake = "00000000-0000-0000-0000-000000000000"
    assert (await client.delete(f"/admin/users/{fake}/tokens/{fake}")).status_code == 401


# --- SMTP fallback ----------------------------------------------------------


async def test_link_is_recoverable_when_smtp_is_down(settings, app_config: AppConfig) -> None:
    # Point email at a dead port; creating a user still returns the link (the portal
    # fallback) and reports the failed delivery — onboarding is never stranded.
    from msig_proxy.app import create_app
    from msig_proxy.core.db import Base

    dead = app_config.model_copy(
        update={
            "notifications": NotificationsConfig(
                email=EmailConfig(
                    enabled=True,
                    smtp_host="127.0.0.1",
                    smtp_port=free_port(),
                    from_address="Proxy <proxy@example.com>",
                    tls=False,
                )
            )
        }
    )
    app = create_app(settings=settings, config=dead)
    Base.metadata.create_all(app.state.db_engine)
    for session in session_scope(app.state.session_factory):
        seed_user(
            session, username="root", email="root@example.com", password=_ADMIN_PW, is_admin=True
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        admin_auth = await _admin_auth(http, app)
        resp = await http.post(
            "/admin/users",
            data={"username": "newbie", "email": "newbie@example.com"},
            headers=admin_auth,
        )

    assert resp.status_code == 201
    body = resp.json()
    assert body["email_delivered"] is False  # SMTP was down
    assert "/enroll/" in body["enrollment_url"]  # ...but the link is recoverable
