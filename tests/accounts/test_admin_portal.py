"""The Admin Portal: user lifecycle + SMTP fallback link (issue #17).

Real DB, real crypto, real HTTP, real in-process SMTP. Exercises the admin-only
``/admin/*`` surface — list, deactivate (with session + login/vote revocation),
delete (key handling), reset, regenerate-link, token revoke — and the
recover-the-link-when-SMTP-is-down path.
"""

from __future__ import annotations

import uuid

import httpx
import pyotp
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.accounts import keys
from msig_proxy.accounts.seed import seed_user
from msig_proxy.approvals import votes
from msig_proxy.auth.sessions import SESSION_COOKIE
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
from msig_proxy.service_types.one_time import intake
from tests.support import SmtpProbe, current_totp, free_port

_ADMIN_PW = "admin-pw-12345"
_ALICE_PW = "alice-pw-12345"


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
            "totp": current_totp(app.state.session_factory, "root", _ADMIN_PW),
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
            "totp": current_totp(app.state.session_factory, "alice", _ALICE_PW),
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
            "totp": current_totp(app.state.session_factory, "alice", _ALICE_PW),
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
            "totp": current_totp(app.state.session_factory, "alice", _ALICE_PW),
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
        svc = ServiceConfig(type="one-time", action="publish-to-pypi", quorum=2, approvers=["*"])
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


# --- enrollment-link invalidation (IDENT-2 remediation) ----------------------
#
# At most one enrollment link is live per user: minting a fresh link voids its
# predecessors, and deactivate/delete void without replacement. An intercepted
# old link must not survive the admin's remediation.


async def _pending_user_with_link(
    client: httpx.AsyncClient, admin_auth: dict[str, str], username: str
) -> tuple[str, str]:
    created = await client.post(
        "/admin/users",
        data={"username": username, "email": f"{username}@example.com"},
        headers=admin_auth,
    )
    assert created.status_code == 201
    return created.json()["user_id"], created.json()["enrollment_url"].rsplit("/", 1)[-1]


async def test_regenerate_invalidates_the_previous_link(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    user_id, old_token = await _pending_user_with_link(client, admin_auth, "pat")

    regen = await client.post(f"/admin/users/{user_id}/enrollment-link", headers=admin_auth)
    new_token = regen.json()["enrollment_url"].rsplit("/", 1)[-1]

    # The intercepted old link is dead; only the fresh one enrolls.
    assert (
        await client.post(f"/enroll/{old_token}", data={"password": "pat-pw-123456"})
    ).status_code == 400
    assert (
        await client.post(f"/enroll/{new_token}", data={"password": "pat-pw-123456"})
    ).status_code == 200


async def test_reset_invalidates_outstanding_enrollment_links(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    user_id, old_token = await _pending_user_with_link(client, admin_auth, "quinn")

    reset = await client.post(f"/admin/users/{user_id}/reset", headers=admin_auth)
    new_token = reset.json()["enrollment_url"].rsplit("/", 1)[-1]

    assert (
        await client.post(f"/enroll/{old_token}", data={"password": "quinn-pw-12345"})
    ).status_code == 400
    assert (
        await client.post(f"/enroll/{new_token}", data={"password": "quinn-pw-12345"})
    ).status_code == 200


async def test_deactivate_invalidates_outstanding_enrollment_links(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    user_id, token = await _pending_user_with_link(client, admin_auth, "rex")

    assert (
        await client.post(f"/admin/users/{user_id}/deactivate", headers=admin_auth)
    ).status_code == 200

    # Without voiding, enrollment would set is_active=True — straight through the
    # deactivation. The link must die with the account's standing.
    assert (
        await client.post(f"/enroll/{token}", data={"password": "rex-pw-123456"})
    ).status_code == 400
    for session in session_scope(app.state.session_factory):
        rex = session.get(User, uuid.UUID(user_id))
        assert rex is not None and rex.is_active is False


async def test_delete_invalidates_outstanding_enrollment_links(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    admin_auth = await _admin_auth(client, app)
    user_id, token = await _pending_user_with_link(client, admin_auth, "sam")

    assert (await client.delete(f"/admin/users/{user_id}", headers=admin_auth)).status_code == 200

    # The row survives deletion (public key kept for audit), so a live link would
    # re-enroll and re-activate the "deleted" account. It must not.
    assert (
        await client.post(f"/enroll/{token}", data={"password": "sam-pw-123456"})
    ).status_code == 400
    for session in session_scope(app.state.session_factory):
        sam = session.get(User, uuid.UUID(user_id))
        assert sam is not None and sam.is_active is False


# --- groups / edit user -----------------------------------------------------


async def test_create_user_with_groups_and_edit_groups_and_email(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    # Create with an optional groups value (#79).
    admin_auth = await _admin_auth(client, app)
    created = await client.post(
        "/admin/users",
        data={"username": "gina", "email": "gina@example.com", "groups": "developers"},
        headers=admin_auth,
    )
    assert created.status_code == 201
    user_id = created.json()["user_id"]
    for session in session_scope(app.state.session_factory):
        gina = session.scalars(select(User).where(User.username == "gina")).one()
        assert gina.groups == "developers"

    # Edit groups + email without resetting credentials (PATCH).
    edited = await client.patch(
        f"/admin/users/{user_id}",
        data={"groups": "developers,release-managers", "email": "gina2@example.com"},
        headers=admin_auth,
    )
    assert edited.status_code == 200
    assert edited.json()["groups"] == "developers,release-managers"
    for session in session_scope(app.state.session_factory):
        gina = session.get(User, uuid.UUID(user_id))
        assert gina is not None
        assert gina.groups == "developers,release-managers"
        assert gina.email == "gina2@example.com"

    # An omitted field is left unchanged: editing only the email keeps groups intact.
    email_only = await client.patch(
        f"/admin/users/{user_id}", data={"email": "gina3@example.com"}, headers=admin_auth
    )
    assert email_only.status_code == 200
    for session in session_scope(app.state.session_factory):
        gina = session.get(User, uuid.UUID(user_id))
        assert gina is not None
        assert gina.email == "gina3@example.com"  # updated
        assert gina.groups == "developers,release-managers"  # untouched (omitted)


async def test_edit_user_requires_admin(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    user_id = _user_id(app, "alice")
    assert (
        await client.patch(f"/admin/users/{user_id}", data={"groups": "x"})
    ).status_code == 401  # anonymous


# --- account events (#80) ---------------------------------------------------


async def test_deactivate_emits_event_and_notifies_user(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: None,
    smtp_server: SmtpProbe,
    event_bus: events.EventBus,
) -> None:
    admin_auth = await _admin_auth(client, app)
    recorded: list[events.Event] = []
    event_bus.subscribe(recorded.append)

    resp = await client.post(
        f"/admin/users/{_user_id(app, 'alice')}/deactivate", headers=admin_auth
    )
    assert resp.status_code == 200
    assert any(isinstance(e, events.AccountDeactivated) for e in recorded)
    # the affected user is told
    assert any("alice@example.com" in m.rcpt_tos for m in smtp_server.messages)


async def test_delete_emits_event_and_notifies_user(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: None,
    smtp_server: SmtpProbe,
    event_bus: events.EventBus,
) -> None:
    admin_auth = await _admin_auth(client, app)
    recorded: list[events.Event] = []
    event_bus.subscribe(recorded.append)

    resp = await client.delete(f"/admin/users/{_user_id(app, 'alice')}", headers=admin_auth)
    assert resp.status_code == 200
    assert any(isinstance(e, events.AccountDeleted) for e in recorded)
    assert any("alice@example.com" in m.rcpt_tos for m in smtp_server.messages)


async def test_reset_emits_credentials_reset_not_enrollment_issued(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: None,
    smtp_server: SmtpProbe,
    event_bus: events.EventBus,
) -> None:
    admin_auth = await _admin_auth(client, app)
    recorded: list[events.Event] = []
    event_bus.subscribe(recorded.append)

    resp = await client.post(f"/admin/users/{_user_id(app, 'alice')}/reset", headers=admin_auth)
    assert resp.status_code == 200
    types = [type(e) for e in recorded]
    assert events.CredentialsReset in types  # a reset is its own distinct event...
    assert events.EnrollmentIssued not in types  # ...not a plain enrollment
    assert any("alice@example.com" in m.rcpt_tos for m in smtp_server.messages)


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


# --- approval-link portal fallback (#82) ------------------------------------


def _pending_request(app: FastAPI, *, requester: str, approvers: list[str]) -> str:
    request_id = ""
    for session in session_scope(app.state.session_factory):
        req_user = session.scalars(select(User).where(User.username == requester)).one()
        svc = ServiceConfig(
            type="one-time", action="publish-to-pypi", quorum=len(approvers), approvers=approvers
        )
        request = intake.create_publish_request(
            session,
            requester=req_user,
            service_name="pypi",
            service=svc,
            package_name="foo",
            package_version="1.0.0",
            filename="foo.tar.gz",
            content=b"artifact bytes",
        )
        request_id = str(request.id)
    return request_id


async def test_admin_portal_surfaces_pending_approval_links(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    # With fallback_to_portal on (the default in this suite's config), the admin can
    # recover a pending request's /approve link from the portal (#82).
    request_id = _pending_request(app, requester="alice", approvers=["root", "alice"])
    admin_auth = await _admin_auth(client, app)

    page = await client.get("/admin", headers=admin_auth)

    assert page.status_code == 200
    assert "Pending Approval Requests" in page.text
    assert f"/approve/{request_id}" in page.text


async def test_approval_links_hidden_when_fallback_disabled(
    settings, app_config: AppConfig
) -> None:
    # fallback_to_portal: false → the approval-link section does not render (#82).
    from msig_proxy.app import create_app
    from msig_proxy.core.db import Base

    no_fallback = app_config.model_copy(
        update={
            "notifications": NotificationsConfig(
                email=EmailConfig(
                    enabled=True,
                    smtp_host="127.0.0.1",
                    smtp_port=2525,
                    from_address="Proxy <proxy@example.com>",
                    tls=False,
                    fallback_to_portal=False,
                )
            )
        }
    )
    app = create_app(settings=settings, config=no_fallback)
    Base.metadata.create_all(app.state.db_engine)
    for session in session_scope(app.state.session_factory):
        seed_user(
            session, username="root", email="root@example.com", password=_ADMIN_PW, is_admin=True
        )
        seed_user(session, username="alice", email="alice@example.com", password=_ALICE_PW)
    request_id = _pending_request(app, requester="alice", approvers=["root", "alice"])

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        admin_auth = await _admin_auth(http, app)
        page = await http.get("/admin", headers=admin_auth)
    app.state.db_engine.dispose()  # close pooled connections (no GC ResourceWarning)

    assert page.status_code == 200
    assert "Pending Approval Requests" not in page.text
    assert f"/approve/{request_id}" not in page.text


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
    app.state.db_engine.dispose()  # close pooled connections (no GC ResourceWarning)

    assert resp.status_code == 201
    body = resp.json()
    assert body["email_delivered"] is False  # SMTP was down
    assert "/enroll/" in body["enrollment_url"]  # ...but the link is recoverable
