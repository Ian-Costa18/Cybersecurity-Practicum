"""Admin-gated activation: the IDENT-2 pending-confirmation gate (issue #128).

Real DB, real crypto, real HTTP, real in-process SMTP. Enrollment no longer
activates a seat: completing ``/enroll/{token}`` lands the account in
**pending-confirmation** (enrolled, keys set, ``is_active`` false), and only an
admin — after confirming out-of-band that the intended human enrolled — flips it
active via ``POST /admin/users/{id}/activate``. The adversarial oracle: an
attacker who intercepts an enrollment link and enrolls first holds a seat that
**cannot vote** until the admin's confirmation they will never get
(``docs/threat-model/IDENT-2-enrollment-link-interception.md``).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core import events
from msig_proxy.core.config import (
    AppConfig,
    AuthConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import User, Vote
from msig_proxy.service_types.one_time.intake import create_publish_request
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
        # Widened so a #135 step-up action presents a TOTP distinct from the login's (#73).
        auth=AuthConfig(totp_window=20),
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


async def _create_and_enroll(
    client: httpx.AsyncClient,
    auth: dict[str, str],
    username: str,
    email: str,
    password: str,
    step_up: Callable[[], dict[str, str]],
) -> str:
    """Admin creates the account (with #135 step-up); the link holder enrolls. Returns
    the user id."""
    created = await client.post(
        "/admin/users", data={"username": username, "email": email, **step_up()}, headers=auth
    )
    assert created.status_code == 201
    token = created.json()["enrollment_url"].rsplit("/", 1)[-1]
    done = await client.post(f"/enroll/{token}", data={"password": password})
    assert done.status_code == 200
    return created.json()["user_id"]


def _vote_count(app: FastAPI, request_id: str) -> int:
    for session in session_scope(app.state.session_factory):
        return len(
            session.scalars(
                select(Vote).where(Vote.approval_request_id == uuid.UUID(request_id))
            ).all()
        )
    return 0  # pragma: no cover


async def test_activation_requires_a_completed_enrollment(
    client: httpx.AsyncClient, app: FastAPI, admin_step_up: Callable[[], dict[str, str]]
) -> None:
    """Pre-activating an un-enrolled account is refused (409).

    If the admin could flip ``is_active`` before enrollment, the next person to
    open the enrollment link would complete straight into an active seat —
    silently bypassing the confirmation gate this endpoint exists to enforce.
    """
    await _seed_admin(app)
    auth = await _admin_session(client, app)

    created = await client.post(
        "/admin/users",
        data={"username": "newbie", "email": "newbie@example.com", **admin_step_up()},
        headers=auth,
    )
    user_id = created.json()["user_id"]

    premature = await client.post(
        f"/admin/users/{user_id}/activate", headers=auth, data=admin_step_up()
    )
    assert premature.status_code == 409

    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == "newbie")).one()
        assert user.is_active is False  # the gate held


async def test_reenrollment_after_reset_lands_in_pending_confirmation(
    client: httpx.AsyncClient, app: FastAPI, admin_step_up: Callable[[], dict[str, str]]
) -> None:
    """A credentials reset *is* a fresh enrollment — the gate applies to it too.

    The reset link rides the same interceptable channel as the original
    (IDENT-2), so re-enrollment must not inherit the seat's previously-active
    flag: it lands back in pending-confirmation, and only the admin's
    confirmation re-activates it. Observed black-box at login.
    """
    await _seed_admin(app)
    auth = await _admin_session(client, app)

    # An enrolled, activated, working seat...
    for session in session_scope(app.state.session_factory):
        seed_user(session, username="victor", email="victor@example.com", password="old-pw-12345")

    # ...is reset by the admin; whoever holds the fresh link re-enrolls.
    for session in session_scope(app.state.session_factory):
        victor_id = str(session.scalars(select(User).where(User.username == "victor")).one().id)
    reset = await client.post(f"/admin/users/{victor_id}/reset", headers=auth, data=admin_step_up())
    token = reset.json()["enrollment_url"].rsplit("/", 1)[-1]
    assert (
        await client.post(f"/enroll/{token}", data={"password": "new-pw-123456"})
    ).status_code == 200

    # The re-enrolled seat is pending-confirmation: valid credentials cannot log in.
    refused = await client.post(
        "/login",
        data={
            "username": "victor",
            "password": "new-pw-123456",
            "totp": current_totp(app.state.session_factory, "victor", "new-pw-123456"),
        },
        follow_redirects=False,
    )
    assert refused.cookies.get(SESSION_COOKIE) is None

    # Admin confirms with the human and re-activates; the same credentials work.
    assert (
        await client.post(f"/admin/users/{victor_id}/activate", headers=auth, data=admin_step_up())
    ).status_code == 200
    accepted = await client.post(
        "/login",
        data={
            "username": "victor",
            "password": "new-pw-123456",
            # A distinct still-valid step: the refused attempt burned nothing, but
            # a same-step repeat could race the single-use ledger (#73).
            "totp": current_totp_at(app.state.session_factory, "victor", 1, "new-pw-123456"),
        },
        follow_redirects=False,
    )
    assert accepted.cookies.get(SESSION_COOKIE)


async def test_enrollment_completion_notifies_the_enrolled_address(
    client: httpx.AsyncClient,
    app: FastAPI,
    smtp_server: SmtpProbe,
    event_bus: events.EventBus,
    admin_step_up: Callable[[], dict[str, str]],
) -> None:
    """Leg (b) of #128: completing enrollment notifies the approver's address.

    If an interceptor enrolled first, the real approver's inbox receives "an
    account was enrolled for you — if this wasn't you, contact your admin", so
    the silent takeover becomes a loud race. Driven black-box: the real HTTP
    enrollment flow, the real in-process SMTP server, plus the typed
    ``account.enrollment_completed`` event on the bus (ADR 0014).
    """
    await _seed_admin(app)
    auth = await _admin_session(client, app)

    recorded: list[events.Event] = []
    event_bus.subscribe(recorded.append)
    await _create_and_enroll(
        client, auth, "alice", "alice@example.com", "alice-pw-12345", admin_step_up
    )

    assert events.EnrollmentCompleted in [type(e) for e in recorded]

    # Creation sent the enrollment link (to alice) and the IDENT-1 admin-action alarm
    # (to the acting admin, #125); completion adds the notice last.
    notice = smtp_server.messages[-1]
    assert notice.rcpt_tos == ["alice@example.com"]
    content = envelope_as_message(notice).get_content()
    assert "enroll" in content.lower()
    assert "wasn't you" in content or "was not you" in content  # the tip-off line
    assert "/enroll/" not in content  # informational: carries no link, grants nothing


async def test_unactivated_seat_cannot_vote_until_admin_activates(
    client: httpx.AsyncClient, app: FastAPI, admin_step_up: Callable[[], dict[str, str]]
) -> None:
    """The IDENT-2 #128 oracle, black-box over the real HTTP surface.

    An enrolled-but-not-activated seat (the position an enrollment-link
    interceptor holds) submits a vote with *fully valid* credentials and is
    rejected — no Vote row, request untouched. Only after the admin activates
    the account (the out-of-band confirmation step) is the same vote accepted.
    """
    await _seed_admin(app)
    auth = await _admin_session(client, app)

    # The intercepted-link position: whoever opened the link first now holds
    # the seat's password, TOTP secret, and signing key...
    mallory_pw = "mallory-pw-1234"
    user_id = await _create_and_enroll(
        client, auth, "mallory", "approver@example.com", mallory_pw, admin_step_up
    )
    for session in session_scope(app.state.session_factory):
        seat = session.scalars(select(User).where(User.username == "mallory")).one()
        assert seat.enrolled_at is not None  # enrolled (keys + credentials set)...
        assert seat.is_active is False  # ...but pending-confirmation: not a live seat

    # ...and the seat sits in a live request's snapshotted approver set
    # (quorum 2, so the accepted vote later does not close the request).
    for session in session_scope(app.state.session_factory):
        seed_user(session, username="trusty", email="trusty@example.com", password="trusty-pw-123")
        requester = seed_user(
            session, username="publisher", email="publisher@example.com", password="pub-pw-123"
        ).user
        request = create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=ServiceConfig(
                type="one-time",
                action="publish-to-pypi",
                quorum=2,
                approvers=["mallory", "trusty"],
            ),
            package_name="foo",
            package_version="1.2.3",
            filename="foo-1.2.3.tar.gz",
            content=b"artifact bytes",
        )
        request_id = str(request.id)

    # The stolen seat votes with completely valid credentials — rejected.
    rejected = await client.post(
        f"/approve/{request_id}",
        data={
            "username": "mallory",
            "password": mallory_pw,
            "totp": current_totp(app.state.session_factory, "mallory", mallory_pw),
            "decision": "approve",
        },
    )
    assert rejected.status_code == 401  # indistinguishable auth failure
    assert _vote_count(app, request_id) == 0  # nothing recorded

    # The admin confirms out-of-band with the intended human and activates (step-up).
    activated = await client.post(
        f"/admin/users/{user_id}/activate", headers=auth, data=admin_step_up()
    )
    assert activated.status_code == 200
    assert activated.json()["is_active"] is True

    # The same credentials now cast a recorded vote (1 of 2 — still pending).
    accepted = await client.post(
        f"/approve/{request_id}",
        data={
            "username": "mallory",
            "password": mallory_pw,
            "totp": current_totp(app.state.session_factory, "mallory", mallory_pw),
            "decision": "approve",
        },
    )
    assert accepted.status_code == 200
    assert _vote_count(app, request_id) == 1
