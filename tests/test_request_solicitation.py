"""Automated approver solicitation on ``request.created`` (issue #13).

Real DB, real crypto, real HTTP, **real in-process SMTP**. Every snapshot Approver
is emailed the Approval Link the moment a request is created — for **both** service
types (forward-auth login and one-time PyPI upload) — and delivery is best-effort:
an SMTP failure never blocks the lifecycle.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core import events
from msig_proxy.core.config import (
    AppConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest
from tests.support import SmtpProbe, envelope_as_message, free_port, totp_code, totp_code_at

# TOTP secrets captured at seed time so /login satisfies the second factor (#16).
_SECRETS: dict[str, str] = {}

ARTIFACT = b"the exact uploaded artifact bytes"
_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "carol", "dave")}
_EMAIL = {name: f"{name}@example.com" for name in ("alice", "bob", "carol", "dave", "publisher")}

_FORWARD_AUTH = ServiceConfig(
    type="forward-auth", quorum=2, approvers=["alice", "bob"], endpoint="http://internal-app:8080"
)
_ONE_TIME = ServiceConfig(
    type="one-time", action="publish-to-pypi", quorum=2, approvers=["alice", "bob", "carol"]
)


def _email_config(
    smtp_server: SmtpProbe, *, host: str | None = None, port: int | None = None
) -> EmailConfig:
    return EmailConfig(
        enabled=True,
        smtp_host=host or smtp_server.host,
        smtp_port=port if port is not None else smtp_server.port,
        from_address="Proxy <proxy@example.com>",
        tls=False,
    )


@pytest.fixture
def app_config(smtp_server: SmtpProbe) -> AppConfig:
    """Forward-auth + one-time services, with email pointed at the live SMTP probe."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        notifications=NotificationsConfig(email=_email_config(smtp_server)),
        services={"internal-app": _FORWARD_AUTH, "pypi": _ONE_TIME},
    )


@pytest.fixture
def seeded(app: FastAPI) -> str:
    """Seed approvers + a requester; return the requester's API token."""
    token = ""
    for session in session_scope(app.state.session_factory):
        for name in ("alice", "bob", "carol", "dave"):
            _SECRETS[name] = seed_user(
                session, username=name, email=_EMAIL[name], password=_PASSWORD[name]
            ).totp_secret
        token = seed_user(
            session, username="publisher", email=_EMAIL["publisher"], password="pub-pw-123"
        ).api_token
    return token


def _recipients(smtp_server: SmtpProbe) -> set[str]:
    return {addr for envelope in smtp_server.messages for addr in envelope.rcpt_tos}


def _bodies(smtp_server: SmtpProbe) -> list[str]:
    return [envelope_as_message(e).get_content() for e in smtp_server.messages]


def _twine_form(name: str = "foo", version: str = "1.2.3") -> dict[str, str]:
    return {
        ":action": "file_upload",
        "protocol_version": "1",
        "metadata_version": "2.1",
        "name": name,
        "version": version,
        "filetype": "sdist",
    }


def _request_count(app: FastAPI) -> int:
    for session in session_scope(app.state.session_factory):
        return session.scalar(select(func.count()).select_from(ApprovalRequest)) or 0
    return 0  # pragma: no cover


# --- forward-auth path ------------------------------------------------------


async def test_forward_auth_request_emails_every_snapshot_approver(
    client: httpx.AsyncClient, seeded: str, smtp_server: SmtpProbe
) -> None:
    # Login authenticates and redirects to the guarded /access; request creation +
    # request.created (and thus approver solicitation) happen there (the de-smudge).
    login = await client.post(
        "/login",
        data={
            "username": "dave",
            "password": _PASSWORD["dave"],
            "totp": totp_code(_SECRETS["dave"]),
            "service": "internal-app",
        },
        follow_redirects=False,
    )
    assert login.status_code == 303
    assert login.headers["location"] == "/access?service=internal-app"
    assert not smtp_server.messages  # nothing solicited at login

    cookie = {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}
    access = await client.get(
        "/access?service=internal-app", headers=cookie, follow_redirects=False
    )
    assert access.status_code == 303
    request_id = access.headers["location"].rsplit("/", 1)[-1]

    # One message per eligible approver (the snapshot set), carrying the Approval Link.
    assert len(smtp_server.messages) == 2
    assert _recipients(smtp_server) == {_EMAIL["alice"], _EMAIL["bob"]}
    assert all(f"http://testserver/approve/{request_id}" in body for body in _bodies(smtp_server))


async def test_resuming_a_pending_request_does_not_re_notify(
    client: httpx.AsyncClient, seeded: str, smtp_server: SmtpProbe
) -> None:
    for attempt in range(2):
        # dave logs in twice; single-use TOTP (#73) burns each accepted step, so the
        # second login uses a distinct still-valid code (offset +1) rather than a replay.
        login = await client.post(
            "/login",
            data={
                "username": "dave",
                "password": _PASSWORD["dave"],
                "totp": totp_code_at(_SECRETS["dave"], attempt),
                "service": "internal-app",
            },
            follow_redirects=False,
        )
        cookie = {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}
        await client.get("/access?service=internal-app", headers=cookie, follow_redirects=False)

    # The second pass resumes the same pending request — approvers are solicited once.
    assert len(smtp_server.messages) == 2


# --- one-time (PyPI) path: the gotcha — it must emit request.created too -----


async def test_one_time_upload_emits_request_created_and_emails_approvers(
    client: httpx.AsyncClient, seeded: str, smtp_server: SmtpProbe, event_bus: events.EventBus
) -> None:
    recorded: list[events.Event] = []
    event_bus.subscribe(recorded.append)

    response = await client.post(
        "/pypi/legacy/",
        data=_twine_form(),
        files={"content": ("foo-1.2.3.tar.gz", ARTIFACT, "application/octet-stream")},
        auth=("__token__", seeded),
    )

    assert response.status_code == 200
    assert [type(e) for e in recorded] == [events.RequestCreated]  # one-time now emits it
    assert _recipients(smtp_server) == {_EMAIL["alice"], _EMAIL["bob"], _EMAIL["carol"]}
    assert all("foo 1.2.3" in body for body in _bodies(smtp_server))  # summary names the package


# --- best-effort guarantee --------------------------------------------------


async def test_smtp_failure_does_not_block_the_lifecycle(settings, app_config: AppConfig) -> None:
    # Point email at a dead port; the connection is refused, the send is dropped,
    # and the request is still created and acknowledged.
    from msig_proxy.app import create_app
    from msig_proxy.core.db import Base

    dead_config = app_config.model_copy(
        update={
            "notifications": NotificationsConfig(
                email=_email_config(SmtpProbe(host="127.0.0.1", port=free_port()))
            )
        }
    )
    app = create_app(settings=settings, config=dead_config)
    Base.metadata.create_all(app.state.db_engine)
    for session in session_scope(app.state.session_factory):
        for name in ("alice", "bob"):
            seed_user(session, username=name, email=_EMAIL[name], password=_PASSWORD[name])
        _SECRETS["dave"] = seed_user(
            session, username="dave", email=_EMAIL["dave"], password=_PASSWORD["dave"]
        ).totp_secret

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        login = await http.post(
            "/login",
            data={
                "username": "dave",
                "password": _PASSWORD["dave"],
                "totp": totp_code(_SECRETS["dave"]),
                "service": "internal-app",
            },
            follow_redirects=False,
        )
        assert login.status_code == 303
        assert login.cookies.get(SESSION_COOKIE)
        cookie = {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}
        access = await http.get(
            "/access?service=internal-app", headers=cookie, follow_redirects=False
        )

    assert access.status_code == 303  # the lifecycle proceeded despite the failed send
    assert _request_count(app) == 1  # the request was created and committed
    app.state.db_engine.dispose()  # close pooled connections (no GC ResourceWarning)


# --- unit: unconfigured email is a silent no-op -----------------------------


def test_notify_is_a_no_op_without_email_config() -> None:
    from msig_proxy.core.db import Base, create_db_engine, create_session_factory
    from msig_proxy.notifications import notifier

    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = create_session_factory(engine)()
    try:
        requester = seed_user(
            session, username="dave", email=_EMAIL["dave"], password=_PASSWORD["dave"]
        ).user
        request = ApprovalRequest(
            requester_id=requester.id,
            service_name="internal-app",
            service_type="forward-auth",
            quorum=1,
        )
        session.add(request)
        session.flush()
        config = AppConfig(
            server=ServerConfig(
                host="127.0.0.1", port=8080, base_url="http://testserver", secret_key="x" * 16
            ),
            notifications=NotificationsConfig(email=None),
        )
        notifier.notify_request_created(session, config, request)  # must not raise
    finally:
        session.close()
        engine.dispose()
