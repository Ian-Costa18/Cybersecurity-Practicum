"""End-to-end: submit → approve to quorum → publish, with the two adversarial oracles.

Real DB, real HTTP, real crypto, **real in-process SMTP**; the PyPI publish is the
single mocked boundary and its captured call is the oracle (``docs/mvp.md``).

This is the close of the Phase 0 thesis (issue #5): it lands the full happy path
and both oracles — Security ① (no quorum ⇒ no publish) and Security ② (mutated
payload ⇒ no publish).
"""

from __future__ import annotations

import uuid

import httpx
import pytest
import respx
from fastapi import FastAPI

from msig_proxy.config import (
    AppConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core import models
from msig_proxy.core.models import ApprovalRequest, StagedArtifact
from msig_proxy.db import session_scope
from msig_proxy.intake import create_publish_request
from msig_proxy.seed import seed_user
from tests.support import SmtpProbe, envelope_as_message, totp_code

ARTIFACT = b"the exact uploaded artifact bytes"
_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "carol")}
# TOTP secrets captured at seed time so vote re-auth satisfies the second factor (#16).
_SECRETS: dict[str, str] = {}
_EMAIL = {name: f"{name}@example.com" for name in ("alice", "bob", "carol")}
_REQUESTER_EMAIL = "publisher@example.com"


@pytest.fixture
def app_config(smtp_server: SmtpProbe) -> AppConfig:
    """Override conftest: register the PyPI service and point email at the live SMTP."""
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
        services={
            "pypi": ServiceConfig(
                type="one-time",
                action="publish-to-pypi",
                quorum=2,
                approvers=["alice", "bob", "carol"],
                credentials={"pypi_token": "pypi-token-value"},
            )
        },
    )


@pytest.fixture
def pending_request_id(app: FastAPI) -> str:
    request_id = ""
    for session in session_scope(app.state.session_factory):
        for name in _PASSWORD:
            _SECRETS[name] = seed_user(
                session, username=name, email=_EMAIL[name], password=_PASSWORD[name]
            ).totp_secret
        requester = seed_user(
            session, username="publisher", email=_REQUESTER_EMAIL, password="pub-pw-123"
        ).user
        service = ServiceConfig(
            type="one-time", action="publish-to-pypi", quorum=2, approvers=list(_PASSWORD)
        )
        request = create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=service,
            package_name="foo",
            package_version="1.2.3",
            filename="foo-1.2.3.tar.gz",
            content=ARTIFACT,
        )
        request_id = str(request.id)
    return request_id


async def _approve(client: httpx.AsyncClient, request_id: str, name: str) -> httpx.Response:
    return await client.post(
        f"/approve/{request_id}",
        data={
            "username": name,
            "password": _PASSWORD[name],
            "totp": totp_code(_SECRETS[name]),
            "decision": "approve",
        },
    )


def _recipients(smtp_server: SmtpProbe) -> set[str]:
    return {addr for envelope in smtp_server.messages for addr in envelope.rcpt_tos}


def _subjects(smtp_server: SmtpProbe) -> list[str]:
    return [envelope_as_message(e)["Subject"] for e in smtp_server.messages]


async def test_happy_path_publishes_and_notifies(
    client: httpx.AsyncClient,
    pending_request_id: str,
    mock_pypi: respx.MockRouter,
    smtp_server: SmtpProbe,
) -> None:
    await _approve(client, pending_request_id, "alice")
    assert not mock_pypi["pypi_upload"].called  # m-1: no publish before quorum
    await _approve(client, pending_request_id, "bob")

    # The handoff reached PyPI exactly once, carrying the approved artifact.
    assert mock_pypi["pypi_upload"].call_count == 1
    assert ARTIFACT in mock_pypi["pypi_upload"].calls.last.request.content

    # Requester + the two endorsing approvers were notified; carol (no vote) was not.
    assert _recipients(smtp_server) == {_REQUESTER_EMAIL, _EMAIL["alice"], _EMAIL["bob"]}
    assert any("Published" in subject for subject in _subjects(smtp_server))


async def test_a_denied_request_never_reaches_pypi(
    client: httpx.AsyncClient,
    app: FastAPI,
    pending_request_id: str,
    mock_pypi: respx.MockRouter,
    smtp_server: SmtpProbe,
) -> None:
    await _approve(client, pending_request_id, "bob")  # one endorsement on record
    await client.post(
        f"/approve/{pending_request_id}",
        data={
            "username": "alice",
            "password": _PASSWORD["alice"],
            "totp": totp_code(_SECRETS["alice"]),
            "decision": "deny",
        },
    )

    # Security ① (quorum oracle): a denied request is never published.
    assert not mock_pypi["pypi_upload"].called
    for session in session_scope(app.state.session_factory):
        denied = session.get(ApprovalRequest, uuid.UUID(pending_request_id))
        assert denied is not None and denied.state == models.DENIED
    # Requester + the endorsing approver (bob) are told it was denied.
    assert _recipients(smtp_server) == {_REQUESTER_EMAIL, _EMAIL["bob"]}
    assert any("denied" in subject.lower() for subject in _subjects(smtp_server))


async def test_a_mutated_payload_is_refused_at_publish(
    client: httpx.AsyncClient,
    app: FastAPI,
    pending_request_id: str,
    mock_pypi: respx.MockRouter,
    smtp_server: SmtpProbe,
) -> None:
    # Substitute the held bytes after creation — one mutated byte breaks Hash Binding.
    for session in session_scope(app.state.session_factory):
        staged = session.get(StagedArtifact, uuid.UUID(pending_request_id))
        assert staged is not None
        staged.content = ARTIFACT + b"!"

    await _approve(client, pending_request_id, "alice")
    await _approve(client, pending_request_id, "bob")  # reaches quorum → executor runs

    # Security ② (integrity oracle): the mutated payload never reaches PyPI.
    assert not mock_pypi["pypi_upload"].called
    assert any("failed" in subject.lower() for subject in _subjects(smtp_server))
