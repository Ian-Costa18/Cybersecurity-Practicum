"""The t = m-1 worst case: even m-1 fully-compromised seats cannot publish (#114, CORE-1).

The demo's Act 2 dramatizes the *realistic* operating point — a single stolen seat plus
one careless approver, resolved by a diligent live deny. This test is its rigorous twin:
the **strict boundary** where m-1 of an m-of-n service's seats are fully attacker-
controlled and both approve. The proxy still will not publish — the request freezes one
short of quorum — and if the last honest approver denies, it reaches ``denied``. The
oracle is that the PyPI boundary is **never invoked** in either case.

Real DB, real crypto, real HTTP; the outbound publish is the single mocked boundary and
its zero call count is the assertion (``docs/mvp.md``). Enters at the Proxy HTTP surface,
like the other adversarial tests.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
import respx
from fastapi import FastAPI

from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import models
from msig_proxy.core.config import AppConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest
from msig_proxy.service_types.one_time.intake import create_publish_request
from tests.support import totp_code

ARTIFACT = b"a malicious payload the compromised seats want shipped"

# A 3-of-3 service: m = 3, so m-1 = 2 seats are the compromised worst case.
_APPROVERS = ("alice", "bob", "carol")
_PASSWORD = {name: f"pw-{name}-123" for name in _APPROVERS}
_SECRETS: dict[str, str] = {}
# The two seats the attacker fully controls; the third is the honest holdout.
_COMPROMISED = ("alice", "bob")
_HONEST = "carol"


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        services={
            "pypi": ServiceConfig(
                type="one-time",
                action="publish-to-pypi",
                quorum=3,
                approvers=list(_APPROVERS),
                credentials={"pypi_token": "pypi-token-value"},
            )
        },
    )


@pytest.fixture
def pending_request_id(app: FastAPI) -> str:
    request_id = ""
    for session in session_scope(app.state.session_factory):
        for name in _APPROVERS:
            _SECRETS[name] = seed_user(
                session, username=name, email=f"{name}@example.com", password=_PASSWORD[name]
            ).totp_secret
        requester = seed_user(
            session, username="publisher", email="publisher@example.com", password="pub-pw-123"
        ).user
        service = ServiceConfig(
            type="one-time", action="publish-to-pypi", quorum=3, approvers=list(_APPROVERS)
        )
        request = create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=service,
            package_name="foo",
            package_version="6.6.6",
            filename="foo-6.6.6.tar.gz",
            content=ARTIFACT,
        )
        request_id = str(request.id)
    return request_id


async def _vote(client: httpx.AsyncClient, request_id: str, name: str, decision: str) -> None:
    await client.post(
        f"/approve/{request_id}",
        data={
            "username": name,
            "password": _PASSWORD[name],
            "totp": totp_code(_SECRETS[name]),
            "decision": decision,
        },
    )


def _state(app: FastAPI, request_id: str) -> str:
    for session in session_scope(app.state.session_factory):
        request = session.get(ApprovalRequest, uuid.UUID(request_id))
        assert request is not None
        return request.state
    return ""  # pragma: no cover


async def test_m_minus_one_compromised_seats_cannot_publish(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str, mock_pypi: respx.MockRouter
) -> None:
    # Both attacker-controlled seats approve — the request reaches m-1 = 2 of 3.
    for name in _COMPROMISED:
        await _vote(client, pending_request_id, name, "approve")

    # Quorum is not met: the request is still pending and nothing has been published.
    assert _state(app, pending_request_id) == models.PENDING
    assert not mock_pypi["pypi_upload"].called  # the whole point: m-1 seats cannot ship

    # The honest holdout denies — now it is terminally closed, still never published.
    await _vote(client, pending_request_id, _HONEST, "deny")

    assert _state(app, pending_request_id) == models.DENIED
    assert not mock_pypi["pypi_upload"].called


async def test_compromised_seats_that_only_abstain_leave_it_frozen(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str, mock_pypi: respx.MockRouter
) -> None:
    # Even if the honest seat never acts, m-1 approvals sit frozen forever — the enforced
    # friction/latency that gives a diligent co-owner time to catch the anomaly (Act 2).
    for name in _COMPROMISED:
        await _vote(client, pending_request_id, name, "approve")

    assert _state(app, pending_request_id) == models.PENDING
    assert not mock_pypi["pypi_upload"].called
