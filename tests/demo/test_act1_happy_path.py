"""Backing check for the demo's Act 1 — the happy-path publish (#112, epic #142).

The notebook (``demo/notebooks/publish_demo.py``) claims to drive the live stack
through a full happy-path publish over real HTTP. These tests exercise the **exact**
flow code the notebook runs (``demo_flow``) against the real app served by uvicorn on a
localhost port, with the demo team provisioned. Real DB, real crypto, real HTTP, real
in-process SMTP, and a **real twine** upload (#158); the one mocked boundary is the
outbound PyPI publish (the pytest twin's oracle), as in the rest of the suite
(``docs/mvp.md``).

The live demo's own oracle is the real ``pypiserver`` index + a ``pip install``
bookend; here the equivalent assertion is the recorded publish call (Act 1 ships)
plus the index-parser exercised against a realistic simple-index response.
"""

from __future__ import annotations

import uuid

import demo_flow
import demo_lib
import httpx
import pytest
import respx
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.core import models
from msig_proxy.core.config import (
    AppConfig,
    AuthConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest, StagedArtifact, User
from tests.support import PYPI_UPLOAD_URL, SmtpProbe, envelope_as_message

# A realistic PEP-503 simple-index page for the parser oracle (what pypiserver serves).
_SIMPLE_INDEX = (
    "<!DOCTYPE html><html><body>"
    '<a href="/packages/acme-widgets-1.0.0.tar.gz#sha256=abc">acme-widgets-1.0.0.tar.gz</a><br>'
    "</body></html>"
)


@pytest.fixture
def app_config(smtp_server: SmtpProbe) -> AppConfig:
    """The demo's 3-of-3 service, email pointed at the live SMTP probe, and a widened
    TOTP window so the fast test can re-auth the same user twice in one window (#73)."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        auth=AuthConfig(totp_window=4),
        notifications=NotificationsConfig(
            email=EmailConfig(
                enabled=True,
                smtp_host=smtp_server.host,
                smtp_port=smtp_server.port,
                from_address="Proxy <proxy@acme.example>",
                tls=False,
            )
        ),
        services={
            demo_lib.SERVICE_NAME: ServiceConfig(
                type="one-time",
                action="publish-to-pypi",
                approvers=[p.username for p in demo_lib.CO_OWNERS],
                quorum=demo_lib.QUORUM,
                endpoint=PYPI_UPLOAD_URL,  # the single mocked boundary (respx)
                credentials={"pypi_token": "demo-token"},
            )
        },
    )


@pytest.fixture
def provisioned(app: FastAPI) -> FastAPI:
    """The demo team, provisioned into the app's DB exactly as Act 0 does."""
    for session in session_scope(app.state.session_factory):
        demo_lib.provision_demo_team(session)
    return app


@pytest.fixture
def stack(smtp_server: SmtpProbe) -> demo_flow.DemoStack:
    """A :class:`demo_flow.DemoStack` whose SMTP is the live probe (human channel)."""
    return demo_flow.DemoStack(
        proxy_url="http://testserver",
        mailpit_url="http://mailpit.test",
        pypiserver_url="http://pypiserver.test",
        smtp_host=smtp_server.host,
        smtp_port=smtp_server.port,
    )


def _read_request(app: FastAPI, request_id: str) -> ApprovalRequest:
    for session in session_scope(app.state.session_factory):
        request = session.get(ApprovalRequest, uuid.UUID(request_id))
        assert request is not None
        session.expunge(request)
        return request
    raise AssertionError("session_scope always yields once")  # pragma: no cover


def _recipients(smtp_server: SmtpProbe) -> set[str]:
    return {addr for envelope in smtp_server.messages for addr in envelope.rcpt_tos}


# --- the team thread (human channel) ---------------------------------------


def test_team_thread_heads_up_is_a_real_email(
    stack: demo_flow.DemoStack, smtp_server: SmtpProbe
) -> None:
    delivered = demo_flow.act1_announce(stack)

    # ONE real *group* email — a single message addressed to every *other* co-owner (the
    # requester does not mail themselves), so the shown inbox reads as a group thread, not a
    # stack of identical 1:1 notes. The whole group is visible on the To line.
    others = {p.email for p in demo_lib.CO_OWNERS if p.key != demo_lib.ACT1_REQUESTER}
    assert delivered == len(others)
    assert len(smtp_server.messages) == 1  # one group message, not one-per-owner
    assert _recipients(smtp_server) == others
    message = envelope_as_message(smtp_server.messages[0])
    assert all(email in message["To"] for email in others)  # the whole group on the To line
    assert "acme-widgets 1.0.0" in message.get_content()


# --- submit + benign self-cancel -------------------------------------------


def test_submit_creates_a_hash_bound_request(
    driver: demo_flow.ProxyDriver, provisioned: FastAPI, mock_pypi: respx.MockRouter
) -> None:
    # The real-client contract (#158): `python -m twine upload` — the tool a package author
    # actually runs, authenticating with an API token — is what creates the pending request.
    # The rest of the suite drives `/pypi/legacy/` with a hand-built form, which is fast but
    # only *resembles* twine; this is the one place the resemblance is checked against twine.
    cookie, token = demo_flow.act1_prepare_requester(driver)
    artifact = demo_flow.benign_release()

    request_id = driver.upload(artifact, token=token, cookie=cookie)

    assert driver.state(request_id) == models.PENDING
    request = _read_request(provisioned, request_id)
    assert request.package_name == demo_lib.PACKAGE_NAME
    assert request.package_version == "1.0.0"
    assert request.artifact_sha256 == artifact.sha256  # hash-bound to the exact bytes
    assert request.quorum == demo_lib.QUORUM
    for session in session_scope(provisioned.state.session_factory):
        staged = session.get(StagedArtifact, request.id)
        assert staged is not None and staged.content == artifact.content
    assert not mock_pypi["pypi_upload"].called  # upload stops before any publish


def test_benign_self_cancel_then_clean_resubmit(
    driver: demo_flow.ProxyDriver, mock_pypi: respx.MockRouter
) -> None:
    cookie, token = demo_flow.act1_prepare_requester(driver)

    draft_id, request_id, _ = demo_flow.act1_submit_with_self_cancel(driver, cookie, token)

    assert draft_id != request_id
    assert driver.state(draft_id) == models.CANCELLED  # the requester withdrew their own draft
    assert driver.state(request_id) == models.PENDING  # the clean resubmit is live
    assert not mock_pypi["pypi_upload"].called  # nothing published yet


# --- notify + inspect the exact artifact -----------------------------------


def test_approvers_notified_and_exact_artifact_downloadable(
    driver: demo_flow.ProxyDriver, smtp_server: SmtpProbe, mock_pypi: respx.MockRouter
) -> None:
    cookie, token = demo_flow.act1_prepare_requester(driver)
    artifact = demo_flow.benign_release()
    request_id = driver.upload(artifact, token=token, cookie=cookie)

    # Every co-owner (the snapshot approver set) is emailed the approval link.
    assert {p.email for p in demo_lib.CO_OWNERS} <= _recipients(smtp_server)
    bodies = [envelope_as_message(e).get_content() for e in smtp_server.messages]
    links = [demo_flow.extract_approval_link(body) for body in bodies]
    assert any(link is not None and request_id in link for link in links)

    # The shown co-owner downloads the EXACT bytes they will sign over.
    assert driver.download_artifact(request_id) == artifact.content


# --- quorum → real publish --------------------------------------------------


def test_quorum_publishes_the_release(
    driver: demo_flow.ProxyDriver, smtp_server: SmtpProbe, mock_pypi: respx.MockRouter
) -> None:
    result = demo_flow.run_act1(driver)

    assert result.inspected_matches is True  # the downloaded artifact hashed as expected
    assert (result.approvals, result.quorum) == (demo_lib.QUORUM, demo_lib.QUORUM)  # 3-of-3
    assert result.final_state == models.APPROVED

    # The publish reached the boundary exactly once, carrying the approved bytes.
    assert mock_pypi["pypi_upload"].call_count == 1
    assert result.artifact is not None
    assert result.artifact.content in mock_pypi["pypi_upload"].calls.last.request.content

    subjects = [envelope_as_message(e)["Subject"] for e in smtp_server.messages]
    assert any("Published" in subject for subject in subjects)


# --- the external oracle: the index parser ---------------------------------


def test_published_version_appears_in_the_index(stack: demo_flow.DemoStack) -> None:
    # The live demo reads the real pypiserver; here the same parser is driven against a
    # realistic simple-index response so the "installs from the index" oracle is covered.
    with respx.mock as router:
        router.get(f"{stack.pypiserver_url}/simple/{demo_lib.PACKAGE_NAME}/").mock(
            return_value=httpx.Response(200, text=_SIMPLE_INDEX)
        )
        files = demo_flow.index_files(stack)

    assert demo_flow.index_has_version(files, "1.0.0") is True  # Act 1's release is present
    assert demo_flow.index_has_version(files, "1.0.1") is False  # Act 2's never will be


# --- reset between takes ----------------------------------------------------


def test_reset_demo_clears_workflow_state(
    driver: demo_flow.ProxyDriver, provisioned: FastAPI, stack: demo_flow.DemoStack
) -> None:
    # A submit leaves a pending request + a minted token; reset clears both but keeps the
    # team accounts, so a recording take re-runs in seconds (demo requirement 31).
    cookie, token = demo_flow.act1_prepare_requester(driver)
    request_id = driver.upload(demo_flow.benign_release(), token=token, cookie=cookie)
    assert driver.state(request_id) == models.PENDING

    # Only the reset's two outbound calls are stubbed; the submit above ran against the
    # live proxy, which respx must not intercept.
    with respx.mock as router:
        router.get(f"{stack.pypiserver_url}/simple/{demo_lib.PACKAGE_NAME}/").mock(
            return_value=httpx.Response(404)  # nothing to remove from the index
        )
        mail_delete = router.delete(f"{stack.mailpit_url}/api/v1/messages").mock(
            return_value=httpx.Response(200)  # the inbox is emptied too
        )
        summary = demo_flow.reset_demo(driver, stack)

    assert summary.requests_deleted == 1
    assert summary.tokens_deleted >= 1
    assert mail_delete.called and summary.mail_cleared is True  # reset empties Mailpit too
    for session in session_scope(provisioned.state.session_factory):
        assert session.get(ApprovalRequest, uuid.UUID(request_id)) is None  # workflow gone
        surviving = session.scalars(
            select(User).where(User.username == demo_lib.ACT1_REQUESTER)
        ).one_or_none()
        assert surviving is not None  # the team account survives the reset
