"""Backing check for the demo's Act 2 — the compromised-account deny (#114, epic #142).

The flagship beat: one co-owner's **proxy credential** is stolen (the planted,
throwaway seat password/TOTP/token — not their mailbox). At 2 a.m. the attacker submits
a malicious ``acme-widgets 1.0.1`` and self-approves; an honest-but-careless co-owner
rubber-stamps; the request **freezes at 2/3 and waits**. The diligent co-owner verifies
out-of-band by real email (the owner's mailbox is intact, so the reply is trustworthy)
and denies on human context. The malicious release never reaches the index.

Same posture as Act 1: real DB/crypto/HTTP/in-process SMTP, the outbound publish the
single mocked boundary — and here the oracle is that it is **never called**. Drives the
exact ``demo_flow`` code the notebook runs, against an in-process proxy.
"""

from __future__ import annotations

from collections.abc import Iterator

import demo_flow
import demo_lib
import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from msig_proxy.audit.integrity import verify_audit_chain
from msig_proxy.core import crypto, models
from msig_proxy.core.config import (
    AppConfig,
    AuthConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import session_scope
from tests.support import PYPI_UPLOAD_URL, SmtpProbe, envelope_as_message

# The demo app's session secret; the audit chain is keyed by an HKDF derivation of it.
_SECRET_KEY = "test-secret-key-0123456789"


@pytest.fixture
def app_config(smtp_server: SmtpProbe) -> AppConfig:
    """The demo's 3-of-3 service, email at the live SMTP probe, wide TOTP window (#73)."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key=_SECRET_KEY,
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
                endpoint=PYPI_UPLOAD_URL,  # the single mocked boundary; must never be called
                credentials={"pypi_token": "demo-token"},
            )
        },
    )


@pytest.fixture
def provisioned(app: FastAPI) -> FastAPI:
    for session in session_scope(app.state.session_factory):
        demo_lib.provision_demo_team(session)
    return app


@pytest.fixture
def driver(provisioned: FastAPI) -> Iterator[demo_flow.ProxyDriver]:
    with TestClient(provisioned) as client:
        yield demo_flow.ProxyDriver(client=client, sessions=provisioned.state.session_factory)


@pytest.fixture
def stack(smtp_server: SmtpProbe) -> demo_flow.DemoStack:
    return demo_flow.DemoStack(
        proxy_url="http://testserver",
        mailpit_url="http://mailpit.test",
        pypiserver_url="http://pypiserver.test",
        smtp_host=smtp_server.host,
        smtp_port=smtp_server.port,
    )


def _recipients(smtp_server: SmtpProbe) -> set[str]:
    return {addr for envelope in smtp_server.messages for addr in envelope.rcpt_tos}


# --- the freeze: a single stolen seat cannot reach quorum ------------------


def test_stolen_seat_and_careless_stamp_freeze_at_two_thirds(
    driver: demo_flow.ProxyDriver, mock_pypi: respx.MockRouter
) -> None:
    with driver.sessions() as session:
        _, request_id, artifact = demo_flow.act2_submit_from_stolen_seat(driver, session)
    demo_flow.act2_careless_rubber_stamp(driver, request_id)

    approvals, quorum = driver.tally(request_id)
    assert (approvals, quorum) == (2, demo_lib.QUORUM)  # 2/3 — one short of quorum
    assert driver.state(request_id) == models.PENDING  # frozen, waiting — not published
    assert not mock_pypi["pypi_upload"].called  # the friction/latency value: no publish
    assert artifact is not None and artifact.version == "1.0.1"


# --- the out-of-band verification is real, independent email ---------------


def test_out_of_band_verification_is_real_email(
    stack: demo_flow.DemoStack, smtp_server: SmtpProbe
) -> None:
    question_sent, reply_sent = demo_flow.act2_verify_out_of_band(stack)

    assert question_sent is True and reply_sent is True
    diligent = demo_lib.person(demo_lib.ACT2_DILIGENT)
    owner = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT)
    # The query goes TO the owner and the reply comes BACK — an exchange with a *different*
    # person whose mailbox the attacker does not hold (only the proxy credential was stolen).
    assert _recipients(smtp_server) == {owner.email, diligent.email}
    froms = [envelope_as_message(e)["From"] for e in smtp_server.messages]
    assert any(owner.email in frm for frm in froms)  # the owner really replied
    bodies = [envelope_as_message(e).get_content() for e in smtp_server.messages]
    assert any("I was asleep" in body for body in bodies)  # "no, I didn't push it"


# --- the deny blocks the malicious release ---------------------------------


def test_diligent_deny_blocks_the_malicious_release(
    driver: demo_flow.ProxyDriver, stack: demo_flow.DemoStack, mock_pypi: respx.MockRouter
) -> None:
    result = demo_flow.run_act2(driver, stack)

    # The freeze the deny resolved was a genuine 2/3.
    assert (result.frozen_approvals, result.quorum) == (2, demo_lib.QUORUM)
    assert result.verification_sent and result.reply_sent
    # The request reached DENIED and the malicious payload never reached the index.
    assert result.final_state == models.DENIED
    assert not mock_pypi["pypi_upload"].called  # 1.0.1 never handed off to the registry
    assert result.artifact is not None and result.artifact.version == "1.0.1"

    # The internal oracle corroborates: the tamper-evident audit chain still verifies
    # end to end after the deny (#121).
    with driver.sessions() as session:
        verdict = verify_audit_chain(session, audit_key=crypto.derive_audit_key(_SECRET_KEY))
    assert verdict.ok


def test_the_revealed_payload_is_a_real_install_time_exec(
    driver: demo_flow.ProxyDriver, mock_pypi: respx.MockRouter
) -> None:
    # The blatant payload is corroboration revealed AFTER the human deny, not its trigger.
    # It is genuinely inside the uploaded archive (extracted from setup.py), not narration.
    artifact = demo_flow.malicious_release()
    setup_py = demo_flow.extract_text_member(artifact.content, "setup.py")
    assert demo_flow.MALICIOUS_PAYLOAD_LINE in setup_py
    assert "os.system(" in setup_py


# --- the outcome oracle: index absent --------------------------------------


def test_malicious_version_is_absent_from_the_index(stack: demo_flow.DemoStack) -> None:
    # The live demo reads the real pypiserver; the parser oracle confirms 1.0.1 is absent
    # from an index that only ever held the good 1.0.0.
    index_html = (
        "<!DOCTYPE html><html><body>"
        '<a href="/packages/acme-widgets-1.0.0.tar.gz">acme-widgets-1.0.0.tar.gz</a>'
        "</body></html>"
    )
    with respx.mock as router:
        router.get(f"{stack.pypiserver_url}/simple/{demo_lib.PACKAGE_NAME}/").mock(
            return_value=httpx.Response(200, text=index_html)
        )
        files = demo_flow.index_files(stack)

    assert demo_flow.index_has_version(files, "1.0.1") is False  # never shipped
    assert demo_flow.index_has_version(files, "1.0.0") is True  # only the good one is there


def test_verification_thread_renders_question_then_reply() -> None:
    # The board's two-card thread widget (US35): the question and reply, rendered from the
    # Mailpit-shaped rows, come through as legible cards with the owner's mailbox as sender.
    diligent = demo_lib.person(demo_lib.ACT2_DILIGENT)
    owner = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT)
    thread = [
        demo_flow.MailpitMessage(
            id="1",
            from_address=diligent.email,
            to_addresses=(owner.email,),
            subject=demo_flow.VERIFICATION_SUBJECT,
            snippet="Are you pushing 1.0.1 right now?",
        ),
        demo_flow.MailpitMessage(
            id="2",
            from_address=owner.email,
            to_addresses=(diligent.email,),
            subject=f"Re: {demo_flow.VERIFICATION_SUBJECT}",
            snippet="What? No — I was asleep.",
        ),
    ]

    html = demo_flow.render_thread_html(thread)

    assert html.index(diligent.email) < html.index("Re:")  # question card precedes the reply
    assert owner.email in html and "I was asleep" in html  # the owner's real reply is shown
