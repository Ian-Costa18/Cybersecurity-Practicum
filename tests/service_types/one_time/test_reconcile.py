"""Out-of-band publish reconciliation — the PUB-2 detection oracle (#124).

Detection tier (not prevention): the proxy cannot stop a publish that never
touched it, but it can *see* one. Real DB, real crypto, **real in-process SMTP**;
the one mocked boundary is the PyPI JSON API standing in for ``pypi.org``. The
alert — an emitted ``publish.out_of_band_detected`` event, its audit row, and the
email to approvers + admin — is the executable oracle.

An out-of-band publish is modelled as a version present on the (mocked) index that
the proxy's publish log never approved; the reconciler must flag exactly that
version and leave versions the proxy did publish alone.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.accounts.seed import seed_user
from msig_proxy.audit import subscriber as audit_subscriber
from msig_proxy.core import crypto, events
from msig_proxy.core.config import (
    AppConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.events import EventBus, OutOfBandPublishDetected
from msig_proxy.core.models import APPROVED, ONE_TIME, ApprovalRequest, AuditLog
from msig_proxy.notifications import subscriber as notification_subscriber
from msig_proxy.service_types.one_time import reconcile
from tests.support import SmtpProbe, envelope_as_message

PROJECT = "foo"
INDEX_URL = "https://pypi.org"
_SERVER = ServerConfig(base_url="http://testserver", secret_key="x" * 16)


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = create_session_factory(engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


def _service() -> ServiceConfig:
    return ServiceConfig(
        type="one-time",
        action="publish-to-pypi",
        quorum=2,
        approvers=["alice", "bob"],
        credentials={"pypi_token": "pypi-token-value"},
    )


def _record_published(session: Session, *, project: str, version: str) -> None:
    """Add an *approved* one-time request — the proxy's publish log for ``project``."""
    requester = seed_user(
        session, username="publisher", email="publisher@example.com", password="pub-pw-123"
    ).user
    session.add(
        ApprovalRequest(
            requester_id=requester.id,
            service_name="pypi",
            service_type=ONE_TIME,
            action="publish-to-pypi",
            state=APPROVED,
            quorum=2,
            package_name=project,
            package_version=version,
            artifact_sha256="0" * 64,
        )
    )
    session.flush()


def _index_json(*versions: str) -> httpx.Response:
    """A PyPI JSON API response whose ``releases`` map lists ``versions``."""
    return httpx.Response(200, json={"releases": {v: [] for v in versions}})


def _collect(bus: EventBus) -> list[events.Event]:
    seen: list[events.Event] = []
    bus.subscribe(seen.append)
    return seen


def test_out_of_band_publish_raises_an_alert(session: Session) -> None:
    # The proxy published foo 1.2.3 through the approval flow...
    _record_published(session, project=PROJECT, version="1.2.3")
    bus = EventBus()
    alerts = _collect(bus)

    # ...but the index also carries 9.9.9, which the proxy never approved.
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{INDEX_URL}/pypi/{PROJECT}/json").mock(
            return_value=_index_json("1.2.3", "9.9.9")
        )
        reconcile.reconcile(session, service_name="pypi", service=_service(), bus=bus)

    # Exactly the unmediated release is flagged; the mediated one is not.
    detected = [e for e in alerts if isinstance(e, OutOfBandPublishDetected)]
    assert len(detected) == 1
    assert detected[0].project == PROJECT
    assert detected[0].version == "9.9.9"


def test_a_release_the_proxy_published_raises_no_alert(session: Session) -> None:
    # The index carries only what the proxy itself published — no bypass.
    _record_published(session, project=PROJECT, version="1.2.3")
    bus = EventBus()
    alerts = _collect(bus)

    with respx.mock(assert_all_called=True) as router:
        router.get(f"{INDEX_URL}/pypi/{PROJECT}/json").mock(return_value=_index_json("1.2.3"))
        flagged = reconcile.reconcile(session, service_name="pypi", service=_service(), bus=bus)

    assert flagged == []
    assert not [e for e in alerts if isinstance(e, OutOfBandPublishDetected)]


def _config(smtp: SmtpProbe) -> AppConfig:
    """Config wiring the alert channel: live SMTP + the pypi service whose approver
    set (``alice``/``bob``) the subscriber resolves as part of the alert audience."""
    return AppConfig(
        server=_SERVER,
        notifications=NotificationsConfig(
            email=EmailConfig(
                enabled=True,
                smtp_host=smtp.host,
                smtp_port=smtp.port,
                from_address="Proxy <proxy@example.com>",
                tls=False,
            )
        ),
        services={"pypi": _service()},
    )


def _recipients(smtp: SmtpProbe) -> set[str]:
    return {addr for envelope in smtp.messages for addr in envelope.rcpt_tos}


def test_the_alert_notifies_approvers_and_admin(
    factory: sessionmaker[Session], smtp_server: SmtpProbe
) -> None:
    bus = EventBus()
    notification_subscriber.register(bus, factory, _config(smtp_server))

    db = factory()
    try:
        seed_user(db, username="alice", email="alice@example.com", password="pw-alice-123")
        seed_user(db, username="bob", email="bob@example.com", password="pw-bob-1234")
        seed_user(
            db, username="root", email="admin@example.com", password="pw-root-123", is_admin=True
        )
        seed_user(db, username="eve", email="eve@example.com", password="pw-eve-1234")
        _record_published(db, project=PROJECT, version="1.2.3")
        db.commit()

        with respx.mock(assert_all_called=True) as router:
            router.get(f"{INDEX_URL}/pypi/{PROJECT}/json").mock(
                return_value=_index_json("1.2.3", "9.9.9")
            )
            with events.session_bound(db):
                reconcile.reconcile(db, service_name="pypi", service=_service(), bus=bus)
    finally:
        db.close()

    # The alert reached the two approvers and the admin — not the requester or a
    # bystander — and names the unmediated release.
    assert _recipients(smtp_server) == {"alice@example.com", "bob@example.com", "admin@example.com"}
    message = envelope_as_message(smtp_server.messages[0])
    assert "9.9.9" in message["Subject"]
    assert PROJECT in message["Subject"]


def test_the_alert_is_recorded_in_the_audit_trail(factory: sessionmaker[Session]) -> None:
    # The durable half of detection: a rogue release leaves an audit row that bounds
    # the exposure window even if the best-effort email is never delivered.
    bus = EventBus()
    audit_subscriber.register(bus, factory, crypto.derive_audit_key("test-secret-key-0123456789"))

    db = factory()
    try:
        _record_published(db, project=PROJECT, version="1.2.3")
        db.commit()
        with respx.mock(assert_all_called=True) as router:
            router.get(f"{INDEX_URL}/pypi/{PROJECT}/json").mock(
                return_value=_index_json("1.2.3", "9.9.9")
            )
            with events.session_bound(db):
                reconcile.reconcile(db, service_name="pypi", service=_service(), bus=bus)

        rows = (
            db.query(AuditLog).filter(AuditLog.event_name == "publish.out_of_band_detected").all()
        )
        assert len(rows) == 1
        assert "9.9.9" in rows[0].payload
        assert PROJECT in rows[0].payload
    finally:
        db.close()


def test_a_project_absent_from_the_index_raises_no_alert(session: Session) -> None:
    # 404 = the project has no presence on the index yet — an empty release set, not
    # an out-of-band publish. (A published version the index has not surfaced would
    # only ever suppress an alert, never manufacture one.)
    _record_published(session, project=PROJECT, version="1.2.3")
    bus = EventBus()
    alerts = _collect(bus)

    with respx.mock(assert_all_called=True) as router:
        router.get(f"{INDEX_URL}/pypi/{PROJECT}/json").mock(return_value=httpx.Response(404))
        flagged = reconcile.reconcile(session, service_name="pypi", service=_service(), bus=bus)

    assert flagged == []
    assert not [e for e in alerts if isinstance(e, OutOfBandPublishDetected)]


def test_an_unreachable_index_is_skipped_not_fatal(session: Session) -> None:
    # Best-effort detection: a project whose fetch fails (5xx / transport) is logged
    # and skipped — one unreachable project must not abort the whole sweep or raise.
    _record_published(session, project=PROJECT, version="1.2.3")
    bus = EventBus()

    with respx.mock(assert_all_called=True) as router:
        router.get(f"{INDEX_URL}/pypi/{PROJECT}/json").mock(return_value=httpx.Response(503))
        flagged = reconcile.reconcile(session, service_name="pypi", service=_service(), bus=bus)

    assert flagged == []


def test_cli_reconciles_against_settings_db_and_alerts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    smtp_server: SmtpProbe,
) -> None:
    # The entrypoint path (the scheduled/cron run): drive reconcile.main over a config
    # file + DB resolved from MSIG_* settings, with the whole subscriber stack wired as
    # in the app — real DB, real SMTP, real audit; only the index JSON is mocked.
    url = f"sqlite+pysqlite:///{(tmp_path / 'reconcile.db').as_posix()}"
    setup_engine = create_db_engine(url)
    Base.metadata.create_all(setup_engine)
    db = create_session_factory(setup_engine)()
    seed_user(db, username="alice", email="alice@example.com", password="pw-alice-123")
    seed_user(db, username="bob", email="bob@example.com", password="pw-bob-1234")
    seed_user(db, username="root", email="admin@example.com", password="pw-root-123", is_admin=True)
    _record_published(db, project=PROJECT, version="1.2.3")
    db.commit()
    db.close()
    setup_engine.dispose()

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "server:\n"
        "  base_url: http://testserver\n"
        "  secret_key: test-secret-key-0123456789\n"
        "notifications:\n"
        "  email:\n"
        "    enabled: true\n"
        f"    smtp_host: {smtp_server.host}\n"
        f"    smtp_port: {smtp_server.port}\n"
        "    from_address: Proxy <proxy@example.com>\n"
        "    tls: false\n"
        "services:\n"
        "  pypi:\n"
        "    type: one-time\n"
        "    action: publish-to-pypi\n"
        "    quorum: 2\n"
        "    approvers: [alice, bob]\n"
        "    credentials:\n"
        "      pypi_token: dummy\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MSIG_DATABASE_URL", url)
    monkeypatch.setenv("MSIG_CONFIG_FILE", str(config_file))

    with respx.mock(assert_all_called=True) as router:
        router.get(f"{INDEX_URL}/pypi/{PROJECT}/json").mock(
            return_value=_index_json("1.2.3", "9.9.9")
        )
        assert reconcile.main([]) == 0

    assert "OUT-OF-BAND: foo 9.9.9" in capsys.readouterr().out
    # The alert reached the governing audience over real SMTP...
    assert _recipients(smtp_server) == {"alice@example.com", "bob@example.com", "admin@example.com"}
    # ...and the durable audit row was committed by the run's session scope.
    engine = create_db_engine(url)
    try:
        check = create_session_factory(engine)()
        rows = (
            check.query(AuditLog)
            .filter(AuditLog.event_name == "publish.out_of_band_detected")
            .all()
        )
        assert len(rows) == 1 and "9.9.9" in rows[0].payload
        check.close()
    finally:
        engine.dispose()
