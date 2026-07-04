"""Out-of-band publish reconciliation — the PUB-2 detection defense (#124).

The proxy's core guarantee (no publish without m-of-n approval) holds only if
*every* path to PyPI routes through the proxy — complete mediation (Saltzer &
Schroeder). PUB-2 (*Proxy Bypass*) is the gap: a publish-capable credential
*outside* the proxy publishes directly, with no request, no votes, no audit trail.
The proxy cannot prevent that — but it can **detect** it. This module reconciles
the project's public release list (PyPI's JSON API) against the proxy's own publish
log and raises an alert on any release the proxy never performed.

Detection, not prevention (the honest boundary, kept in PUB-2's threat body):
detection **bounds the exposure window**; it cannot un-ship an artifact that
reached the index. Response is an operator runbook — yank/delete via the PyPI web
UI, rotate credentials, audit the collaborator/token list — because PyPI exposes no
delete/yank API and yank (PEP 592) does not remove already-pinned installs anyway.

The **publish log** is the set of ``(package_name, package_version)`` pairs of
one-time Approval Requests that reached ``approved`` — the versions the proxy
authorized. Reconciliation only alerts on a release PyPI has that the log lacks, so
an approved-but-failed publish (never on PyPI) never raises a false alert. The
project set watched is exactly the projects the proxy has published; a project it
never touched is not its mediation surface.

The alert is raised **blind** (ADR 0005): the reconciler emits an
:class:`~msig_proxy.core.events.OutOfBandPublishDetected` event onto the bus, where
the **audit** subscriber records it (durable evidence — the executable oracle) and
the **notification** subscriber emails approvers + admin. The PyPI JSON fetch is the
one outbound boundary here; like the publish POST it is a sync :class:`httpx.Client`
call (``[pure]`` — an outbound adapter, not the inbound web framework; ADR 0011).
"""

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.audit import subscriber as audit_subscriber
from msig_proxy.core import crypto, events
from msig_proxy.core.config import DEFAULT_PYPI_INDEX_URL, ServiceConfig, Settings, load_config
from msig_proxy.core.db import create_db_engine, create_session_factory, session_scope
from msig_proxy.core.events import EventBus, OutOfBandPublishDetected
from msig_proxy.core.models import APPROVED, ONE_TIME, ApprovalRequest
from msig_proxy.notifications import subscriber as notification_subscriber

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class OutOfBandRelease:
    """A release found on the index that the proxy's publish log never approved."""

    project: str
    version: str


def fetch_pypi_versions(
    index_url: str, project: str, *, client: httpx.Client | None = None
) -> set[str]:
    """Fetch the set of released versions for ``project`` from the index JSON API.

    Reads ``{index_url}/pypi/{project}/json`` (PyPI's public per-project JSON
    endpoint) and returns the keys of its ``releases`` map. A ``404`` means the
    project has no presence on the index — an empty set, not an error. Any other
    non-2xx raises :class:`httpx.HTTPStatusError`; the caller decides whether one
    project's fetch failure aborts the run. A sync client matches the threadpool
    posture of the publish path (ADR 0011); an injected ``client`` lets tests and a
    batch run share one connection.
    """
    url = f"{index_url.rstrip('/')}/pypi/{project}/json"
    owned = client is None
    client = client or httpx.Client(timeout=30)
    try:
        response = client.get(url)
    finally:
        if owned:
            client.close()
    if response.status_code == 404:
        return set()
    response.raise_for_status()
    releases = response.json().get("releases", {})
    return set(releases.keys())


def published_projects(session: Session) -> set[str]:
    """Distinct package names the proxy has approved a one-time publish for.

    The project set reconciliation watches — the proxy's mediation surface. A
    project it never published is not reconciled (there is nothing to compare).
    """
    rows = session.scalars(
        select(ApprovalRequest.package_name)
        .where(
            ApprovalRequest.service_type == ONE_TIME,
            ApprovalRequest.state == APPROVED,
            ApprovalRequest.package_name.is_not(None),
        )
        .distinct()
    ).all()
    return {name for name in rows if name is not None}


def published_versions(session: Session, project: str) -> set[str]:
    """The publish log for ``project``: versions of its *approved* one-time requests.

    The proxy authorized each of these; a version PyPI has that is absent here never
    routed through the proxy. Approved-but-failed publishes are harmless to include —
    they are not on PyPI, so they can never suppress a real out-of-band release.
    """
    rows = session.scalars(
        select(ApprovalRequest.package_version).where(
            ApprovalRequest.service_type == ONE_TIME,
            ApprovalRequest.state == APPROVED,
            ApprovalRequest.package_name == project,
            ApprovalRequest.package_version.is_not(None),
        )
    ).all()
    return {version for version in rows if version is not None}


def reconcile(
    session: Session,
    *,
    service_name: str,
    service: ServiceConfig,
    bus: EventBus,
    client: httpx.Client | None = None,
) -> list[OutOfBandRelease]:
    """Reconcile the index against the publish log; emit an alert per rogue release.

    For each project the proxy has published, fetch the index's release list and
    subtract the publish log; whatever remains reached the index without the proxy —
    an :class:`OutOfBandPublishDetected` event is emitted for each (blind, ADR 0005:
    audit records it, notifications email approvers + admin). Returns the flagged
    releases in a stable order. A project whose fetch fails is logged and skipped —
    best-effort detection never aborts the whole sweep for one unreachable project.
    """
    index_url = service.index_url or DEFAULT_PYPI_INDEX_URL
    flagged: list[OutOfBandRelease] = []
    for project in sorted(published_projects(session)):
        try:
            index_versions = fetch_pypi_versions(index_url, project, client=client)
        except httpx.HTTPError:
            _log.warning("reconcile: could not fetch releases for %s", project, exc_info=True)
            continue
        out_of_band = index_versions - published_versions(session, project)
        for version in sorted(out_of_band):
            flagged.append(OutOfBandRelease(project=project, version=version))
            bus.emit(
                OutOfBandPublishDetected(
                    service_name=service_name, project=project, version=version
                )
            )
    return flagged


def main(argv: list[str] | None = None) -> int:
    """CLI/entrypoint: reconcile the configured PyPI service against its publish log.

    Meant to run on a schedule (cron), mirroring how ``msig-provision`` runs at
    boot. Loads deploy :class:`Settings` and the application config, resolves the
    single one-time PyPI service, and reconciles it. Wires a fresh :class:`EventBus`
    with **both** subscribers — audit (records the alert) and notifications (emails
    approvers + admin) — exactly as the app factory does, so a detected out-of-band
    publish is recorded and alerted the same as any lifecycle event. Prints one line
    per flagged release plus a summary.
    """
    argparse.ArgumentParser(
        description="Reconcile PyPI releases against the proxy's publish log (detect out-of-band)."
    ).parse_args(argv)

    settings = Settings()
    config = load_config(settings.config_file)
    service_name, service = config.pypi_service()

    engine = create_db_engine(settings.database_url)
    factory = create_session_factory(engine)
    bus = EventBus()
    audit_subscriber.register(
        bus, factory, crypto.derive_audit_key(config.server.secret_key)
    )  # record the alert (critical consumer)
    notification_subscriber.register(bus, factory, config)  # email approvers + admin

    try:
        for session in session_scope(factory):
            # Bind the reconcile session as the active event session so both subscribers
            # read/write on it (the audit row commits with the scope), as the web path does.
            with events.session_bound(session):
                flagged = reconcile(session, service_name=service_name, service=service, bus=bus)
    finally:
        engine.dispose()

    for release in flagged:
        print(f"  OUT-OF-BAND: {release.project} {release.version}")
    print(f"Reconciled {service_name}: {len(flagged)} out-of-band release(s) detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
