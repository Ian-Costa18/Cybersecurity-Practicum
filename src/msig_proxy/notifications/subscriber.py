"""Notifications as a best-effort *subscriber* to the lifecycle seam (ADR 0005).

The approval flow only :func:`~msig_proxy.core.events.emit`s; nothing in it calls a
notification backend. This module is the single consumer that turns those
lifecycle events into outbound email. Registering it with
:func:`msig_proxy.core.events.subscribe` is the **enforceable** form of the decoupling
(ADR 0005 §"Notification as a Best-Effort Consumer"): the emitter physically
cannot wait on delivery, because delivery happens behind the seam, not inline.

The handler dispatches on ``event.name``:

* ``request.created``  → solicit the snapshot approvers (the Approval Link pull)
* ``request.denied``   → terminal-outcome email (Requester + Endorsing Approvers)
* ``action.succeeded`` → terminal-outcome email (published)
* ``action.failed``    → terminal-outcome email (execution failed)
* ``grant.activated``  → forward-auth access-granted email (Requester + Endorsing Approvers)

The payloads carry **only identifiers** — recipients are resolved from persisted
state (the vote record and approver snapshot the DB already holds). A lifecycle
event is emitted inside the transition's open transaction (flushed, not committed),
so the subscriber reads recipients from the emitter's own session when one is
exposed via :func:`events.active_session`, and otherwise opens a read session off a
captured factory (events fired outside any request scope). A failure here is logged
and swallowed by :func:`events.emit`, never propagating back to the emitting
transition.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable

from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import ApprovalRequest
from msig_proxy.notifications import notifier

_log = logging.getLogger(__name__)


# Events this subscriber turns into email. Every other lifecycle event
# (grant.expired, request.cancelled, account.*) flows past untouched — no load,
# no warning.
_HANDLED = frozenset(
    {
        events.REQUEST_CREATED,
        events.REQUEST_DENIED,
        events.ACTION_SUCCEEDED,
        events.ACTION_FAILED,
        events.GRANT_ACTIVATED,
    }
)


def _load_request(session: Session, payload: dict[str, object]) -> ApprovalRequest | None:
    raw_id = payload.get("approval_request_id")
    if raw_id is None:
        return None
    try:
        request_id = uuid.UUID(str(raw_id))
    except (ValueError, TypeError):
        return None
    return session.get(ApprovalRequest, request_id)


def _dispatch(session: Session, config: AppConfig, event: events.Event) -> None:
    """Resolve recipients from persisted state and send the matching email.

    A no-op for any event this subscriber does not handle. For a handled event whose
    request cannot be resolved, the miss is logged (best-effort, ADR 0005) and dropped.
    """
    if event.name not in _HANDLED:
        return

    request = _load_request(session, event.payload)
    if request is None:
        _log.warning("notification subscriber: no request for %s", event.name)
        return

    email = config.notifications.email if config.notifications else None

    if event.name == events.REQUEST_CREATED:
        notifier.notify_request_created(session, config, request)
    elif event.name == events.REQUEST_DENIED:
        notifier.notify_outcome(
            session,
            email,
            request,
            subject=f"Request denied: {request.service_name}",
            body="Your request was denied by an approver.",
        )
    elif event.name == events.ACTION_SUCCEEDED:
        notifier.notify_outcome(
            session,
            email,
            request,
            subject=f"Published: {request.package_name} {request.package_version}",
            body="Your request was approved and the package was published successfully.",
        )
    elif event.name == events.ACTION_FAILED:
        reason = event.payload.get("reason")
        notifier.notify_outcome(
            session,
            email,
            request,
            subject=f"Execution failed: {request.package_name} {request.package_version}",
            body=f"Your request was approved, but execution failed: {reason}",
        )
    elif event.name == events.GRANT_ACTIVATED:
        # forward-auth handoff: the approved request minted a Service Grant. The
        # audience matches the other terminal outcomes (Requester + Endorsing
        # Approvers), kept on by default for parity (docs/notification-system.md).
        notifier.notify_outcome(
            session,
            email,
            request,
            subject=f"Access granted: {request.service_name}",
            body="Your request was approved and access to the service has been granted.",
        )


def make_handler(
    session_factory: sessionmaker[Session], config: AppConfig
) -> Callable[[events.Event], None]:
    """Build the subscriber handler bound to a session factory and config.

    The returned handler reads recipients from the emitter's session when one is
    lent (:func:`events.active_session`) — so a flushed-but-uncommitted transition is
    visible — and otherwise opens (and closes) its own read session off the factory.
    """

    def handler(event: events.Event) -> None:
        active = events.active_session()
        if active is not None:
            # Read from the emitter's transaction so flushed-but-uncommitted rows
            # (the request, its votes) are visible; do not close a borrowed session.
            _dispatch(active, config, event)
            return
        session = session_factory()
        try:
            _dispatch(session, config, event)
        finally:
            session.close()

    return handler


def register(
    session_factory: sessionmaker[Session], config: AppConfig
) -> Callable[[events.Event], None]:
    """Subscribe the notification handler to the event seam; return it (for tests)."""
    handler = make_handler(session_factory, config)
    events.subscribe(handler)
    return handler
