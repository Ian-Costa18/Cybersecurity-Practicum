"""Notifications as a best-effort *subscriber* to the lifecycle seam (ADR 0005).

The approval flow only :meth:`~msig_proxy.core.events.EventBus.emit`s; nothing in it
calls a notification backend. This module is the single consumer that turns those
lifecycle events into outbound email. Registering it on the app's bus with
:meth:`msig_proxy.core.events.EventBus.subscribe` is the **enforceable** form of the decoupling
(ADR 0005 §"Notification as a Best-Effort Consumer"): the emitter physically
cannot wait on delivery, because delivery happens behind the seam, not inline.

The handler ``match``es on the event **type** (ADR 0014 — no string compare):

* :class:`~events.RequestCreated`  → solicit the snapshot approvers (the Approval Link pull)
* :class:`~events.RequestApproved` → approved-outcome email (Requester only)
* :class:`~events.RequestDenied`   → terminal-outcome email (Requester + Endorsing Approvers)
* :class:`~events.ActionSucceeded` → terminal-outcome email (published)
* :class:`~events.ActionFailed`    → terminal-outcome email (execution failed)
* :class:`~events.GrantActivated`  → forward-auth access email (Requester + Endorsing Approvers)

Every other event type (``GrantExpired``, ``RequestCancelled``, the ``account.*``
events) falls through the ``match`` untouched — no load, no warning. The four
terminal-outcome arms are kept as **honest branches** rather than a data table: their
subjects interpolate different request fields and ``ActionFailed`` splices a dynamic
reason, so a table would need escape hatches for most of its rows (ADR 0014, the
deferred-matrix decision from #103).

The events carry **only identifiers** — recipients are resolved from persisted
state (the vote record and approver snapshot the DB already holds). A lifecycle
event is emitted inside the transition's open transaction (flushed, not committed),
so the subscriber reads recipients from the emitter's bound session when a transition
is in flight, and otherwise opens a read session off a captured factory (events fired
outside any session scope). That borrow-vs-own choice is owned by
:func:`events.deliver_with_session` (``commit=False``, the *best-effort* class); this
module supplies only the dispatch body. A failure here is logged and swallowed by
:meth:`events.EventBus.emit`, never propagating back to the emitting transition.
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


def _request(session: Session, approval_request_id: uuid.UUID) -> ApprovalRequest | None:
    """Load the Approval Request a notification email is about, or ``None``.

    The id is a typed :class:`~uuid.UUID` field on the event (ADR 0014), so there is no
    string re-parse here — only the existence check. A miss (the row cannot be resolved
    from this session) is logged (best-effort, ADR 0005) and the event dropped.
    """
    request = session.get(ApprovalRequest, approval_request_id)
    if request is None:
        _log.warning("notification subscriber: no request %s", approval_request_id)
    return request


def _dispatch(session: Session, config: AppConfig, event: events.Event) -> None:
    """Resolve recipients from persisted state and send the matching email.

    ``match``es on the event type; an event type this subscriber does not handle falls
    through to a silent no-op. For a handled event whose request cannot be resolved, the
    miss is logged (best-effort, ADR 0005) and dropped.
    """
    email = config.notifications.email if config.notifications else None

    match event:
        case events.RequestCreated(approval_request_id=rid):
            if (request := _request(session, rid)) is not None:
                notifier.notify_request_created(session, config, request)
        case events.RequestApproved(approval_request_id=rid):
            # The approval axis settled: tell the Requester only. The execution/grant
            # outcome (action.succeeded / grant.activated) is a separate, later email.
            if (request := _request(session, rid)) is not None:
                notifier.notify_requester(
                    session,
                    email,
                    request,
                    subject=f"Request approved: {request.service_name}",
                    body="Your request was approved.",
                )
        case events.RequestDenied(approval_request_id=rid):
            if (request := _request(session, rid)) is not None:
                notifier.notify_outcome(
                    session,
                    email,
                    request,
                    subject=f"Request denied: {request.service_name}",
                    body="Your request was denied by an approver.",
                )
        case events.ActionSucceeded(approval_request_id=rid):
            if (request := _request(session, rid)) is not None:
                notifier.notify_outcome(
                    session,
                    email,
                    request,
                    subject=f"Published: {request.package_name} {request.package_version}",
                    body="Your request was approved and the package was published successfully.",
                )
        case events.ActionFailed(approval_request_id=rid, reason=reason):
            if (request := _request(session, rid)) is not None:
                notifier.notify_outcome(
                    session,
                    email,
                    request,
                    subject=f"Execution failed: {request.package_name} {request.package_version}",
                    body=f"Your request was approved, but execution failed: {reason}",
                )
        case events.GrantActivated(approval_request_id=rid):
            # forward-auth handoff: the approved request minted a Service Grant. The
            # audience matches the other terminal outcomes (Requester + Endorsing
            # Approvers), kept on by default for parity (docs/notification-system.md).
            if (request := _request(session, rid)) is not None:
                notifier.notify_outcome(
                    session,
                    email,
                    request,
                    subject=f"Access granted: {request.service_name}",
                    body="Your request was approved and access to the service has been granted.",
                )
        case events.OutOfBandPublishDetected(service_name=svc, project=project, version=version):
            # PUB-2 detection (#124): a release the proxy never published appeared on
            # the index. Not request-scoped — the audience is admins + the service's
            # approvers, resolved by the notifier (which needs the full config, not just
            # the email block, to reach the service's approver set).
            notifier.notify_out_of_band_publish(
                session, config, service_name=svc, project=project, version=version
            )


def make_handler(
    session_factory: sessionmaker[Session], config: AppConfig
) -> Callable[[events.Event], None]:
    """Build the subscriber handler bound to a session factory and config.

    The returned handler reads recipients from the emitter's bound session when a
    transition is in flight — so a flushed-but-uncommitted transition is visible — and
    otherwise opens (and closes) its own read session. That choice, and ``commit=False``
    (notifications only read; this is the best-effort class), are owned by
    :func:`events.deliver_with_session`; this handler supplies only the dispatch body.
    """

    def handler(event: events.Event) -> None:
        events.deliver_with_session(
            lambda session: _dispatch(session, config, event),
            session_factory=session_factory,
            commit=False,
        )

    return handler


def register(
    bus: events.EventBus, session_factory: sessionmaker[Session], config: AppConfig
) -> Callable[[events.Event], None]:
    """Subscribe the notification handler to the app's event bus; return it (for tests)."""
    handler = make_handler(session_factory, config)
    bus.subscribe(handler)
    return handler
