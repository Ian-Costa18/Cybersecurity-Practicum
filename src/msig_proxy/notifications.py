"""Best-effort outcome notifications over SMTP (``docs/notification-system.md``).

The notification system is a **best-effort subscriber** (ADR 0005): it reacts
after a transition has committed and a delivery failure never propagates back to
the lifecycle. The terminal-outcome notifications (#5) cover:

* ``request.denied`` → Requester + Endorsing Approvers
* ``action.succeeded`` (published) → Requester + Endorsing Approvers
* ``action.failed`` → Requester + Endorsing Approvers
* ``grant.activated`` (forward-auth access) → Requester + Endorsing Approvers

An **Endorsing Approver** is an approver whose *effective* vote is ``approve`` —
they put their name on the request, so they learn how it ended (an approver who
denied or withdrew does not). Recipients are resolved from the persisted vote
record, not from the best-effort notification itself.

SMTP is the one boundary the test suite does **not** mock; these messages are
sent with the stdlib :mod:`smtplib` (sync, matching the threadpool DB posture)
against a real server. Login/STARTTLS are attempted only when configured and the
server advertises them, so a local no-auth dev server works unchanged.
"""

from __future__ import annotations

import logging
import smtplib
import uuid
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import votes
from msig_proxy.core.config import AppConfig, EmailConfig
from msig_proxy.core.models import (
    APPROVE,
    ONE_TIME,
    ApprovalRequest,
    ApprovalRequestApprover,
    User,
)

_log = logging.getLogger(__name__)


def endorsing_approvers(session: Session, request: ApprovalRequest) -> list[User]:
    """Users whose *effective* vote on the request is ``approve``."""
    effective = votes.effective_votes(votes.votes_for(session, request.id))
    endorser_ids = [uid for uid, decision in effective.items() if decision == APPROVE]
    return [user for user in (session.get(User, uid) for uid in endorser_ids) if user is not None]


def snapshot_approvers(session: Session, request: ApprovalRequest) -> list[User]:
    """The request's **eligible approver set** — the exact set snapshotted at
    creation (ADR 0008), in first-seen order. This is the ``request.created``
    audience: approvers who do not yet know the request exists."""
    ids = session.scalars(
        select(ApprovalRequestApprover.user_id).where(
            ApprovalRequestApprover.approval_request_id == request.id
        )
    ).all()
    return [user for user in (session.get(User, uid) for uid in ids) if user is not None]


def _requester(session: Session, requester_id: uuid.UUID) -> User | None:
    return session.get(User, requester_id)


def send_email(config: EmailConfig, *, to: list[str], subject: str, body: str) -> bool:
    """Send one email, returning whether it was delivered. Never raises.

    A failure is logged and swallowed (best-effort, ADR 0005). With no recipients
    or ``enabled: false`` this is a silent no-op.
    """
    if not config.enabled or not to:
        return False

    message = EmailMessage()
    message["From"] = config.from_address
    message["To"] = ", ".join(to)
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as server:
            if config.tls and server.has_extn("starttls"):
                server.starttls()
            if config.smtp_user and config.smtp_password and server.has_extn("auth"):
                server.login(config.smtp_user, config.smtp_password)
            server.send_message(message)
    except OSError, smtplib.SMTPException:  # delivery is best-effort; do not block
        _log.warning("notification email delivery failed", exc_info=True)
        return False
    return True


def notify_outcome(
    session: Session,
    config: EmailConfig | None,
    request: ApprovalRequest,
    *,
    subject: str,
    body: str,
) -> None:
    """Notify the Requester and Endorsing Approvers of a terminal outcome.

    A no-op when email is unconfigured. Recipients are de-duplicated (a requester
    who is also an endorsing approver is mailed once).
    """
    if config is None:
        return

    recipients: list[str] = []
    requester = _requester(session, request.requester_id)
    if requester is not None:
        recipients.append(requester.email)
    for approver in endorsing_approvers(session, request):
        if approver.email not in recipients:
            recipients.append(approver.email)

    send_email(config, to=recipients, subject=subject, body=body)


def _approval_link(base_url: str, request_id: uuid.UUID) -> str:
    return f"{base_url.rstrip('/')}/approve/{request_id}"


def _created_summary(session: Session, request: ApprovalRequest) -> str:
    """One-line 'who wants what' for the solicitation body."""
    requester = _requester(session, request.requester_id)
    who = requester.username if requester is not None else "a user"
    if request.service_type == ONE_TIME and request.package_name:
        what = f"publish {request.package_name} {request.package_version}"
    else:
        what = f"access to {request.service_name}"
    return f"Requested by {who}: {what}"


def notify_request_created(session: Session, config: AppConfig, request: ApprovalRequest) -> None:
    """Email every snapshot Approver the Approval Link — *a request needs your vote*.

    The ``request.created`` default subscription (``docs/notification-system.md``):
    the full eligible/snapshot approver set, for **both** service types, never
    suppressed — it is the pull that brings approvers to the approve/deny page.
    Best-effort (ADR 0005): **one message per Approver**, each send logged and
    dropped on failure, never blocking or rolling back the lifecycle (``send_email``
    cannot raise). A no-op when email is unconfigured.

    Reachability anchors to the (critically-written) Approval Request record, not
    to this best-effort send: the Approval Link is derivable from the persisted
    request, so a dropped email is recoverable (the portal surfaces it via the
    fallback link).
    """
    email = config.notifications.email if config.notifications else None
    if email is None:
        return

    link = _approval_link(config.server.base_url, request.id)
    summary = _created_summary(session, request)
    subject = f"Approval needed: {request.service_name}"
    body = (
        "A request needs your vote.\n\n"
        f"Service: {request.service_name}\n"
        f"{summary}\n\n"
        f"Review it and approve or deny:\n{link}\n"
    )
    for approver in snapshot_approvers(session, request):
        send_email(email, to=[approver.email], subject=subject, body=body)


def notify_enrollment_issued(config: AppConfig, *, user: User, enroll_url: str) -> bool:
    """Email a newly-created User their single-use enrollment link (#15).

    The ``account.enrollment_issued`` default subscription
    (``docs/notification-system.md``): the affected User. Best-effort — a failed
    send is logged and dropped. **Returns whether the email was delivered** so the
    Admin Portal can surface the link as a fallback when SMTP is down (#17); the
    link is anyway recoverable by regenerating it. ``False`` when email is unconfigured.
    """
    email = config.notifications.email if config.notifications else None
    if email is None:
        return False
    return send_email(
        email,
        to=[user.email],
        subject="Set up your proxy account",
        body=(
            "An account has been created for you.\n\n"
            "Set your password and two-factor authentication here (single-use, expiring):\n"
            f"{enroll_url}\n"
        ),
    )
