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

from msig_proxy.approvals import snapshot, votes
from msig_proxy.approvals.snapshot import UnknownApproverError, resolve_approvers
from msig_proxy.core import urls
from msig_proxy.core.config import AppConfig, EmailConfig
from msig_proxy.core.models import (
    ONE_TIME,
    ApprovalRequest,
    User,
)

_log = logging.getLogger(__name__)

# Delivery errors swallowed best-effort (ADR 0005): connection/socket failures
# surface as OSError, SMTP protocol failures as SMTPException. Held as a named
# tuple rather than an inline ``except (OSError, smtplib.SMTPException):`` because
# ruff format (0.15.18) strips the parens, re-introducing the invalid Python-2
# ``except OSError, smtplib.SMTPException:`` syntax; a named constant is stable.
_DELIVERY_ERRORS = (OSError, smtplib.SMTPException)


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
    except _DELIVERY_ERRORS:  # delivery is best-effort; do not block
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
    for approver in votes.endorsing_approvers(session, request):
        if approver.email not in recipients:
            recipients.append(approver.email)

    send_email(config, to=recipients, subject=subject, body=body)


def notify_requester(
    session: Session,
    config: EmailConfig | None,
    request: ApprovalRequest,
    *,
    subject: str,
    body: str,
) -> None:
    """Notify **only the Requester** of an outcome (no endorsing approvers).

    The recipient profile for ``request.approved`` (``docs/notification-system.md``
    §Default subscriptions): the Requester alone is told their request was approved —
    distinct from the terminal-outcome rows that also copy the Endorsing Approvers. A
    no-op when email is unconfigured or the requester cannot be resolved.
    """
    if config is None:
        return
    requester = _requester(session, request.requester_id)
    if requester is None:
        return
    send_email(config, to=[requester.email], subject=subject, body=body)


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

    link = urls.approval_link(config.server.base_url, request.id)
    summary = _created_summary(session, request)
    subject = f"Approval needed: {request.service_name}"
    body = (
        "A request needs your vote.\n\n"
        f"Service: {request.service_name}\n"
        f"{summary}\n\n"
        f"Review it and approve or deny:\n{link}\n"
    )
    for approver in snapshot.snapshot_approvers(session, request):
        send_email(email, to=[approver.email], subject=subject, body=body)


def _out_of_band_recipients(session: Session, config: AppConfig, service_name: str) -> list[str]:
    """Resolve the out-of-band-alert audience: every admin plus the service's approvers.

    A proxy bypass is a security event the people who govern publishing must see, so
    the audience is the union of all active **admins** and the service's configured
    **approvers** (glob-expanded against live users, like the request snapshot). No
    Requester or Endorsing-Approver notion applies — the rogue release never had a
    request. De-duplicated in first-seen order (admins first). A configured approver
    with no account is tolerated here (logged, skipped): a security alert must still
    reach everyone else rather than fail because the topology drifted.
    """
    recipients: list[str] = []
    admins = session.scalars(
        select(User).where(User.is_admin.is_(True), User.is_active.is_(True))
    ).all()
    for admin in admins:
        if admin.email not in recipients:
            recipients.append(admin.email)

    service = config.services.get(service_name)
    if service is not None:
        try:
            approvers = resolve_approvers(session, service.approvers)
        except UnknownApproverError:
            _log.warning(
                "out-of-band alert: unresolved approver in %s", service_name, exc_info=True
            )
            approvers = []
        for approver in approvers:
            if approver.email not in recipients:
                recipients.append(approver.email)
    return recipients


def notify_out_of_band_publish(
    session: Session,
    config: AppConfig,
    *,
    service_name: str,
    project: str,
    version: str,
) -> None:
    """Alert approvers + admins that a release appeared on PyPI the proxy never published.

    The PUB-2 detection defense (#124): a release on the index with no matching entry
    in the proxy's publish log is an exclusivity violation — a publish that bypassed
    m-of-n approval. This message is the alert leg of that detection; the durable
    record is the audit trail's ``publish.out_of_band_detected`` row. Best-effort and
    a no-op when email is unconfigured. The body points at the operator runbook —
    detection bounds the exposure window, it cannot un-ship the artifact.
    """
    email = config.notifications.email if config.notifications else None
    if email is None:
        return
    recipients = _out_of_band_recipients(session, config, service_name)
    send_email(
        email,
        to=recipients,
        subject=f"Out-of-band publish detected: {project} {version}",
        body=(
            f"A release appeared on the package index that the proxy never published:\n\n"
            f"  Project: {project}\n"
            f"  Version: {version}\n"
            f"  Service: {service_name}\n\n"
            "This means a publish reached the index without m-of-n approval — a "
            "credential outside the proxy can publish directly (threat PUB-2, proxy "
            "bypass).\n\n"
            "Detection bounds the exposure window; it cannot un-ship the artifact. "
            "Respond by hand: yank/delete the release via the PyPI web UI, rotate the "
            "project's credentials, and audit the collaborator and API-token list for "
            "any credential able to publish without the proxy.\n"
        ),
    )


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


def notify_enrollment_completed(config: AppConfig, *, user: User) -> bool:
    """Tell the registered address that their account's enrollment just completed (#128).

    The ``account.enrollment_completed`` default subscription
    (``docs/notification-system.md`` §Account events): the affected User. This is
    leg (b) of the IDENT-2 detection defense — if an enrollment-link interceptor
    enrolled first, the *real* approver's inbox receives this notice and the
    takeover surfaces before the admin ever activates the seat. Informational: no
    link, grants no capability. It rides the same channel IDENT-2 assumes may be
    compromised, so it supplements (never replaces) the admin-gated activation.
    Best-effort; ``False`` when email is unconfigured.
    """
    email = config.notifications.email if config.notifications else None
    if email is None:
        return False
    return send_email(
        email,
        to=[user.email],
        subject="An account was enrolled for you",
        body=(
            f"Enrollment was just completed for the proxy account '{user.username}' "
            "registered to this address.\n\n"
            "If this wasn't you, contact your administrator immediately — do not "
            "ignore this message. The account cannot act until an administrator "
            "activates it.\n\n"
            "If this was you, no action is needed: your administrator will activate "
            "the account after confirming with you.\n"
        ),
    )


def notify_credentials_reset(config: AppConfig, *, user: User, enroll_url: str) -> bool:
    """Email a User a fresh enrollment link after an admin reset their credentials (#80).

    The ``account.credentials_reset`` default subscription
    (``docs/notification-system.md`` §Account events): the affected User, carrying a
    fresh enrollment link (a reset *is* a re-enrollment). Best-effort and returns
    whether delivery succeeded so the Admin Portal can surface the link as a fallback;
    the link is anyway recoverable by regenerating it. ``False`` when email is unconfigured.
    """
    email = config.notifications.email if config.notifications else None
    if email is None:
        return False
    return send_email(
        email,
        to=[user.email],
        subject="Your proxy credentials were reset",
        body=(
            "An administrator has reset your account credentials.\n\n"
            "Set a new password and two-factor authentication here (single-use, expiring):\n"
            f"{enroll_url}\n"
        ),
    )


def notify_account_deactivated(config: AppConfig, *, user: User) -> bool:
    """Email a User that their account was deactivated (#80) — informational, no link.

    The ``account.deactivated`` default subscription (``docs/notification-system.md``
    §Account events): the affected User, a "contact your admin" message that carries
    no link and grants no capability. Best-effort; ``False`` when email is unconfigured.
    """
    email = config.notifications.email if config.notifications else None
    if email is None:
        return False
    return send_email(
        email,
        to=[user.email],
        subject="Your proxy account has been deactivated",
        body=(
            "Your account has been deactivated. Contact your administrator if this is unexpected.\n"
        ),
    )


def notify_account_deleted(config: AppConfig, *, user: User) -> bool:
    """Email a User that their account was deleted (#80) — informational, no link.

    The ``account.deleted`` default subscription (``docs/notification-system.md``
    §Account events): the affected User, a "contact your admin" message that carries
    no link and grants no capability. Best-effort; ``False`` when email is unconfigured.
    """
    email = config.notifications.email if config.notifications else None
    if email is None:
        return False
    return send_email(
        email,
        to=[user.email],
        subject="Your proxy account has been deleted",
        body=("Your account has been deleted. Contact your administrator if this is unexpected.\n"),
    )
