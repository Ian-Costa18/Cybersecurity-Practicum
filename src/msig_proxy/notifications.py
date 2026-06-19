"""Best-effort outcome notifications over SMTP (``docs/notification-system.md``).

The notification system is a **best-effort subscriber** (ADR 0005): it reacts
after a transition has committed and a delivery failure never propagates back to
the lifecycle. Phase 0 #5 needs the terminal-outcome slice of the matrix:

* ``request.denied`` → Requester + Endorsing Approvers
* ``action.succeeded`` (published) → Requester + Endorsing Approvers
* ``action.failed`` → Requester + Endorsing Approvers

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

from sqlalchemy.orm import Session

from msig_proxy import votes
from msig_proxy.config import EmailConfig
from msig_proxy.models import APPROVE, ApprovalRequest, User

_log = logging.getLogger(__name__)


def endorsing_approvers(session: Session, request: ApprovalRequest) -> list[User]:
    """Users whose *effective* vote on the request is ``approve``."""
    effective = votes.effective_votes(votes.votes_for(session, request.id))
    endorser_ids = [uid for uid, decision in effective.items() if decision == APPROVE]
    return [user for user in (session.get(User, uid) for uid in endorser_ids) if user is not None]


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
