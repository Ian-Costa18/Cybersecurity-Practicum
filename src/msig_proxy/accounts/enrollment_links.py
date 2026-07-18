"""Minting a single-use enrollment link — the shared account-lifecycle operation.

Creating a user (admin-initiated via the Admin Portal, or config-driven via the
declarative provision step, #100) and resetting credentials all need the *same*
move: persist a fresh single-use :class:`~msig_proxy.core.models.EnrollmentToken`,
emit the matching ``account.*`` event, and send the link by SMTP (portal-fallback
when delivery fails). Concentrating it here keeps that security-sensitive flow in
one place rather than re-derived at each call site, and keeps it **framework-free**
so the bootstrap provision command can reuse it without importing the web edge
(``docs/source-layout.md`` dependency rule).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import delete
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult

from msig_proxy.core import crypto, events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.events import EventBus
from msig_proxy.core.models import EnrollmentToken, User
from msig_proxy.core.urls import enrollment_link
from msig_proxy.notifications import notifier


def void_open_enrollment_links(session: Session, user: User) -> int:
    """Invalidate every outstanding (unconsumed) enrollment link for ``user``.

    At most one enrollment link is live per user: minting a fresh one voids its
    predecessors, and deactivate/delete void without replacement — otherwise an
    intercepted old link would survive the admin's remediation, and could even
    re-activate a deactivated or deleted account (enrollment sets
    ``is_active = True``). ``docs/account-management.md`` §Admin Portal
    Capabilities. Returns the number of links voided.
    """
    result = cast(
        "CursorResult[Any]",
        session.execute(
            delete(EnrollmentToken).where(
                EnrollmentToken.user_id == user.id, EnrollmentToken.consumed_at.is_(None)
            )
        ),
    )
    return result.rowcount


def mint_enrollment_link(
    session: Session,
    config: AppConfig,
    user: User,
    *,
    bus: EventBus,
    reset: bool = False,
    actor_id: uuid.UUID | None = None,
) -> tuple[str, bool]:
    """Create a fresh single-use enrollment token for ``user`` and email the link.

    Shared by admin create / reset / regenerate (``docs/account-management.md``
    §Admin Portal Capabilities) and by config-driven provisioning (#100). Returns
    ``(enroll_url, email_delivered)`` — the URL is the SMTP-down fallback
    (recoverable even when delivery fails).

    ``reset`` selects the account event + message: a credentials reset emits
    ``account.credentials_reset`` and sends the reset-flavored mail, while create and
    regenerate emit ``account.enrollment_issued`` and send the welcome mail. Both
    carry the same single-use link (a reset *is* a re-enrollment;
    ``docs/account-management.md`` §Account Events).

    ``actor_id`` is the acting admin recorded on the resulting audit row (#121); it is
    ``None`` for config-driven provisioning, which has no admin actor.

    Minting voids the user's outstanding links first — the fresh link is the only
    live one, so regenerating after a suspected interception is a real remediation.
    """
    void_open_enrollment_links(session, user)
    token = crypto.generate_enrollment_token()
    now = datetime.now(UTC)
    session.add(
        EnrollmentToken(
            user_id=user.id,
            token_hash=crypto.hash_enrollment_token(token),
            expires_at=now + timedelta(hours=config.auth.enrollment_link_expiry_hours),
            created_at=now,
        )
    )
    session.flush()
    enroll_url = enrollment_link(config.server.base_url, token)
    event: events.Event = (
        events.CredentialsReset(user_id=user.id, email=user.email, actor_id=actor_id)
        if reset
        else events.EnrollmentIssued(user_id=user.id, email=user.email, actor_id=actor_id)
    )
    bus.emit(event)
    if reset:
        delivered = notifier.notify_credentials_reset(config, user=user, enroll_url=enroll_url)
    else:
        delivered = notifier.notify_enrollment_issued(config, user=user, enroll_url=enroll_url)
    return enroll_url, delivered
