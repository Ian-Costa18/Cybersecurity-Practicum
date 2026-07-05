"""The eligible-approver + quorum snapshot — the shared creation rule (ADR 0008).

Owned by ``approvals`` because approvals both *writes* this rule (the snapshot is
frozen onto the request at creation) and *reads* it (the Tally evaluates quorum
over the snapshotted approver set). Each service type's intake imports it at
creation time; ``approvals`` imports nothing from ``service_types`` in return.

Framework-free (`[pure]`): operates on a :class:`~sqlalchemy.orm.Session` and the
configured approver patterns, returning User rows or raising a domain error.
"""

from __future__ import annotations

import fnmatch
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.core.config import is_wildcard
from msig_proxy.core.models import ApprovalRequest, ApprovalRequestApprover, User


class UnknownApproverError(Exception):
    """A service lists a literal approver username with no corresponding User account.

    A configuration/provisioning fault: the snapshot would silently omit an
    intended approver (weakening quorum), so creation fails loudly instead. Only
    *literal* entries raise — a glob is allowed to match zero users.
    """


def resolve_approvers(session: Session, patterns: list[str]) -> list[User]:
    """Expand configured approver patterns to distinct User rows at snapshot time.

    Each entry is a literal username or a glob (``*`` = all users, ``admin_*`` =
    that prefix; fnmatch semantics, see :func:`msig_proxy.core.config.is_wildcard`).
    Literals must resolve — a missing one raises :class:`UnknownApproverError`
    rather than silently shrinking the eligible set — while a glob may match zero
    users (a forward-looking rule like "any admin" is valid before the first admin
    exists). Matches are de-duplicated and returned in first-seen order, since the
    snapshot keys on distinct user ids (ADR 0008).
    """
    users = session.scalars(select(User)).all()
    by_name = {user.username: user for user in users}

    resolved: dict[uuid.UUID, User] = {}
    missing: list[str] = []
    for pattern in patterns:
        if is_wildcard(pattern):
            for user in users:
                if fnmatch.fnmatchcase(user.username, pattern):
                    resolved.setdefault(user.id, user)
        elif pattern in by_name:
            resolved.setdefault(by_name[pattern].id, by_name[pattern])
        else:
            missing.append(pattern)

    if missing:
        raise UnknownApproverError(f"no User account for configured approver(s): {missing}")
    return list(resolved.values())


def persist_request_with_snapshot(
    session: Session, request: ApprovalRequest, approvers: list[User]
) -> ApprovalRequest:
    """Persist a built :class:`ApprovalRequest` together with its approver-snapshot rows.

    Adds the request and flushes to allocate ``request.id`` (so the snapshot foreign
    keys resolve), then writes one :class:`ApprovalRequestApprover` per resolved
    approver (ADR 0008), in the given order. Owned by ``approvals`` because it owns
    the snapshot; each service-type intake builds the request and resolves the approver
    set (:func:`resolve_approvers`) then calls this, layering any type-specific
    persistence (the one-time artifact) on top. Flushes, never commits — the caller's
    session scope owns the commit.

    Since #121 each snapshot row also **freezes the approver's active signing key**
    (``key_id`` + ``public_key``) so the execution-time re-check verifies Votes against
    this anchor rather than the live ``user_keys`` column — closing the HOST-2
    public-key-substitution gap. An eligible approver with no active key yet
    (unenrolled) freezes nulls; they cannot vote until they enroll anyway.
    """
    session.add(request)
    session.flush()  # allocate request.id for the snapshot links
    for approver in approvers:
        active = keys.active_key(session, approver)
        session.add(
            ApprovalRequestApprover(
                approval_request_id=request.id,
                user_id=approver.id,
                key_id=active.id if active is not None else None,
                public_key=active.public_key if active is not None else None,
            )
        )
    session.flush()
    return request


def snapshot_approvers(session: Session, request: ApprovalRequest) -> list[User]:
    """The request's **eligible approver set** — the exact set snapshotted at creation
    (ADR 0008), in first-seen order.

    The ``request.created`` solicitation audience: the approvers who do not yet know
    the request exists. Owned here because ``approvals`` owns the snapshot (this reads
    back what :func:`resolve_approvers` froze onto the request at creation); the
    notification subscriber consumes it instead of querying the snapshot table itself.
    """
    ids = session.scalars(
        select(ApprovalRequestApprover.user_id).where(
            ApprovalRequestApprover.approval_request_id == request.id
        )
    ).all()
    return [user for user in (session.get(User, uid) for uid in ids) if user is not None]
