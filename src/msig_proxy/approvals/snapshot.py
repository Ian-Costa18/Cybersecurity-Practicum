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

from msig_proxy.core.config import is_wildcard
from msig_proxy.core.models import User


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
