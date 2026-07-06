"""Offline verification of the audit-trail hash chain (#121).

The companion to :mod:`msig_proxy.audit.subscriber`: the subscriber *writes* the
HMAC-SHA-256 chain, this module *checks* it. Walking the rows in append (``id``)
order, it re-derives each row's ``entry_hash`` under the same HKDF-derived audit key
and confirms two things per row: the row's ``prev_hash`` still points at the actual
predecessor's ``entry_hash`` (breaks on **deletion / reordering** of whole rows), and
the stored ``entry_hash`` re-computes from the row's content (breaks on
**modification** of a row). A HOST-2 database-write attacker cannot repair either
break without the host secret the key derives from (``docs/cryptography.md`` §Audit
Trail Integrity).

Framework-free (`[pure]`): a :class:`~sqlalchemy.orm.Session` in, a verdict out — no
FastAPI, so an offline audit tool or a test can drive it directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.core import crypto
from msig_proxy.core.models import AuditLog
from msig_proxy.core.time import aware


@dataclass(frozen=True)
class ChainVerification:
    """The verdict of an audit-chain walk (#121).

    ``ok`` is the headline oracle. On a break, ``broken_at`` is the ``id`` of the
    first row whose link fails and ``reason`` says which invariant broke, so an
    operator learns *where* and *how* the trail was tampered.
    """

    ok: bool
    broken_at: int | None = None
    reason: str | None = None


def verify_audit_chain(session: Session, *, audit_key: bytes) -> ChainVerification:
    """Verify the audit-log hash chain end to end (#121).

    Returns ``ChainVerification(ok=True)`` for an intact trail (including the empty
    trail, which is vacuously intact). On the first broken link it returns ``ok=False``
    with the offending row id and a reason — a *modified* row (``entry_hash`` no longer
    recomputes) or a *deleted / reordered* row (``prev_hash`` no longer matches the
    actual predecessor).
    """
    rows = session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    prev_hash = crypto.AUDIT_GENESIS
    for row in rows:
        if row.prev_hash != prev_hash:
            return ChainVerification(
                ok=False,
                broken_at=row.id,
                reason="prev_hash does not match the predecessor — a row was deleted or reordered",
            )
        expected = crypto.audit_chain_hash(
            audit_key,
            prev_hash=prev_hash,
            event_name=row.event_name,
            payload=row.payload,
            recorded_at=aware(row.recorded_at).isoformat(),
            actor_id=str(row.actor_id) if row.actor_id is not None else None,
        )
        if row.entry_hash != expected:
            return ChainVerification(
                ok=False,
                broken_at=row.id,
                reason="entry_hash does not recompute — the row was modified",
            )
        # Chain forward on the recomputed digest: it equals the (verified) stored
        # ``entry_hash`` but is statically ``bytes``, never the column's ``bytes | None``.
        prev_hash = expected
    return ChainVerification(ok=True)
