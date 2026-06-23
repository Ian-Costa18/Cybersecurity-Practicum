"""API-token domain logic shared across the account/admin web edges.

Framework-free (`[pure]`): operates on a :class:`~sqlalchemy.orm.Session` and an
:class:`~msig_proxy.core.models.ApiToken`. Each web edge owns its own lookup and
authorization (the Admin Portal acts on any token; the User Portal acts on the
caller's own) and its own HTTP-response shaping; the idempotent revoke mutation
lives here, once.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from msig_proxy.core.models import ApiToken


def revoke(session: Session, token: ApiToken) -> None:
    """Idempotently revoke an API token: stamp ``revoked_at`` if unset, then flush.

    A no-op for an already-revoked token — the original ``revoked_at`` is never
    overwritten. Flushes within the caller's transaction; the caller commits.
    """
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
        session.flush()
