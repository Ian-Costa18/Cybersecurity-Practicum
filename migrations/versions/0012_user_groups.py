"""add the nullable users.groups column

Revision ID: 0012
Revises: 0011
Create Date: 2026-06-22

Phase 2 #79: model group membership on the User. ``groups`` is free text injected
verbatim as the ``Remote-Groups`` header on forward-auth success
(``docs/account-management.md`` §Users table, ``docs/web-proxy.md`` §Identity
Headers); the proxy does not interpret it. Nullable — a User with no groups set has
the header omitted entirely. Mirrors :class:`msig_proxy.core.models.User`.

No data backfill — same convention as 0008/0010/0011: there is no production data in
the MVP, and an existing User simply has ``groups`` null (no header) until edited.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("groups", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "groups")
