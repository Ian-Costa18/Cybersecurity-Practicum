"""generalize approval request for forward-auth (service_type + nullable publish cols)

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-18

Phase 1 #8 prefactor: make the Approval Request able to *carry* a forward-auth
request before any forward-auth behavior exists. Adds the ``service_type``
discriminator (ADR 0007) and relaxes the publish-specific columns to nullable
(valid-only-when ``one-time``). No change to the existing publish path's behavior.
Mirrors :class:`msig_proxy.core.models.ApprovalRequest`.

Uses Alembic batch mode because SQLite cannot ``ALTER COLUMN`` in place — the
table is copied/recreated with the new shape.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PUBLISH_COLUMNS = ("action", "artifact_sha256", "package_name", "package_version")


def upgrade() -> None:
    with op.batch_alter_table("approval_requests") as batch:
        # Existing rows are publish requests — backfill them as one-time.
        batch.add_column(
            sa.Column("service_type", sa.String(), nullable=False, server_default="one-time")
        )
        for column in _PUBLISH_COLUMNS:
            batch.alter_column(column, existing_type=sa.String(), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("approval_requests") as batch:
        for column in _PUBLISH_COLUMNS:
            batch.alter_column(column, existing_type=sa.String(), nullable=False)
        batch.drop_column("service_type")
