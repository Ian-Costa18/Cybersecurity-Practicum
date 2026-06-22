"""service grants (forward-auth post-approval object) + request forward pointer

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-19

Phase 1 #11: the forward-auth handoff. A Service Grant is created on the
``pending -> approved`` transition for a forward-auth request (ADR 0007). The
unique ``approval_request_id`` makes a redelivered ``request.approved`` a no-op;
the Approval Request carries the matching forward pointer (``service_grant_id``).
Mirrors :class:`msig_proxy.core.models.ServiceGrant`.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("approval_request_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("service_name", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_request_id"], ["approval_requests.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("approval_request_id"),
    )
    op.create_index("ix_service_grants_user_id", "service_grants", ["user_id"])
    op.create_index("ix_service_grants_service_name", "service_grants", ["service_name"])

    with op.batch_alter_table("approval_requests") as batch:
        batch.add_column(sa.Column("service_grant_id", sa.Uuid(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("approval_requests") as batch:
        batch.drop_column("service_grant_id")

    op.drop_index("ix_service_grants_service_name", table_name="service_grants")
    op.drop_index("ix_service_grants_user_id", table_name="service_grants")
    op.drop_table("service_grants")
