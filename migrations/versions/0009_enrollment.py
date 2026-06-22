"""enrollment tokens + nullable user credentials (keypair at enrollment)

Revision ID: 0009
Revises: 0008
Create Date: 2026-06-19

Phase 2 #2 (#15): admin-created accounts exist with **no credentials** until the
enrollee self-enrolls. Makes the ``users`` credential columns nullable and adds
the single-use, expiring ``enrollment_tokens`` table. Mirrors
:class:`msig_proxy.core.models.User` / :class:`msig_proxy.core.models.EnrollmentToken`.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_enrollment_tokens_user_id", "enrollment_tokens", ["user_id"])
    op.create_index("ix_enrollment_tokens_token_hash", "enrollment_tokens", ["token_hash"])

    # SQLite can't ALTER COLUMN in place — batch rebuilds the table (see 0005, 0007).
    with op.batch_alter_table("users") as batch:
        batch.alter_column("password_hash", existing_type=sa.String(), nullable=True)
        batch.alter_column("public_key", existing_type=sa.LargeBinary(), nullable=True)
        batch.alter_column("encrypted_private_key", existing_type=sa.LargeBinary(), nullable=True)
        batch.alter_column("key_salt", existing_type=sa.LargeBinary(), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.alter_column("key_salt", existing_type=sa.LargeBinary(), nullable=False)
        batch.alter_column("encrypted_private_key", existing_type=sa.LargeBinary(), nullable=False)
        batch.alter_column("public_key", existing_type=sa.LargeBinary(), nullable=False)
        batch.alter_column("password_hash", existing_type=sa.String(), nullable=False)

    op.drop_index("ix_enrollment_tokens_token_hash", table_name="enrollment_tokens")
    op.drop_index("ix_enrollment_tokens_user_id", table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")
