"""generalize users (flags + enrollment state) + normalize api_tokens

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-19

Phase 2 #1 (#14): structural prep for the self-service surfaces, no user-facing
behavior. Adds role/lifecycle flags (``is_admin``, ``is_active``), the Phase 2
second-factor secret (``totp_secret``), and enrollment state (``enrolled_at``) to
``users``; normalizes the single ``users.token_hash`` out into a one-to-many
``api_tokens`` table so a User can hold many labeled, individually-revocable
tokens. Mirrors :class:`msig_proxy.core.models.User` / :class:`msig_proxy.core.models.ApiToken`.

Note: ``users.token_hash`` is dropped without backfilling existing tokens into
``api_tokens`` — there is no production data in the MVP, so any seeded token is
simply re-issued (re-run ``python -m msig_proxy.seed``). New ``NOT NULL`` flags
carry a ``server_default`` so existing rows upgrade cleanly.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"])

    # SQLite can't ALTER COLUMN in place — batch rebuilds the table (see 0005, 0007).
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true())
        )
        batch.add_column(sa.Column("totp_secret", sa.String(), nullable=True))
        batch.add_column(sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True))
        batch.drop_column("token_hash")


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("token_hash", sa.String(), nullable=False, server_default=""))
        batch.drop_column("enrolled_at")
        batch.drop_column("totp_secret")
        batch.drop_column("is_active")
        batch.drop_column("is_admin")

    op.drop_index("ix_api_tokens_token_hash", table_name="api_tokens")
    op.drop_index("ix_api_tokens_user_id", table_name="api_tokens")
    op.drop_table("api_tokens")
