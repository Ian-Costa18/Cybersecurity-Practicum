"""proxy sessions (server-side, revocable browser sessions)

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-19

Phase 1 #9: the server-side Proxy Session backing the signed ``session_id``
cookie. Deleting a row revokes the session immediately. Mirrors
:class:`msig_proxy.core.models.ProxySession`.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "proxy_sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_proxy_sessions_user_id", "proxy_sessions", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_proxy_sessions_user_id", table_name="proxy_sessions")
    op.drop_table("proxy_sessions")
