"""signed votes (append-only vote log + per-vote signed audit record)

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-18

Phase 0 issue #4: the approval core's persistence. Each Vote on an Approval
Request is recorded append-only (ADR 0009) with the Ed25519 signature over its
canonical approval record; the integer ``id`` is the supersession sequence
(latest per approver = effective vote). Mirrors :class:`msig_proxy.core.models.Vote`.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "votes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("approval_request_id", sa.Uuid(), nullable=False),
        sa.Column("approver_id", sa.Uuid(), nullable=False),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("action_hash", sa.String(), nullable=False),
        sa.Column("signed_at", sa.String(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_request_id"], ["approval_requests.id"]),
        sa.ForeignKeyConstraint(["approver_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_votes_approval_request_id", "votes", ["approval_request_id"])
    op.create_index("ix_votes_approver_id", "votes", ["approver_id"])


def downgrade() -> None:
    op.drop_index("ix_votes_approver_id", table_name="votes")
    op.drop_index("ix_votes_approval_request_id", table_name="votes")
    op.drop_table("votes")
