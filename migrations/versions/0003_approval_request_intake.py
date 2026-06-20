"""approval request intake (upload + hash binding + request creation)

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-18

Phase 0 issue #3: the one-time upload path's persistence. An Approval Request is
created ``pending`` with its eligible-approver set and quorum snapshotted at
creation (ADR 0008) and the artifact's SHA-256 bound (Hash Binding,
``docs/constraints.md`` §6); the uploaded bytes are staged for the Executor to
re-verify and destroy later. Mirrors :class:`msig_proxy.core.models.ApprovalRequest`,
``ApprovalRequestApprover``, and ``StagedArtifact``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("requester_id", sa.Uuid(), nullable=False),
        sa.Column("service_name", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("quorum", sa.Integer(), nullable=False),
        sa.Column("artifact_sha256", sa.String(), nullable=False),
        sa.Column("package_name", sa.String(), nullable=False),
        sa.Column("package_version", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["requester_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_approval_requests_requester_id", "approval_requests", ["requester_id"])
    op.create_index("ix_approval_requests_state", "approval_requests", ["state"])

    op.create_table(
        "approval_request_approvers",
        sa.Column("approval_request_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["approval_request_id"], ["approval_requests.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("approval_request_id", "user_id"),
    )

    op.create_table(
        "staged_artifacts",
        sa.Column("approval_request_id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_request_id"], ["approval_requests.id"]),
        sa.PrimaryKeyConstraint("approval_request_id"),
    )


def downgrade() -> None:
    op.drop_table("staged_artifacts")
    op.drop_table("approval_request_approvers")
    op.drop_index("ix_approval_requests_state", table_name="approval_requests")
    op.drop_index("ix_approval_requests_requester_id", table_name="approval_requests")
    op.drop_table("approval_requests")
