"""add the audit_log table (records every emitted event)

Revision ID: 0014
Revises: 0013
Create Date: 2026-06-22

Phase 2 #85: the critical Audit consumer records one row per emitted event
(``request.*`` / ``action.*`` / ``grant.*`` / ``account.*`` / ``artifact.destroyed``),
the non-vote half of the audit trail (``docs/architecture.md`` §"What each box is
responsible for"). The per-Vote Ed25519 signature in ``votes`` is the tamper-evident
half; this table is per-record evidence only — no hash chain in the MVP. Mirrors
:class:`msig_proxy.core.models.AuditLog`.

The integer ``id`` is the append sequence. No data backfill — same convention as the
other Phase 2 migrations: the trail starts empty.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_name", sa.String(), nullable=False),
        sa.Column("payload", sa.String(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_event_name", "audit_log", ["event_name"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_event_name", table_name="audit_log")
    op.drop_table("audit_log")
