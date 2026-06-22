"""add the nullable approval_requests.denial_reason column

Revision ID: 0013
Revises: 0012
Create Date: 2026-06-22

Phase 2 #87: capture the optional free-text reason a denying Approver gives. It is
surfaced on the waiting room's denial screen and carried in the ``denied`` SSE frame
(``docs/web-proxy.md`` §Denial State + §Real-Time Updates). Nullable — null when no
reason was given or the request is not denied. Not part of the signed Vote record.
Mirrors :class:`msig_proxy.core.models.ApprovalRequest`.

No data backfill — same convention as 0008/0010/0011/0012: there is no production
data in the MVP.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("approval_requests", sa.Column("denial_reason", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("approval_requests", "denial_reason")
