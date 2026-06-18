"""initial baseline (no domain tables yet)

Revision ID: 0001
Revises:
Create Date: 2026-06-18

Phase 0 has no domain tables. This baseline establishes the migration chain so
later phases add their tables on a clean, versioned foundation, and it gives the
test harness a real ``alembic upgrade head`` to assert applies cleanly.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
