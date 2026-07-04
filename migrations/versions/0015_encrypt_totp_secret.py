"""wrap the TOTP secret at rest under the password-derived key

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-04

Issue #122 / threat-model HOST-3: the TOTP secret was the one credential stored in
the clear at rest. It is now AES-256-GCM-wrapped under ``PBKDF2(password, totp_salt)``
and bound to the ``User.id`` as AAD — the same wrap the Ed25519 signing key already
has — so a database read yields ciphertext, not a working second factor
(``docs/threat-model/HOST-3-database-read-compromise.md``, ``docs/cryptography.md``).

Two schema changes on ``users``, mirroring :class:`msig_proxy.core.models.User`:

* ``totp_secret`` changes type ``String`` → ``LargeBinary`` — it now holds the
  ``iv ‖ ciphertext ‖ tag`` blob rather than the base32 plaintext.
* a new nullable ``totp_salt`` (``LargeBinary``) holds the per-secret 128-bit PBKDF2
  salt (its own salt, not the signing key's, so the verifier reads only the User row).

No data backfill — same convention as 0008/0010/0011/0012: there is no production data
in the MVP, and the plaintext-to-ciphertext transition has no in-place re-encryption
path (a plaintext secret has no password to wrap it with). Both columns stay nullable:
an admin-created account has no TOTP until enrollment sets both together.

SQLite needs a table rebuild to change a column type, so both changes go through one
``batch_alter_table`` block (``render_as_batch`` is also set in ``env.py``).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_salt", sa.LargeBinary(), nullable=True))
        batch_op.alter_column(
            "totp_secret",
            existing_type=sa.String(),
            type_=sa.LargeBinary(),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "totp_secret",
            existing_type=sa.LargeBinary(),
            type_=sa.String(),
            existing_nullable=True,
        )
        batch_op.drop_column("totp_salt")
