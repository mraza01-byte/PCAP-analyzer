"""Prevent duplicate capture uploads across backend workers.

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    duplicate = connection.execute(
        sa.text(
            "SELECT sha256, COUNT(*) AS count FROM captures "
            "GROUP BY sha256 HAVING COUNT(*) > 1 LIMIT 1"
        )
    ).first()
    if duplicate:
        raise RuntimeError(
            "Cannot enforce unique capture SHA-256 values: existing duplicate "
            f"fingerprint {duplicate.sha256!r}. Resolve duplicate capture records before upgrading."
        )

    op.drop_index("ix_captures_sha256", table_name="captures")
    op.create_index("ix_captures_sha256", "captures", ["sha256"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_captures_sha256", table_name="captures")
    op.create_index("ix_captures_sha256", "captures", ["sha256"], unique=False)
