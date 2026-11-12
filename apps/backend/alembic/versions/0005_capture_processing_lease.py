"""Add renewable ownership leases for capture processing.

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa

import app.database.types


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("captures", sa.Column("processing_token", sa.String(length=36), nullable=True))
    op.add_column(
        "captures",
        sa.Column("processing_lease_expires_at", app.database.types.UTCDateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("captures", "processing_lease_expires_at")
    op.drop_column("captures", "processing_token")
