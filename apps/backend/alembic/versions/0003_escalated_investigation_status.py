"""Persist escalated investigation status separately from under review.

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(
                "open", "in_progress", "closed",
                name="investigationstatus", native_enum=False, length=16,
            ),
            type_=sa.Enum(
                "open", "in_progress", "escalated", "closed",
                name="investigationstatus", native_enum=False, length=16,
            ),
            existing_nullable=False,
        )


def downgrade() -> None:
    op.execute("UPDATE investigations SET status = 'in_progress' WHERE status = 'escalated'")
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(
                "open", "in_progress", "escalated", "closed",
                name="investigationstatus", native_enum=False, length=16,
            ),
            type_=sa.Enum(
                "open", "in_progress", "closed",
                name="investigationstatus", native_enum=False, length=16,
            ),
            existing_nullable=False,
        )
