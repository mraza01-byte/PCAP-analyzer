"""persist packet analysis output

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-10
"""
from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("investigations", sa.Column("severity", sa.String(length=16), server_default="medium", nullable=False))
    op.add_column("investigations", sa.Column("lead_analyst", sa.String(length=255), server_default="", nullable=False))
    op.add_column("investigations", sa.Column("findings", sa.Text(), nullable=True))
    op.add_column("investigations", sa.Column("ioc_list", sa.Text(), nullable=True))
    op.add_column("captures", sa.Column("error_message", sa.String(length=2000), nullable=True))
    op.add_column("hosts", sa.Column("packet_count", sa.BigInteger(), server_default="0", nullable=False))
    op.add_column("hosts", sa.Column("bytes_sent", sa.BigInteger(), server_default="0", nullable=False))
    op.add_column("hosts", sa.Column("bytes_received", sa.BigInteger(), server_default="0", nullable=False))
    op.add_column("hosts", sa.Column("open_ports", sa.JSON(), server_default="[]", nullable=False))
    op.add_column("flows", sa.Column("bytes_forward", sa.BigInteger(), server_default="0", nullable=False))
    op.add_column("flows", sa.Column("bytes_reverse", sa.BigInteger(), server_default="0", nullable=False))
    op.add_column("flows", sa.Column("application", sa.String(length=32), server_default="", nullable=False))
    op.add_column("flows", sa.Column("tcp_flags", sa.String(length=32), server_default="-", nullable=False))


def downgrade() -> None:
    op.drop_column("flows", "tcp_flags")
    op.drop_column("flows", "application")
    op.drop_column("flows", "bytes_reverse")
    op.drop_column("flows", "bytes_forward")
    op.drop_column("hosts", "open_ports")
    op.drop_column("hosts", "bytes_received")
    op.drop_column("hosts", "bytes_sent")
    op.drop_column("hosts", "packet_count")
    op.drop_column("captures", "error_message")
    op.drop_column("investigations", "ioc_list")
    op.drop_column("investigations", "findings")
    op.drop_column("investigations", "lead_analyst")
    op.drop_column("investigations", "severity")