"""phase3 protocol extraction

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-12
"""
from alembic import op
import sqlalchemy as sa
import app.database.types


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "certificates",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("capture_id", sa.String(length=36), nullable=False),
        sa.Column("flow_id", sa.String(length=36), nullable=True),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("subject_cn", sa.String(length=255), nullable=True),
        sa.Column("subject_org", sa.String(length=255), nullable=True),
        sa.Column("issuer_cn", sa.String(length=255), nullable=True),
        sa.Column("issuer_org", sa.String(length=255), nullable=True),
        sa.Column("valid_from", app.database.types.UTCDateTime(timezone=True), nullable=True),
        sa.Column("valid_to", app.database.types.UTCDateTime(timezone=True), nullable=True),
        sa.Column("serial_number", sa.String(length=128), nullable=True),
        sa.Column("san_list", sa.Text(), nullable=True),
        sa.Column("is_self_signed", sa.Boolean(), nullable=False),
        sa.Column("created_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.Column("updated_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["captures.id"], name=op.f("fk_certificates_capture_id_captures"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.id"], name=op.f("fk_certificates_flow_id_flows"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_certificates")),
    )
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.create_index("ix_certificates_capture_id", ["capture_id"], unique=False)
        batch_op.create_index("ix_certificates_fingerprint_sha256", ["fingerprint_sha256"], unique=False)

    op.create_table(
        "dns_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("capture_id", sa.String(length=36), nullable=False),
        sa.Column("flow_id", sa.String(length=36), nullable=True),
        sa.Column("timestamp", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.Column("query_name", sa.String(length=255), nullable=False),
        sa.Column("query_type", sa.String(length=16), nullable=False),
        sa.Column("response_code", sa.String(length=16), nullable=True),
        sa.Column("answers", sa.Text(), nullable=True),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.Column("created_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.Column("updated_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["captures.id"], name=op.f("fk_dns_records_capture_id_captures"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.id"], name=op.f("fk_dns_records_flow_id_flows"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dns_records")),
    )
    with op.batch_alter_table("dns_records", schema=None) as batch_op:
        batch_op.create_index("ix_dns_records_capture_id", ["capture_id"], unique=False)
        batch_op.create_index("ix_dns_records_query_name", ["query_name"], unique=False)
        batch_op.create_index("ix_dns_records_timestamp", ["timestamp"], unique=False)

    op.create_table(
        "http_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("capture_id", sa.String(length=36), nullable=False),
        sa.Column("flow_id", sa.String(length=36), nullable=True),
        sa.Column("timestamp", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_phrase", sa.String(length=64), nullable=True),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("created_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.Column("updated_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["captures.id"], name=op.f("fk_http_requests_capture_id_captures"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.id"], name=op.f("fk_http_requests_flow_id_flows"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_http_requests")),
    )
    with op.batch_alter_table("http_requests", schema=None) as batch_op:
        batch_op.create_index("ix_http_requests_capture_id", ["capture_id"], unique=False)
        batch_op.create_index("ix_http_requests_host", ["host"], unique=False)
        batch_op.create_index("ix_http_requests_timestamp", ["timestamp"], unique=False)

    op.create_table(
        "tls_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("capture_id", sa.String(length=36), nullable=False),
        sa.Column("flow_id", sa.String(length=36), nullable=True),
        sa.Column("timestamp", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("sni", sa.String(length=255), nullable=True),
        sa.Column("cipher_suite", sa.String(length=128), nullable=True),
        sa.Column("alpn", sa.String(length=64), nullable=True),
        sa.Column("created_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.Column("updated_at", app.database.types.UTCDateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["captures.id"], name=op.f("fk_tls_records_capture_id_captures"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.id"], name=op.f("fk_tls_records_flow_id_flows"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tls_records")),
    )
    with op.batch_alter_table("tls_records", schema=None) as batch_op:
        batch_op.create_index("ix_tls_records_capture_id", ["capture_id"], unique=False)
        batch_op.create_index("ix_tls_records_sni", ["sni"], unique=False)
        batch_op.create_index("ix_tls_records_timestamp", ["timestamp"], unique=False)

    with op.batch_alter_table("flows", schema=None) as batch_op:
        batch_op.add_column(sa.Column("summary", sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column("payload_preview", sa.Text(), nullable=True))

    with op.batch_alter_table("hosts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("role", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("risk_score", sa.Integer(), server_default="0", nullable=False))

    with op.batch_alter_table("timeline_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("severity", sa.String(length=32), server_default="info", nullable=False))
        batch_op.add_column(sa.Column("category", sa.String(length=64), server_default="General", nullable=False))
        batch_op.add_column(sa.Column("protocol", sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column("src", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("dst", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("timeline_events", schema=None) as batch_op:
        batch_op.drop_column("dst")
        batch_op.drop_column("src")
        batch_op.drop_column("protocol")
        batch_op.drop_column("category")
        batch_op.drop_column("severity")

    with op.batch_alter_table("hosts", schema=None) as batch_op:
        batch_op.drop_column("risk_score")
        batch_op.drop_column("role")

    with op.batch_alter_table("flows", schema=None) as batch_op:
        batch_op.drop_column("payload_preview")
        batch_op.drop_column("summary")

    with op.batch_alter_table("tls_records", schema=None) as batch_op:
        batch_op.drop_index("ix_tls_records_timestamp")
        batch_op.drop_index("ix_tls_records_sni")
        batch_op.drop_index("ix_tls_records_capture_id")

    op.drop_table("tls_records")

    with op.batch_alter_table("http_requests", schema=None) as batch_op:
        batch_op.drop_index("ix_http_requests_timestamp")
        batch_op.drop_index("ix_http_requests_host")
        batch_op.drop_index("ix_http_requests_capture_id")

    op.drop_table("http_requests")

    with op.batch_alter_table("dns_records", schema=None) as batch_op:
        batch_op.drop_index("ix_dns_records_timestamp")
        batch_op.drop_index("ix_dns_records_query_name")
        batch_op.drop_index("ix_dns_records_capture_id")

    op.drop_table("dns_records")

    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.drop_index("ix_certificates_fingerprint_sha256")
        batch_op.drop_index("ix_certificates_capture_id")

    op.drop_table("certificates")
