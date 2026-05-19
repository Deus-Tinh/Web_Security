"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-19
"""
from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    user_role = postgresql.ENUM("ADMIN", "ANALYST", name="userrole", create_type=False)
    scan_status = postgresql.ENUM("QUEUED", "RUNNING", "COMPLETED", "FAILED", name="scanstatus", create_type=False)
    severity = postgresql.ENUM("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity", create_type=False)
    user_role.create(op.get_bind(), checkfirst=True)
    scan_status.create(op.get_bind(), checkfirst=True)
    severity.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(120), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("scope", postgresql.JSONB(), nullable=False),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_target", "scans", ["target_url"])
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("endpoint", sa.String(2048), nullable=False),
        sa.Column("parameter", sa.String(120)),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_table(
        "scan_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("level", sa.String(20), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("context", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_logs_scan_id", "scan_logs", ["scan_id"])
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("summary", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_index("ix_scan_logs_scan_id", table_name="scan_logs")
    op.drop_table("scan_logs")
    op.drop_index("ix_vulnerabilities_severity", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index("ix_scans_target", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
    sa.Enum(name="severity").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="scanstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="userrole").drop(op.get_bind(), checkfirst=True)
