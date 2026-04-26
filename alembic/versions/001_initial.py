"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-04-25

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Devices
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_hash", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("app_version", sa.String(20), nullable=True),
        sa.Column("first_seen_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("total_threats_reported", sa.Integer, nullable=False, server_default="0"),
    )

    # Admin users
    op.create_table(
        "admin_users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column(
            "role",
            sa.Enum("super_admin", "analyst", "viewer", name="adminrole"),
            nullable=False,
            server_default="analyst",
        ),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime, nullable=True),
    )

    # Threats
    op.create_table(
        "threats",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mobile_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column(
            "source",
            sa.Enum("MANUAL", "AUTO_SMS", "AUTO_TELEGRAM", name="threatsource"),
            nullable=False,
        ),
        sa.Column("message_truncated", sa.Text, nullable=True),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("confidence", sa.Integer, nullable=True),
        sa.Column(
            "label",
            sa.Enum("SAFE", "SUSPICIOUS", "DANGEROUS", name="threatlabel"),
            nullable=False,
            server_default="DANGEROUS",
        ),
        sa.Column("reasons", postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("recommendations", postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("analyzed_at_device", sa.DateTime, nullable=True),
        sa.Column("sender_name", sa.String(255), nullable=True, index=True),
        sa.Column("source_app", sa.String(100), nullable=True),
        sa.Column("detected_file_name", sa.String(500), nullable=True),
        sa.Column("detected_file_type", sa.String(200), nullable=True),
        sa.Column("detected_url", sa.Text, nullable=True, index=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column(
            "status",
            sa.Enum("new", "confirmed", "false_positive", "actioned", "archived", name="threatstatus"),
            nullable=False,
            server_default="new",
        ),
        sa.Column("auto_tags", postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("manual_tags", postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("analyst_notes", sa.Text, nullable=True),
        sa.Column("actioned_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("admin_users.id"), nullable=True),
        sa.Column("actioned_at", sa.DateTime, nullable=True),
        sa.Column("received_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    op.create_index("idx_threats_status", "threats", ["status"])
    op.create_index("idx_threats_label", "threats", ["label"])
    op.create_index("idx_threats_received_at", "threats", ["received_at"])
    op.create_index("idx_threats_risk_score", "threats", ["risk_score"])
    op.create_index("idx_threats_source", "threats", ["source"])

    # AI Analyses
    op.create_table(
        "ai_analyses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("threat_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threats.id"), nullable=False),
        sa.Column("severity_assessment", sa.String(20), nullable=True),
        sa.Column("threat_type", sa.String(100), nullable=True),
        sa.Column("analysis_text", sa.Text, nullable=False),
        sa.Column("recommended_actions", postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("ioc_indicators", postgresql.JSONB, nullable=True),
        sa.Column("similar_pattern_description", sa.Text, nullable=True),
        sa.Column("confidence_score", sa.Integer, nullable=True),
        sa.Column("model_used", sa.String(50), nullable=False, server_default="claude-sonnet-4-20250514"),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("admin_users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # Audit log
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("admin_users.id"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=True),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("ai_analyses")
    op.drop_table("threats")
    op.drop_table("admin_users")
    op.drop_table("devices")
    op.execute("DROP TYPE IF EXISTS adminrole")
    op.execute("DROP TYPE IF EXISTS threatsource")
    op.execute("DROP TYPE IF EXISTS threatlabel")
    op.execute("DROP TYPE IF EXISTS threatstatus")
