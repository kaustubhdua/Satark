"""Add encrypted TOTP MFA factors and hashed recovery codes."""
import sqlalchemy as sa
from alembic import op

revision = "20261109_0007"
down_revision = "20261109_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "satark_mfa_factors" not in inspector.get_table_names():
        op.create_table(
            "satark_mfa_factors",
            sa.Column("user_id", sa.String(length=36), sa.ForeignKey("satark_users.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("secret_encrypted", sa.String(length=512), nullable=False),
            sa.Column("recovery_code_hashes", sa.JSON(), nullable=False),
            sa.Column("last_totp_counter", sa.Integer(), nullable=True),
            sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    op.drop_table("satark_mfa_factors")
