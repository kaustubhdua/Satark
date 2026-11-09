"""Add optional email verification and one-time verification tokens."""
import sqlalchemy as sa
from alembic import op

revision = "20261109_0006"
down_revision = "20261109_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    user_columns = {column["name"] for column in inspector.get_columns("satark_users")}
    if "email_verified_at" not in user_columns:
        op.add_column("satark_users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
        # Accounts that existed before this opt-in feature are grandfathered as
        # verified; only newly registered accounts require a confirmation link.
        op.execute("UPDATE satark_users SET email_verified_at = created_at WHERE email_verified_at IS NULL")

    if "satark_email_verification_tokens" not in inspector.get_table_names():
        op.create_table(
            "satark_email_verification_tokens",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("user_id", sa.String(length=36), sa.ForeignKey("satark_users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_satark_email_verification_tokens_user_id", "satark_email_verification_tokens", ["user_id"])
        op.create_index("ix_satark_email_verification_tokens_token_hash", "satark_email_verification_tokens", ["token_hash"])
        op.create_index("ix_satark_email_verification_tokens_expires_at", "satark_email_verification_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("satark_email_verification_tokens")
    op.drop_column("satark_users", "email_verified_at")
