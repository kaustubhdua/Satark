"""Add session-family identifiers and rotation-reuse revocation reasons."""
import sqlalchemy as sa
from alembic import op

revision = "20261109_0008"
down_revision = "20261109_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("satark_sessions")}
    if "family_id" not in columns:
        op.add_column("satark_sessions", sa.Column("family_id", sa.String(length=36), nullable=True))
    if "revoked_reason" not in columns:
        op.add_column("satark_sessions", sa.Column("revoked_reason", sa.String(length=32), nullable=True))
    op.execute("UPDATE satark_sessions SET family_id = id WHERE family_id IS NULL")
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("satark_sessions")}
    if "ix_satark_sessions_family_id" not in indexes:
        op.create_index("ix_satark_sessions_family_id", "satark_sessions", ["family_id"])


def downgrade() -> None:
    op.drop_index("ix_satark_sessions_family_id", table_name="satark_sessions")
    op.drop_column("satark_sessions", "revoked_reason")
    op.drop_column("satark_sessions", "family_id")
