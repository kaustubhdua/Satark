"""Add one-time password reset tokens."""
from alembic import op
from satark_backend import PasswordResetToken

revision = "20261109_0002"
down_revision = "20261109_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    PasswordResetToken.__table__.create(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    PasswordResetToken.__table__.drop(bind=op.get_bind(), checkfirst=True)
