"""Add persistent authentication abuse throttling."""
from alembic import op
from satark_backend import AuthThrottle

revision = "20261109_0004"
down_revision = "20261109_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    AuthThrottle.__table__.create(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    AuthThrottle.__table__.drop(bind=op.get_bind(), checkfirst=True)
