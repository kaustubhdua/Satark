"""Initial SATARK-owned relational schema."""
from alembic import op
from satark_backend import Base

revision = "20261109_0001"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)

def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
