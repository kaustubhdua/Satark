"""Initial SATARK-owned relational schema and append-only audit guard."""
from alembic import op
from satark_backend import Base

revision = "20261109_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)
    if bind.dialect.name == "postgresql":
        # Audit history is append-only even if an application route accidentally
        # attempts to edit or delete a record. Database owners can still perform
        # emergency maintenance through a separately controlled break-glass path.
        op.execute("""
            CREATE OR REPLACE FUNCTION satark_reject_audit_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'SATARK audit events are append-only';
            END;
            $$
        """)
        op.execute("""
            CREATE TRIGGER satark_audit_events_append_only
            BEFORE UPDATE OR DELETE ON satark_audit_events
            FOR EACH ROW EXECUTE FUNCTION satark_reject_audit_mutation()
        """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS satark_audit_events_append_only ON satark_audit_events")
        op.execute("DROP FUNCTION IF EXISTS satark_reject_audit_mutation()")
    Base.metadata.drop_all(bind=bind, checkfirst=True)
