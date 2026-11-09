"""Install or repair the PostgreSQL append-only audit trigger."""
from alembic import op

revision = "20261109_0003"
down_revision = "20261109_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
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
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger
                WHERE tgname = 'satark_audit_events_append_only'
                  AND NOT tgisinternal
            ) THEN
                CREATE TRIGGER satark_audit_events_append_only
                BEFORE UPDATE OR DELETE ON satark_audit_events
                FOR EACH ROW EXECUTE FUNCTION satark_reject_audit_mutation();
            END IF;
        END;
        $$
    """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS satark_audit_events_append_only ON satark_audit_events")
        op.execute("DROP FUNCTION IF EXISTS satark_reject_audit_mutation()")
