"""Add deterministic per-tenant sequence numbers to audit events."""
import sqlalchemy as sa
from alembic import op

revision = "20261109_0005"
down_revision = "20261109_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # The backfill is a controlled schema migration, so pause the append-only
        # trigger only for this statement and restore it before migration ends.
        op.execute("DROP TRIGGER IF EXISTS satark_audit_events_append_only ON satark_audit_events")
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("satark_audit_events")}
    if "sequence" not in columns:
        op.add_column("satark_audit_events", sa.Column("sequence", sa.Integer(), nullable=True))
    op.execute(sa.text("""
        WITH ordered AS (
            SELECT id, ROW_NUMBER() OVER (
                PARTITION BY tenant_id ORDER BY created_at ASC, id ASC
            ) AS position
            FROM satark_audit_events
        )
        UPDATE satark_audit_events AS target
        SET sequence = ordered.position
        FROM ordered
        WHERE target.id = ordered.id
    """))
    op.alter_column("satark_audit_events", "sequence", existing_type=sa.Integer(), nullable=False)
    constraints = {item.get("name") for item in sa.inspect(bind).get_unique_constraints("satark_audit_events")}
    if "uq_satark_audit_sequence" not in constraints:
        op.create_unique_constraint("uq_satark_audit_sequence", "satark_audit_events", ["tenant_id", "sequence"])
    if bind.dialect.name == "postgresql":
        op.execute("""
            CREATE TRIGGER satark_audit_events_append_only
            BEFORE UPDATE OR DELETE ON satark_audit_events
            FOR EACH ROW EXECUTE FUNCTION satark_reject_audit_mutation()
        """)


def downgrade() -> None:
    bind = op.get_bind()
    constraints = {item.get("name") for item in sa.inspect(bind).get_unique_constraints("satark_audit_events")}
    if "uq_satark_audit_sequence" in constraints:
        op.drop_constraint("uq_satark_audit_sequence", "satark_audit_events", type_="unique")
    columns = {column["name"] for column in sa.inspect(bind).get_columns("satark_audit_events")}
    if "sequence" in columns:
        op.drop_column("satark_audit_events", "sequence")
