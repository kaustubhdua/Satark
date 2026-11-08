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

    # Reconstruct the original hash-chain order rather than assuming timestamps
    # are unique. This preserves verification for existing audit histories.
    rows = bind.execute(sa.text("""
        SELECT id, tenant_id, previous_hash, event_hash, created_at
        FROM satark_audit_events
        ORDER BY tenant_id, created_at, id
    """)).mappings().all()
    grouped = {}
    for row in rows:
        grouped.setdefault(row["tenant_id"], []).append(row)
    for tenant_rows in grouped.values():
        by_previous = {}
        for row in tenant_rows:
            by_previous.setdefault(row["previous_hash"], []).append(row)
        for candidates in by_previous.values():
            candidates.sort(key=lambda row: (row["created_at"], row["id"]))
        previous_hash = "0" * 64
        sequence = 1
        assigned = set()
        while previous_hash in by_previous:
            candidates = [row for row in by_previous[previous_hash] if row["id"] not in assigned]
            if not candidates:
                break
            row = candidates[0]
            bind.execute(sa.text(
                "UPDATE satark_audit_events SET sequence = :sequence WHERE id = :id"
            ), {"sequence": sequence, "id": row["id"]})
            assigned.add(row["id"])
            previous_hash = row["event_hash"]
            sequence += 1
        # Preserve visibility of any pre-existing fork/orphan. The verifier will
        # report it; the migration must not silently discard an audit record.
        remaining = [row for row in tenant_rows if row["id"] not in assigned]
        remaining.sort(key=lambda row: (row["created_at"], row["id"]))
        for row in remaining:
            bind.execute(sa.text(
                "UPDATE satark_audit_events SET sequence = :sequence WHERE id = :id"
            ), {"sequence": sequence, "id": row["id"]})
            sequence += 1

    refreshed = sa.inspect(bind)
    sequence_column = next(column for column in refreshed.get_columns("satark_audit_events") if column["name"] == "sequence")
    constraints = {item.get("name") for item in refreshed.get_unique_constraints("satark_audit_events")}
    needs_unique = "uq_satark_audit_sequence" not in constraints
    if bind.dialect.name == "sqlite":
        # SQLite needs a batch table rebuild to add NOT NULL / UNIQUE safely.
        if sequence_column["nullable"] or needs_unique:
            with op.batch_alter_table("satark_audit_events") as batch:
                if sequence_column["nullable"]:
                    batch.alter_column("sequence", existing_type=sa.Integer(), nullable=False)
                if needs_unique:
                    batch.create_unique_constraint("uq_satark_audit_sequence", ["tenant_id", "sequence"])
    else:
        if sequence_column["nullable"]:
            op.alter_column("satark_audit_events", "sequence", existing_type=sa.Integer(), nullable=False)
        if needs_unique:
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
    columns = {column["name"] for column in sa.inspect(bind).get_columns("satark_audit_events")}
    if bind.dialect.name == "sqlite":
        if "uq_satark_audit_sequence" in constraints or "sequence" in columns:
            with op.batch_alter_table("satark_audit_events") as batch:
                if "uq_satark_audit_sequence" in constraints:
                    batch.drop_constraint("uq_satark_audit_sequence", type_="unique")
                if "sequence" in columns:
                    batch.drop_column("sequence")
    else:
        if "uq_satark_audit_sequence" in constraints:
            op.drop_constraint("uq_satark_audit_sequence", "satark_audit_events", type_="unique")
        if "sequence" in columns:
            op.drop_column("satark_audit_events", "sequence")
