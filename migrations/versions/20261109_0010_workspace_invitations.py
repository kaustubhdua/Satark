"""Add workspace invitation records with token-scoped PostgreSQL access."""
import sqlalchemy as sa
from alembic import op

revision = "20261109_0010"
down_revision = "20261109_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "satark_workspace_invitations" not in inspector.get_table_names():
        op.create_table(
            "satark_workspace_invitations",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("satark_tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("invited_email", sa.String(length=254), nullable=False),
            sa.Column("role", sa.String(length=16), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_satark_workspace_invitations_tenant_id", "satark_workspace_invitations", ["tenant_id"])
        op.create_index("ix_satark_workspace_invitations_invited_email", "satark_workspace_invitations", ["invited_email"])
        op.create_index("ix_satark_workspace_invitations_token_hash", "satark_workspace_invitations", ["token_hash"])
        op.create_index("ix_satark_workspace_invitations_expires_at", "satark_workspace_invitations", ["expires_at"])

    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE public.satark_workspace_invitations ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE public.satark_workspace_invitations FORCE ROW LEVEL SECURITY")
        op.execute("""
            CREATE POLICY satark_workspace_invitations_tenant_isolation
            ON public.satark_workspace_invitations
            USING (
                public.satark_has_tenant_access(tenant_id)
                OR token_hash = NULLIF(current_setting('satark.invitation_token', true), '')
            )
            WITH CHECK (public.satark_has_tenant_access(tenant_id))
        """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS satark_workspace_invitations_tenant_isolation ON public.satark_workspace_invitations")
        op.execute("ALTER TABLE public.satark_workspace_invitations NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE public.satark_workspace_invitations DISABLE ROW LEVEL SECURITY")
    op.drop_table("satark_workspace_invitations")
