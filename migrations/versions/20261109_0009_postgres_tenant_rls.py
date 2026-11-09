"""Enable PostgreSQL row-level tenant isolation for SATARK data tables."""
from alembic import op

revision = "20261109_0009"
down_revision = "20261109_0008"
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "satark_cases",
    "satark_case_notes",
    "satark_evidence",
    "satark_findings",
    "satark_reports",
    "satark_audit_events",
    "satark_approvals",
    "satark_ingestion_checkpoints",
    "satark_investigation_jobs",
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute("""
        CREATE OR REPLACE FUNCTION public.satark_has_tenant_access(target_tenant_id varchar)
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT EXISTS (
                SELECT 1
                FROM public.satark_memberships AS membership
                WHERE membership.tenant_id = target_tenant_id
                  AND membership.user_id = NULLIF(current_setting('satark.user_id', true), '')
            )
        $$
    """)

    op.execute("ALTER TABLE public.satark_tenants ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.satark_tenants FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY satark_tenants_isolation ON public.satark_tenants
        USING (public.satark_has_tenant_access(id))
        WITH CHECK (
            created_by = NULLIF(current_setting('satark.user_id', true), '')
        )
    """)

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        if table == "satark_investigation_jobs":
            policy = """
                USING (
                    public.satark_has_tenant_access(tenant_id)
                    OR current_setting('satark.worker', true) = 'on'
                )
                WITH CHECK (
                    public.satark_has_tenant_access(tenant_id)
                    OR current_setting('satark.worker', true) = 'on'
                )
            """
        else:
            policy = """
                USING (public.satark_has_tenant_access(tenant_id))
                WITH CHECK (public.satark_has_tenant_access(tenant_id))
            """
        op.execute(f"CREATE POLICY {table}_tenant_isolation ON public.{table} {policy}")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON public.{table}")
        op.execute(f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS satark_tenants_isolation ON public.satark_tenants")
    op.execute("ALTER TABLE public.satark_tenants NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.satark_tenants DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS public.satark_has_tenant_access(varchar)")
