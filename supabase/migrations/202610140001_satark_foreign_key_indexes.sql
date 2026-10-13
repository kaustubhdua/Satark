-- Cover SATARK foreign keys identified by Supabase's performance advisor.
-- Non-destructive and scoped exclusively to SATARK-prefixed tables.
create index if not exists satark_audit_events_actor_id_idx
  on public.satark_audit_events (actor_id);
create index if not exists satark_audit_events_tenant_case_idx
  on public.satark_audit_events (tenant_id, case_id);
create index if not exists satark_cases_created_by_idx
  on public.satark_cases (created_by);
create index if not exists satark_evidence_created_by_idx
  on public.satark_evidence (created_by);
create index if not exists satark_evidence_tenant_case_idx
  on public.satark_evidence (tenant_id, case_id);
create index if not exists satark_evidence_tenant_id_idx
  on public.satark_evidence (tenant_id);
