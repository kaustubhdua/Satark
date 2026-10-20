-- Ensure the policy helper exists before this migration installs approval RLS
-- policies. It is deliberately outside the exposed public/PostgREST schema.
create schema if not exists satark_private;
revoke all on schema satark_private from public, anon;
grant usage on schema satark_private to authenticated;

create or replace function satark_private.has_membership(
  target_tenant uuid,
  allowed_roles text[] default null
) returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.satark_memberships m
    where m.tenant_id = target_tenant
      and m.user_id = (select auth.uid())
      and (allowed_roles is null or m.role = any(allowed_roles))
  );
$$;

revoke all on function satark_private.has_membership(uuid, text[]) from public, anon;
grant execute on function satark_private.has_membership(uuid, text[]) to authenticated;

-- Rebind all tenant-scoped policies to the private helper before revoking the
-- public wrapper's EXECUTE grant. This also keeps clean local resets aligned with
-- the intended hosted policy model.
drop policy if exists satark_tenants_member_read on public.satark_tenants;
create policy satark_tenants_member_read on public.satark_tenants
  for select to authenticated using (satark_private.has_membership(id));

drop policy if exists satark_memberships_self_read on public.satark_memberships;
create policy satark_memberships_self_read on public.satark_memberships
  for select to authenticated using (
    user_id = (select auth.uid())
    or satark_private.has_membership(tenant_id, array['owner']::text[])
  );

drop policy if exists satark_cases_member_read on public.satark_cases;
create policy satark_cases_member_read on public.satark_cases
  for select to authenticated using (satark_private.has_membership(tenant_id));

drop policy if exists satark_cases_analyst_write on public.satark_cases;
create policy satark_cases_analyst_write on public.satark_cases
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[])
  );

drop policy if exists satark_cases_analyst_update on public.satark_cases;
create policy satark_cases_analyst_update on public.satark_cases
  for update to authenticated
  using (satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[]))
  with check (satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[]));

drop policy if exists satark_evidence_member_read on public.satark_evidence;
create policy satark_evidence_member_read on public.satark_evidence
  for select to authenticated using (satark_private.has_membership(tenant_id));

drop policy if exists satark_evidence_analyst_insert on public.satark_evidence;
create policy satark_evidence_analyst_insert on public.satark_evidence
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[])
  );

drop policy if exists satark_audit_member_read on public.satark_audit_events;
create policy satark_audit_member_read on public.satark_audit_events
  for select to authenticated using (satark_private.has_membership(tenant_id));

drop policy if exists satark_audit_member_insert on public.satark_audit_events;
create policy satark_audit_member_insert on public.satark_audit_events
  for insert to authenticated with check (
    actor_id = (select auth.uid())
    and satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[])
  );

drop policy if exists satark_findings_member_read on public.satark_findings;
create policy satark_findings_member_read on public.satark_findings
  for select to authenticated using (satark_private.has_membership(tenant_id));

drop policy if exists satark_findings_analyst_insert on public.satark_findings;
create policy satark_findings_analyst_insert on public.satark_findings
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[])
  );

drop policy if exists satark_reports_member_read on public.satark_reports;
create policy satark_reports_member_read on public.satark_reports
  for select to authenticated using (satark_private.has_membership(tenant_id));

drop policy if exists satark_reports_analyst_insert on public.satark_reports;
create policy satark_reports_analyst_insert on public.satark_reports
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[])
  );

-- Storage policies must also use the private helper before the public wrapper
-- is revoked, otherwise evidence uploads/downloads fail closed.
drop policy if exists satark_evidence_object_read on storage.objects;
create policy satark_evidence_object_read on storage.objects
  for select to authenticated
  using (
    bucket_id = 'satark-evidence'
    and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and satark_private.has_membership(split_part(name, '/', 1)::uuid)
  );

drop policy if exists satark_evidence_object_insert on storage.objects;
create policy satark_evidence_object_insert on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'satark-evidence'
    and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and satark_private.has_membership(
      split_part(name, '/', 1)::uuid, array['owner','responder','analyst']::text[]
    )
    and exists (
      select 1 from public.satark_cases c
      where c.id = split_part(objects.name, '/', 2)::uuid
        and c.tenant_id = split_part(objects.name, '/', 1)::uuid
        and satark_private.has_membership(
          c.tenant_id, array['owner','responder','analyst']::text[]
        )
    )
  );

revoke all on function public.satark_has_membership(uuid, text[]) from public, anon, authenticated;
