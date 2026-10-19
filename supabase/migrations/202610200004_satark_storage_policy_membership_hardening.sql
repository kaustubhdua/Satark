-- This migration is independently runnable on main, before the approval
-- hardening PR merges. Define the non-exposed helper before storage policies use it.
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

-- The membership helper was moved to satark_private and its public wrapper's
-- EXECUTE grant was revoked. Storage policies must call the private helper too;
-- otherwise authenticated evidence uploads/downloads fail with permission errors.
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

drop policy if exists satark_evidence_object_read on storage.objects;
create policy satark_evidence_object_read on storage.objects
  for select to authenticated
  using (
    bucket_id = 'satark-evidence'
    and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and satark_private.has_membership(split_part(name, '/', 1)::uuid)
  );
