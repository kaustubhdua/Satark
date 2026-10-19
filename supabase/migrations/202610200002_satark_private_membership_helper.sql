-- Isolate the membership predicate behind a non-exposed schema. RLS policies can
-- invoke this helper, but PostgREST must not expose it as an RPC endpoint.
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
