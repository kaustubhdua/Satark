-- Authenticated, atomic first-workspace provisioning for SATARK.
-- The function derives the owner from auth.uid(); callers cannot choose a user or role.
create or replace function public.satark_create_tenant(tenant_name text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  actor uuid := auth.uid();
  created_tenant uuid;
  audit_payload jsonb;
begin
  if actor is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if tenant_name is null or length(trim(tenant_name)) < 1 or length(trim(tenant_name)) > 160 then
    raise exception 'Tenant name must contain 1–160 characters' using errcode = '22023';
  end if;

  insert into public.satark_tenants(name) values (trim(tenant_name))
    returning id into created_tenant;
  insert into public.satark_memberships(tenant_id, user_id, role)
    values (created_tenant, actor, 'owner');

  audit_payload := jsonb_build_object(
    'tenant_id', created_tenant,
    'actor_id', actor,
    'action', 'tenant.created',
    'name', trim(tenant_name),
    'created_at', clock_timestamp()
  );
  insert into public.satark_audit_events(
    tenant_id, actor_id, action, details, event_hash
  ) values (
    created_tenant, actor, 'tenant.created',
    jsonb_build_object('name', trim(tenant_name)),
    encode(extensions.digest(convert_to(audit_payload::text, 'UTF8'), 'sha256'), 'hex')
  );
  return created_tenant;
end;
$$;

revoke all on function public.satark_create_tenant(text) from public;
revoke all on function public.satark_create_tenant(text) from anon;
grant execute on function public.satark_create_tenant(text) to authenticated;
