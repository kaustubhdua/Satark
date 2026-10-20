-- Keep the exposed tenant-creation RPC as a SECURITY INVOKER wrapper.
-- Only the private implementation performs the atomic SECURITY DEFINER writes.
-- It derives ownership exclusively from auth.uid(), validates input, and records
-- the tenant-created audit event. Both functions use a fixed empty search_path.
create schema if not exists satark_private;
revoke all on schema satark_private from public, anon;
grant usage on schema satark_private to authenticated;

create or replace function satark_private.create_tenant(tenant_name text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
  actor uuid := auth.uid();
  created_tenant uuid;
  event_time timestamptz := clock_timestamp();
  event_details jsonb;
  payload jsonb;
begin
  if actor is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if tenant_name is null or length(trim(tenant_name)) < 1 or length(trim(tenant_name)) > 160 then
    raise exception 'Tenant name must contain 1–160 characters' using errcode = '22023';
  end if;

  insert into public.satark_tenants(name)
  values (trim(tenant_name))
  returning id into created_tenant;

  insert into public.satark_memberships(tenant_id, user_id, role)
  values (created_tenant, actor, 'owner');

  event_details := jsonb_build_object('name', trim(tenant_name));
  payload := jsonb_build_object(
    'tenant_id', created_tenant, 'case_id', null, 'actor_id', actor,
    'action', 'tenant.created', 'details', event_details,
    'previous_hash', null, 'created_at', event_time
  );
  insert into public.satark_audit_events(
    tenant_id, actor_id, action, details, previous_hash, event_hash, created_at
  )
  values (
    created_tenant, actor, 'tenant.created', event_details, null,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'),
    event_time
  );
  return created_tenant;
end;
$function$;

revoke all on function satark_private.create_tenant(text) from public, anon;
grant execute on function satark_private.create_tenant(text) to authenticated;

create or replace function public.satark_create_tenant(tenant_name text)
returns uuid
language plpgsql
set search_path = ''
as $function$
begin
  return satark_private.create_tenant(tenant_name);
end;
$function$;

revoke all on function public.satark_create_tenant(text) from public, anon;
grant execute on function public.satark_create_tenant(text) to authenticated;
