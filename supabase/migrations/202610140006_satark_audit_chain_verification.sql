-- Standardize audit payload hashing, enable audit-chain verification, and maintain case update timestamps.
create or replace function public.satark_create_tenant(tenant_name text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare
  actor uuid := auth.uid();
  created_tenant uuid;
  event_time timestamptz := clock_timestamp();
  event_details jsonb;
  payload jsonb;
begin
  if actor is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  if tenant_name is null or length(trim(tenant_name)) < 1 or length(trim(tenant_name)) > 160 then
    raise exception 'Tenant name must contain 1–160 characters' using errcode = '22023';
  end if;
  insert into public.satark_tenants(name) values (trim(tenant_name)) returning id into created_tenant;
  insert into public.satark_memberships(tenant_id, user_id, role) values (created_tenant, actor, 'owner');
  event_details := jsonb_build_object('name', trim(tenant_name));
  payload := jsonb_build_object('tenant_id', created_tenant, 'case_id', null, 'actor_id', actor,
    'action', 'tenant.created', 'details', event_details, 'previous_hash', null, 'created_at', event_time);
  insert into public.satark_audit_events(tenant_id, actor_id, action, details, previous_hash, event_hash, created_at)
  values (created_tenant, actor, 'tenant.created', event_details, null,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'), event_time);
  return created_tenant;
end; $$;
revoke all on function public.satark_create_tenant(text) from public, anon;
grant execute on function public.satark_create_tenant(text) to authenticated;

create or replace function public.satark_touch_case_updated_at()
returns trigger language plpgsql set search_path = ''
as $$ begin new.updated_at := clock_timestamp(); return new; end; $$;
revoke all on function public.satark_touch_case_updated_at() from public, anon, authenticated;
drop trigger if exists satark_case_touch_updated_at on public.satark_cases;
create trigger satark_case_touch_updated_at before update on public.satark_cases
for each row execute function public.satark_touch_case_updated_at();

create or replace function public.satark_verify_audit_chain(target_tenant uuid)
returns table(event_count bigint, chain_valid boolean, first_invalid_event_id bigint)
language plpgsql security definer set search_path = ''
as $$
declare
  actor uuid := auth.uid();
  item record;
  expected_previous text := null;
  expected_hash text;
  payload jsonb;
  count_events bigint := 0;
  invalid_id bigint := null;
begin
  if actor is null or not exists (
    select 1 from public.satark_memberships m where m.tenant_id = target_tenant and m.user_id = actor
  ) then
    raise exception 'Workspace access denied' using errcode = '42501';
  end if;
  for item in
    select id, tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at
    from public.satark_audit_events where tenant_id = target_tenant order by id asc
  loop
    count_events := count_events + 1;
    payload := jsonb_build_object('tenant_id', item.tenant_id, 'case_id', item.case_id,
      'actor_id', item.actor_id, 'action', item.action, 'details', item.details,
      'previous_hash', item.previous_hash, 'created_at', item.created_at);
    expected_hash := encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex');
    if invalid_id is null and (item.previous_hash is distinct from expected_previous or item.event_hash is distinct from expected_hash) then
      invalid_id := item.id;
    end if;
    expected_previous := item.event_hash;
  end loop;
  return query select count_events, invalid_id is null, invalid_id;
end; $$;
revoke all on function public.satark_verify_audit_chain(uuid) from public, anon;
grant execute on function public.satark_verify_audit_chain(uuid) to authenticated;
