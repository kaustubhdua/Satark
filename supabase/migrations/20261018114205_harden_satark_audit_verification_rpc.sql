-- Keep the exposed audit-verification RPC as a SECURITY INVOKER wrapper.
-- The implementation lives in the non-exposed satark_private schema, uses a
-- fixed empty search_path, and checks that auth.uid() belongs to the target tenant.
create schema if not exists satark_private;
revoke all on schema satark_private from public, anon;
grant usage on schema satark_private to authenticated;

create or replace function satark_private.verify_audit_chain(target_tenant uuid)
returns table(event_count bigint, chain_valid boolean, first_invalid_event_id bigint)
language plpgsql
security definer
set search_path = ''
as $function$
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
    select 1 from public.satark_memberships m
    where m.tenant_id = target_tenant and m.user_id = actor
  ) then
    raise exception 'Workspace access denied' using errcode = '42501';
  end if;

  for item in
    select id, tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at
    from public.satark_audit_events
    where tenant_id = target_tenant
    order by id asc
  loop
    count_events := count_events + 1;
    payload := jsonb_build_object(
      'tenant_id', item.tenant_id, 'case_id', item.case_id,
      'actor_id', item.actor_id, 'action', item.action, 'details', item.details,
      'previous_hash', item.previous_hash, 'created_at', item.created_at
    );
    expected_hash := encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex');
    if invalid_id is null and (
      item.previous_hash is distinct from expected_previous
      or item.event_hash is distinct from expected_hash
    ) then
      invalid_id := item.id;
    end if;
    expected_previous := item.event_hash;
  end loop;

  return query select count_events, invalid_id is null, invalid_id;
end;
$function$;

revoke all on function satark_private.verify_audit_chain(uuid) from public, anon;
grant execute on function satark_private.verify_audit_chain(uuid) to authenticated;

create or replace function public.satark_verify_audit_chain(target_tenant uuid)
returns table(event_count bigint, chain_valid boolean, first_invalid_event_id bigint)
language plpgsql
set search_path = ''
as $function$
begin
  return query select * from satark_private.verify_audit_chain(target_tenant);
end;
$function$;

revoke all on function public.satark_verify_audit_chain(uuid) from public, anon;
grant execute on function public.satark_verify_audit_chain(uuid) to authenticated;
