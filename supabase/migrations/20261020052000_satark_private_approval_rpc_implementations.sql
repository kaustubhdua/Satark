-- Keep the exposed approval and assignment RPCs as SECURITY INVOKER wrappers.
-- Their privileged, transactionally guarded implementations live in the
-- non-exposed satark_private schema with a fixed empty search_path. This keeps
-- PostgREST behavior stable while preventing authenticated SECURITY DEFINER
-- functions from being directly exposed in the public API schema.

create schema if not exists satark_private;
revoke all on schema satark_private from public, anon;
grant usage on schema satark_private to authenticated;

create or replace function satark_private.authorize_response_action(
  p_approval_id uuid,
  p_tenant_id uuid,
  p_case_id uuid,
  p_action_key text,
  p_payload_sha256 text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
declare
  a public.satark_approvals%rowtype;
begin
  if auth.uid() is null then return false; end if;
  if not satark_private.has_membership(
    p_tenant_id, array['owner','responder']::text[]
  ) then return false; end if;
  select * into a from public.satark_approvals
    where id=p_approval_id and tenant_id=p_tenant_id and case_id=p_case_id
    for update;
  if not found or a.status <> 'approved' or a.expires_at <= now()
    or a.action_key <> p_action_key or a.payload_sha256 <> p_payload_sha256
    or a.decided_by is null or a.decided_by = a.requested_by then
    return false;
  end if;
  -- This validates only. The executor must atomically consume the approval
  -- immediately before action; no live executor is enabled by this migration.
  return true;
exception when others then return false;
end
$function$;

create or replace function satark_private.consume_response_approval(
  p_approval_id uuid,
  p_tenant_id uuid,
  p_case_id uuid,
  p_action_key text,
  p_payload_sha256 text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
declare
  a public.satark_approvals%rowtype;
  previous text;
  event_time timestamptz := clock_timestamp();
  event_details jsonb;
  payload jsonb;
  actor uuid := auth.uid();
begin
  if actor is null or not satark_private.has_membership(
    p_tenant_id, array['owner','responder']::text[]
  ) then return false; end if;
  select * into a from public.satark_approvals
    where id=p_approval_id and tenant_id=p_tenant_id and case_id=p_case_id
    for update;
  if not found or a.status <> 'approved' or a.expires_at <= event_time
    or a.action_key <> p_action_key or a.payload_sha256 <> p_payload_sha256
    or a.decided_by is null or a.decided_by = a.requested_by then
    return false;
  end if;

  update public.satark_approvals set status='consumed', consumed_at=event_time where id=a.id;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(a.tenant_id::text,0));
  select event_hash into previous from public.satark_audit_events
    where tenant_id=a.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object(
    'approval_id',a.id,'action_key',a.action_key,
    'payload_sha256',a.payload_sha256,'decision','consumed'
  );
  payload := jsonb_build_object(
    'tenant_id',a.tenant_id,'case_id',a.case_id,'actor_id',actor,
    'action','approval.consumed','details',event_details,
    'previous_hash',previous,'created_at',event_time
  );
  insert into public.satark_audit_events(
    tenant_id,case_id,actor_id,action,details,previous_hash,event_hash,created_at
  ) values (
    a.tenant_id,a.case_id,actor,'approval.consumed',event_details,previous,
    encode(extensions.digest(convert_to(payload::text,'UTF8'),'sha256'),'hex'),event_time
  );
  return true;
exception when others then return false;
end
$function$;

create or replace function satark_private.decide_approval(
  p_approval_id uuid,
  p_decision text,
  p_reason text default null
)
returns public.satark_approvals
language plpgsql
security definer
set search_path = ''
as $function$
declare
  a public.satark_approvals%rowtype;
  previous text;
  event_time timestamptz := clock_timestamp();
  event_details jsonb;
  payload jsonb;
  actor uuid := auth.uid();
begin
  if actor is null or p_decision not in ('approved','rejected') then
    raise exception 'unauthorized or invalid decision';
  end if;
  if p_reason is not null and length(p_reason)>2000 then
    raise exception 'decision reason too long';
  end if;
  select * into a from public.satark_approvals where id=p_approval_id for update;
  if not found then raise exception 'approval not found'; end if;
  if a.status <> 'pending' or a.expires_at <= now() then
    raise exception 'approval is not pending or has expired';
  end if;
  if actor = a.requested_by then raise exception 'requester cannot decide own approval'; end if;
  if not satark_private.has_membership(
    a.tenant_id, array['owner','responder']::text[]
  ) then raise exception 'insufficient tenant role'; end if;

  update public.satark_approvals
    set status=p_decision, decided_by=actor, decision_reason=p_reason, decided_at=event_time
    where id=a.id returning * into a;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(a.tenant_id::text,0));
  select event_hash into previous from public.satark_audit_events
    where tenant_id=a.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object(
    'approval_id',a.id,'action_key',a.action_key,
    'payload_sha256',a.payload_sha256,'decision',p_decision,'reason',p_reason
  );
  payload := jsonb_build_object(
    'tenant_id',a.tenant_id,'case_id',a.case_id,'actor_id',actor,
    'action','approval.'||p_decision,'details',event_details,
    'previous_hash',previous,'created_at',event_time
  );
  insert into public.satark_audit_events(
    tenant_id,case_id,actor_id,action,details,previous_hash,event_hash,created_at
  ) values (
    a.tenant_id,a.case_id,actor,'approval.'||p_decision,event_details,previous,
    encode(extensions.digest(convert_to(payload::text,'UTF8'),'sha256'),'hex'),event_time
  );
  return a;
end
$function$;

create or replace function satark_private.list_assignable_members(p_tenant_id uuid)
returns table(user_id uuid, role text)
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if auth.uid() is null or not satark_private.has_membership(
    p_tenant_id, array['owner','responder']::text[]
  ) then
    raise exception 'workspace owner or responder access required' using errcode='42501';
  end if;
  return query
    select m.user_id, m.role
    from public.satark_memberships m
    where m.tenant_id=p_tenant_id and m.role in ('owner','responder','analyst')
    order by m.role, m.user_id;
end
$function$;

revoke all on function satark_private.authorize_response_action(uuid,uuid,uuid,text,text) from public, anon;
revoke all on function satark_private.consume_response_approval(uuid,uuid,uuid,text,text) from public, anon;
revoke all on function satark_private.decide_approval(uuid,text,text) from public, anon;
revoke all on function satark_private.list_assignable_members(uuid) from public, anon;
grant execute on function satark_private.authorize_response_action(uuid,uuid,uuid,text,text) to authenticated;
grant execute on function satark_private.consume_response_approval(uuid,uuid,uuid,text,text) to authenticated;
grant execute on function satark_private.decide_approval(uuid,text,text) to authenticated;
grant execute on function satark_private.list_assignable_members(uuid) to authenticated;

create or replace function public.satark_authorize_response_action(
  p_approval_id uuid,
  p_tenant_id uuid,
  p_case_id uuid,
  p_action_key text,
  p_payload_sha256 text
)
returns boolean
language plpgsql
set search_path = ''
as $function$
begin
  return satark_private.authorize_response_action(
    p_approval_id,p_tenant_id,p_case_id,p_action_key,p_payload_sha256
  );
end
$function$;

create or replace function public.satark_consume_response_approval(
  p_approval_id uuid,
  p_tenant_id uuid,
  p_case_id uuid,
  p_action_key text,
  p_payload_sha256 text
)
returns boolean
language plpgsql
set search_path = ''
as $function$
begin
  return satark_private.consume_response_approval(
    p_approval_id,p_tenant_id,p_case_id,p_action_key,p_payload_sha256
  );
end
$function$;

create or replace function public.satark_decide_approval(
  p_approval_id uuid,
  p_decision text,
  p_reason text default null
)
returns public.satark_approvals
language plpgsql
set search_path = ''
as $function$
declare
  result public.satark_approvals;
begin
  result := satark_private.decide_approval(p_approval_id,p_decision,p_reason);
  return result;
end
$function$;

create or replace function public.satark_list_assignable_members(p_tenant_id uuid)
returns table(user_id uuid, role text)
language plpgsql
set search_path = ''
as $function$
begin
  return query select * from satark_private.list_assignable_members(p_tenant_id);
end
$function$;

revoke all on function public.satark_authorize_response_action(uuid,uuid,uuid,text,text) from public, anon;
revoke all on function public.satark_consume_response_approval(uuid,uuid,uuid,text,text) from public, anon;
revoke all on function public.satark_decide_approval(uuid,text,text) from public, anon;
revoke all on function public.satark_list_assignable_members(uuid) from public, anon;
grant execute on function public.satark_authorize_response_action(uuid,uuid,uuid,text,text) to authenticated;
grant execute on function public.satark_consume_response_approval(uuid,uuid,uuid,text,text) to authenticated;
grant execute on function public.satark_decide_approval(uuid,text,text) to authenticated;
grant execute on function public.satark_list_assignable_members(uuid) to authenticated;
