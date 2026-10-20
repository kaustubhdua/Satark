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



-- Harden the durable-approval foundation already present in 202610200001.
-- This follow-up keeps the original migration immutable and fixes RLS helper ACLs,
-- server-side payload binding, bounded expiry, and trigger-only function exposure.

drop policy if exists satark_approvals_member_read on public.satark_approvals;
create policy satark_approvals_member_read on public.satark_approvals
  for select to authenticated
  using (satark_private.has_membership(tenant_id));

drop policy if exists satark_approvals_request on public.satark_approvals;
create policy satark_approvals_request on public.satark_approvals
  for insert to authenticated
  with check (
    requested_by = (select auth.uid())
    and status = 'pending'
    and decided_by is null
    and decided_at is null
    and satark_private.has_membership(
      tenant_id, array['owner','responder','analyst']::text[]
    )
  );

create or replace function public.satark_approvals_guard()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'approval records cannot be deleted';
  end if;

  if tg_op = 'INSERT' then
    -- Compute the digest in the database over PostgreSQL's canonical JSONB text;
    -- never trust a client-supplied digest for an approval's action payload.
    new.payload_sha256 := encode(
      extensions.digest(convert_to(new.action_payload::text, 'UTF8'), 'sha256'),
      'hex'
    );
    if new.expires_at > now() + interval '30 minutes' then
      raise exception 'approval expiry exceeds maximum lifetime';
    end if;
    if new.status <> 'pending'
      or new.decided_by is not null
      or new.decided_at is not null
      or new.consumed_at is not null then
      raise exception 'approvals must start pending';
    end if;
    return new;
  end if;

  if new.id is distinct from old.id
    or new.tenant_id is distinct from old.tenant_id
    or new.case_id is distinct from old.case_id
    or new.action_key is distinct from old.action_key
    or new.action_payload is distinct from old.action_payload
    or new.payload_sha256 is distinct from old.payload_sha256
    or new.requested_by is distinct from old.requested_by
    or new.created_at is distinct from old.created_at
    or new.expires_at is distinct from old.expires_at then
    raise exception 'approval request details are immutable';
  end if;

  if old.status = 'approved' and new.status = 'consumed' then
    if new.consumed_at is null
      or new.decided_by is distinct from old.decided_by
      or new.decided_at is distinct from old.decided_at
      or new.decision_reason is distinct from old.decision_reason
      or not satark_private.has_membership(
        old.tenant_id, array['owner','responder']::text[]
      ) then
      raise exception 'invalid approval consumption';
    end if;
    return new;
  end if;

  if old.status <> 'pending' then
    raise exception 'terminal approval records are immutable';
  end if;
  if new.status not in ('approved','rejected','revoked')
    or new.decided_by is null
    or new.decided_at is null then
    raise exception 'only a complete terminal decision is allowed';
  end if;
  if new.decided_by = old.requested_by then
    raise exception 'requester cannot approve own action';
  end if;
  if not satark_private.has_membership(
    old.tenant_id, array['owner','responder']::text[]
  ) then
    raise exception 'approver lacks required tenant role';
  end if;
  if old.expires_at <= now() then
    raise exception 'approval request expired';
  end if;
  return new;
end $$;

-- This function is trigger-only, not a PostgREST RPC endpoint.
revoke all on function public.satark_approvals_guard() from public, anon, authenticated;

create or replace function public.satark_authorize_response_action(
  p_approval_id uuid, p_tenant_id uuid, p_case_id uuid, p_action_key text, p_payload_sha256 text
) returns boolean language plpgsql security definer set search_path = ''
as $$
declare a public.satark_approvals%rowtype;
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
end $$;

create or replace function public.satark_decide_approval(
  p_approval_id uuid, p_decision text, p_reason text default null
) returns public.satark_approvals language plpgsql security definer set search_path = ''
as $$
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
end $$;

create or replace function public.satark_consume_response_approval(
  p_approval_id uuid, p_tenant_id uuid, p_case_id uuid, p_action_key text, p_payload_sha256 text
) returns boolean language plpgsql security definer set search_path = ''
as $$
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
end $$;

revoke all on function public.satark_authorize_response_action(uuid,uuid,uuid,text,text) from public, anon;
grant execute on function public.satark_authorize_response_action(uuid,uuid,uuid,text,text) to authenticated;
revoke all on function public.satark_decide_approval(uuid,text,text) from public, anon;
grant execute on function public.satark_decide_approval(uuid,text,text) to authenticated;
revoke all on function public.satark_consume_response_approval(uuid,uuid,uuid,text,text) from public, anon;
grant execute on function public.satark_consume_response_approval(uuid,uuid,uuid,text,text) to authenticated;

comment on column public.satark_approvals.payload_sha256 is
  'SHA-256 of the canonical PostgreSQL JSONB text for action_payload; computed by the database trigger.';

