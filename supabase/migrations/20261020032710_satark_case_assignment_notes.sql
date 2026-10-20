-- Complete SATARK case assignment and immutable analyst notes.
-- This migration changes SATARK tables only.
alter table public.satark_cases
  add column if not exists assigned_to uuid references auth.users(id) on delete set null;
create index if not exists satark_cases_tenant_assignee_idx
  on public.satark_cases(tenant_id,assigned_to) where assigned_to is not null;

create or replace function public.satark_validate_case_assignee()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.assigned_to is not null and not exists (
    select 1 from public.satark_memberships m
    where m.tenant_id=new.tenant_id and m.user_id=new.assigned_to
      and m.role in ('owner','responder','analyst')
  ) then
    raise exception 'case assignee must be an owner, responder, or analyst in the same tenant'
      using errcode='23514';
  end if;
  return new;
end $$;
revoke all on function public.satark_validate_case_assignee() from public,anon,authenticated;
drop trigger if exists satark_case_assignee_guard on public.satark_cases;
create trigger satark_case_assignee_guard before insert or update of assigned_to,tenant_id
on public.satark_cases for each row execute function public.satark_validate_case_assignee();

-- Extend the existing case audit function so assignment changes are included in
-- the before/after event and are covered by the existing tenant hash chain.
create or replace function public.satark_audit_case_update()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare previous text; payload jsonb; event_time timestamptz := clock_timestamp(); event_details jsonb;
begin
  if OLD.title is not distinct from NEW.title
    and OLD.status is not distinct from NEW.status
    and OLD.severity is not distinct from NEW.severity
    and OLD.metadata is not distinct from NEW.metadata
    and OLD.assigned_to is not distinct from NEW.assigned_to then
    return NEW;
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous from public.satark_audit_events where tenant_id=NEW.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object(
    'case_id',NEW.id,
    'before',jsonb_build_object('title',OLD.title,'status',OLD.status,'severity',OLD.severity,'metadata',OLD.metadata,'assigned_to',OLD.assigned_to),
    'after',jsonb_build_object('title',NEW.title,'status',NEW.status,'severity',NEW.severity,'metadata',NEW.metadata,'assigned_to',NEW.assigned_to)
  );
  payload := jsonb_build_object('tenant_id',NEW.tenant_id,'case_id',NEW.id,'actor_id',auth.uid(),
    'action','case.updated','details',event_details,'previous_hash',previous,'created_at',event_time);
  insert into public.satark_audit_events(tenant_id,case_id,actor_id,action,details,previous_hash,event_hash,created_at)
  values(NEW.tenant_id,NEW.id,auth.uid(),'case.updated',event_details,previous,
    encode(extensions.digest(convert_to(payload::text,'UTF8'),'sha256'),'hex'),event_time);
  return NEW;
end $$;
revoke all on function public.satark_audit_case_update() from public,anon,authenticated;

create table if not exists public.satark_case_notes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid not null,
  body text not null check (length(btrim(body)) between 1 and 4000),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  constraint satark_case_notes_tenant_case_fk foreign key (tenant_id,case_id)
    references public.satark_cases(tenant_id,id) on delete restrict
);
create index if not exists satark_case_notes_tenant_case_created_idx
  on public.satark_case_notes(tenant_id,case_id,created_at desc);
alter table public.satark_case_notes enable row level security;
alter table public.satark_case_notes force row level security;
revoke all on public.satark_case_notes from anon,authenticated;
grant select,insert on public.satark_case_notes to authenticated;

drop policy if exists satark_case_notes_member_read on public.satark_case_notes;
create policy satark_case_notes_member_read on public.satark_case_notes
 for select to authenticated using (public.satark_has_membership(tenant_id));
drop policy if exists satark_case_notes_analyst_insert on public.satark_case_notes;
create policy satark_case_notes_analyst_insert on public.satark_case_notes
 for insert to authenticated with check (
   created_by=(select auth.uid())
   and public.satark_has_membership(tenant_id,array['owner','responder','analyst']::text[])
 );

create or replace function public.satark_audit_case_note_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare previous text; payload jsonb; event_time timestamptz := clock_timestamp(); event_details jsonb;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text,0));
  select event_hash into previous from public.satark_audit_events where tenant_id=NEW.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object('note_id',NEW.id,'body_sha256',encode(extensions.digest(convert_to(NEW.body,'UTF8'),'sha256'),'hex'));
  payload := jsonb_build_object('tenant_id',NEW.tenant_id,'case_id',NEW.case_id,'actor_id',NEW.created_by,
    'action','case.note_added','details',event_details,'previous_hash',previous,'created_at',event_time);
  insert into public.satark_audit_events(tenant_id,case_id,actor_id,action,details,previous_hash,event_hash,created_at)
  values(NEW.tenant_id,NEW.case_id,NEW.created_by,'case.note_added',event_details,previous,
    encode(extensions.digest(convert_to(payload::text,'UTF8'),'sha256'),'hex'),event_time);
  return NEW;
end $$;
revoke all on function public.satark_audit_case_note_insert() from public,anon,authenticated;
drop trigger if exists satark_case_note_audit_trigger on public.satark_case_notes;
create trigger satark_case_note_audit_trigger after insert on public.satark_case_notes
for each row execute function public.satark_audit_case_note_insert();
