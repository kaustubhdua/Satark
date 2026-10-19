-- Durable approval records for SATARK. This migration intentionally does not enable
-- real response execution: no response executor is trusted until it calls the
-- authorization RPC below immediately before performing an action.
create table if not exists public.satark_approvals (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid not null,
  action_key text not null check (length(btrim(action_key)) between 1 and 120),
  action_payload jsonb not null default '{}'::jsonb check (pg_column_size(action_payload) <= 16384),
  payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
  status text not null default 'pending' check (status in ('pending','approved','rejected','revoked','consumed')),
  requested_by uuid not null references auth.users(id) on delete restrict,
  decided_by uuid references auth.users(id) on delete restrict,
  decision_reason text check (decision_reason is null or length(decision_reason) <= 2000),
  decided_at timestamptz,
  expires_at timestamptz not null default (now() + interval '30 minutes'),
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  constraint satark_approvals_tenant_case_fk foreign key (tenant_id,case_id)
    references public.satark_cases(tenant_id,id) on delete restrict,
  constraint satark_approvals_decision_shape check (
    (status in ('pending') and decided_by is null and decided_at is null)
    or (status in ('approved','rejected','revoked','consumed') and decided_by is not null and decided_at is not null)
  ),
  constraint satark_approvals_not_self_approved check (decided_by is null or decided_by <> requested_by)
);
create index if not exists satark_approvals_tenant_case_created_idx
  on public.satark_approvals(tenant_id,case_id,created_at desc);
create index if not exists satark_approvals_pending_expiry_idx
  on public.satark_approvals(tenant_id,expires_at) where status='pending';
alter table public.satark_approvals enable row level security;
alter table public.satark_approvals force row level security;
revoke all on public.satark_approvals from anon, authenticated;
grant select, insert, update on public.satark_approvals to authenticated;
drop policy if exists satark_approvals_member_read on public.satark_approvals;
create policy satark_approvals_member_read on public.satark_approvals
 for select to authenticated using (satark_private.has_membership(tenant_id));
drop policy if exists satark_approvals_request on public.satark_approvals;
create policy satark_approvals_request on public.satark_approvals
 for insert to authenticated with check (
   requested_by = (select auth.uid())
   and status='pending' and decided_by is null and decided_at is null
   and satark_private.has_membership(tenant_id, array['owner','responder','analyst']::text[])
 );
-- Prevent changing who requested or what exact action/payload is being approved,
-- deleting requests, or changing a terminal decision through direct table writes.
create or replace function public.satark_approvals_guard()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if tg_op = 'DELETE' then raise exception 'approval records cannot be deleted'; end if;
 if tg_op = 'INSERT' then
   if new.status <> 'pending' or new.decided_by is not null or new.decided_at is not null
      or new.consumed_at is not null then raise exception 'approvals must start pending'; end if;
   return new;
 end if;
 if old.status <> 'pending' then raise exception 'terminal approval records are immutable'; end if;
 if new.id is distinct from old.id or new.tenant_id is distinct from old.tenant_id
    or new.case_id is distinct from old.case_id or new.action_key is distinct from old.action_key
    or new.action_payload is distinct from old.action_payload or new.payload_sha256 is distinct from old.payload_sha256
    or new.requested_by is distinct from old.requested_by or new.created_at is distinct from old.created_at
    or new.expires_at is distinct from old.expires_at then
   raise exception 'approval request details are immutable';
 end if;
 if new.status not in ('approved','rejected','revoked') or new.decided_by is null or new.decided_at is null then
   raise exception 'only a complete terminal decision is allowed';
 end if;
 if new.decided_by = old.requested_by then raise exception 'requester cannot approve own action'; end if;
 if not public.satark_private.has_membership(old.tenant_id, array['owner','responder']::text[]) then
   raise exception 'approver lacks required tenant role';
 end if;
 if old.expires_at <= now() then raise exception 'approval request expired'; end if;
 return new;
end $$;
drop trigger if exists satark_approvals_guard_trigger on public.satark_approvals;
create trigger satark_approvals_guard_trigger before insert or update or delete on public.satark_approvals
 for each row execute function public.satark_approvals_guard();
-- An approval is only usable for the exact payload hash and exact action key.
-- No application may perform a real response unless this returns true immediately
-- before execution; absence, expiry, mismatch, consumption, or access failure is false.
create or replace function public.satark_authorize_response_action(
 p_approval_id uuid, p_tenant_id uuid, p_case_id uuid, p_action_key text, p_payload_sha256 text
) returns boolean language plpgsql security definer set search_path = ''
as $$
declare a public.satark_approvals%rowtype;
begin
 if auth.uid() is null then return false; end if;
 if not public.satark_private.has_membership(p_tenant_id, array['owner','responder']::text[]) then return false; end if;
 select * into a from public.satark_approvals
  where id=p_approval_id and tenant_id=p_tenant_id and case_id=p_case_id
  for update;
 if not found or a.status <> 'approved' or a.expires_at <= now()
    or a.action_key <> p_action_key or a.payload_sha256 <> p_payload_sha256
    or a.decided_by is null or a.decided_by = a.requested_by then return false; end if;
 -- This function deliberately only validates authorization. The executor must
 -- atomically consume the approval as part of its own transaction before action.
 return true;
exception when others then return false;
end $$;
revoke all on function public.satark_authorize_response_action(uuid,uuid,uuid,text,text) from public, anon;
grant execute on function public.satark_authorize_response_action(uuid,uuid,uuid,text,text) to authenticated;
