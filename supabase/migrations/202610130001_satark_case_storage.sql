-- SATARK case storage foundation.
-- Apply only to the dedicated SATARK Supabase project after review.
-- Never apply to the unrelated JYC website project.
create extension if not exists pgcrypto;

create table if not exists public.satark_tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 1 and 160),
  created_at timestamptz not null default now()
);

create table if not exists public.satark_memberships (
  tenant_id uuid not null references public.satark_tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'responder', 'analyst', 'viewer')),
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);
create index if not exists satark_memberships_user_idx on public.satark_memberships(user_id, tenant_id);

create table if not exists public.satark_cases (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  title text not null check (length(trim(title)) between 1 and 240),
  status text not null default 'open' check (status in ('open', 'contained', 'resolved', 'archived')),
  severity text not null default 'unknown' check (severity in ('unknown', 'low', 'medium', 'high', 'critical')),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, id),
  metadata jsonb not null default '{}'::jsonb check (pg_column_size(metadata) <= 65536)
);
create index if not exists satark_cases_tenant_updated_idx on public.satark_cases(tenant_id, updated_at desc);

create table if not exists public.satark_evidence (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid not null references public.satark_cases(id) on delete cascade,
  source_label text not null check (length(source_label) <= 160),
  event_kind text not null check (length(event_kind) <= 100),
  observed_at timestamptz not null,
  summary text not null check (length(summary) <= 8192),
  source_sha256 text check (source_sha256 is null or source_sha256 ~ '^[0-9a-f]{64}$'),
  record_sha256 text not null check (record_sha256 ~ '^[0-9a-f]{64}$'),
  metadata jsonb not null default '{}'::jsonb check (pg_column_size(metadata) <= 32768),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  unique (case_id, record_sha256),
  constraint satark_evidence_tenant_case_fk foreign key (tenant_id, case_id)
    references public.satark_cases(tenant_id, id) on delete cascade
);
create index if not exists satark_evidence_case_time_idx on public.satark_evidence(case_id, observed_at);

create table if not exists public.satark_audit_events (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid references public.satark_cases(id) on delete restrict,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null check (length(action) between 1 and 120),
  request_id text check (request_id is null or length(request_id) <= 160),
  details jsonb not null default '{}'::jsonb check (pg_column_size(details) <= 16384),
  previous_hash text check (previous_hash is null or previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash text not null check (event_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  constraint satark_audit_tenant_case_fk foreign key (tenant_id, case_id)
    references public.satark_cases(tenant_id, id) on delete restrict
);
create index if not exists satark_audit_tenant_created_idx on public.satark_audit_events(tenant_id, created_at desc);
create index if not exists satark_audit_case_created_idx on public.satark_audit_events(case_id, created_at asc);

-- Membership checks use a fixed search_path and a narrowly-scoped definer function
-- to avoid recursive RLS evaluation of satark_memberships.
create or replace function public.satark_has_membership(target_tenant uuid, allowed_roles text[] default null)
returns boolean
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
revoke all on function public.satark_has_membership(uuid, text[]) from public;
grant execute on function public.satark_has_membership(uuid, text[]) to authenticated;

alter table public.satark_tenants enable row level security;
alter table public.satark_memberships enable row level security;
alter table public.satark_cases enable row level security;
alter table public.satark_evidence enable row level security;
alter table public.satark_audit_events enable row level security;

create policy satark_tenants_member_read on public.satark_tenants
  for select to authenticated using (public.satark_has_membership(id));
create policy satark_memberships_self_read on public.satark_memberships
  for select to authenticated using (user_id = (select auth.uid()) or public.satark_has_membership(tenant_id, array['owner']));
create policy satark_cases_member_read on public.satark_cases
  for select to authenticated using (public.satark_has_membership(tenant_id));
create policy satark_cases_analyst_write on public.satark_cases
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and public.satark_has_membership(tenant_id, array['owner','responder','analyst'])
  );
create policy satark_cases_analyst_update on public.satark_cases
  for update to authenticated
  using (public.satark_has_membership(tenant_id, array['owner','responder','analyst']))
  with check (public.satark_has_membership(tenant_id, array['owner','responder','analyst']));
create policy satark_evidence_member_read on public.satark_evidence
  for select to authenticated using (public.satark_has_membership(tenant_id));
create policy satark_evidence_analyst_insert on public.satark_evidence
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and public.satark_has_membership(tenant_id, array['owner','responder','analyst'])
  );
create policy satark_audit_member_read on public.satark_audit_events
  for select to authenticated using (public.satark_has_membership(tenant_id));
create policy satark_audit_member_insert on public.satark_audit_events
  for insert to authenticated with check (
    actor_id = (select auth.uid())
    and public.satark_has_membership(tenant_id, array['owner','responder','analyst'])
  );

-- Audit events are append-only for normal database roles. Database owners can still
-- alter data; production deployments need restricted database roles and backups.
create or replace function public.satark_reject_audit_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'SATARK audit events are append-only';
end;
$$;
drop trigger if exists satark_audit_no_update_delete on public.satark_audit_events;
create trigger satark_audit_no_update_delete
  before update or delete on public.satark_audit_events
  for each row execute function public.satark_reject_audit_mutation();

-- Authenticated client grants are intentionally narrow. No tenant or membership
-- insert is granted here; tenant provisioning must be an audited trusted-server flow.
revoke all on public.satark_tenants, public.satark_memberships,
  public.satark_cases, public.satark_evidence, public.satark_audit_events from anon, authenticated;
grant select on public.satark_tenants, public.satark_memberships to authenticated;
grant select, insert, update on public.satark_cases to authenticated;
grant select, insert on public.satark_evidence, public.satark_audit_events to authenticated;
