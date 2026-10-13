-- Durable findings and immutable report snapshots for SATARK cases.
create table if not exists public.satark_findings (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid not null references public.satark_cases(id) on delete cascade,
  finding_key text not null check (length(finding_key) between 1 and 160),
  title text not null check (length(title) between 1 and 240),
  severity text not null check (severity in ('info','low','medium','high','critical','review','unknown')),
  detail text not null check (length(detail) <= 8192),
  evidence_refs jsonb not null default '[]'::jsonb check (jsonb_typeof(evidence_refs) = 'array' and pg_column_size(evidence_refs) <= 16384),
  source text not null default 'FIRSTLIGHT deterministic rules' check (length(source) <= 160),
  confidence numeric check (confidence is null or (confidence >= 0 and confidence <= 1)),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  unique (case_id, finding_key),
  constraint satark_findings_tenant_case_fk foreign key (tenant_id, case_id)
    references public.satark_cases(tenant_id, id) on delete cascade
);
create index if not exists satark_findings_tenant_case_created_idx on public.satark_findings(tenant_id, case_id, created_at);

create table if not exists public.satark_reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid not null references public.satark_cases(id) on delete restrict,
  title text not null check (length(title) between 1 and 240),
  report_version integer not null default 1 check (report_version > 0),
  snapshot jsonb not null check (pg_column_size(snapshot) <= 1048576),
  snapshot_sha256 text not null check (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  unique (case_id, snapshot_sha256),
  constraint satark_reports_tenant_case_fk foreign key (tenant_id, case_id)
    references public.satark_cases(tenant_id, id) on delete restrict
);
create index if not exists satark_reports_tenant_case_created_idx on public.satark_reports(tenant_id, case_id, created_at desc);

alter table public.satark_findings enable row level security;
alter table public.satark_reports enable row level security;
revoke all on public.satark_findings, public.satark_reports from anon, authenticated;
grant select, insert on public.satark_findings to authenticated;
grant select, insert on public.satark_reports to authenticated;

drop policy if exists satark_findings_member_read on public.satark_findings;
create policy satark_findings_member_read on public.satark_findings
  for select to authenticated using (public.satark_has_membership(tenant_id));
drop policy if exists satark_findings_analyst_insert on public.satark_findings;
create policy satark_findings_analyst_insert on public.satark_findings
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and public.satark_has_membership(tenant_id, array['owner','responder','analyst'])
  );
drop policy if exists satark_reports_member_read on public.satark_reports;
create policy satark_reports_member_read on public.satark_reports
  for select to authenticated using (public.satark_has_membership(tenant_id));
drop policy if exists satark_reports_analyst_insert on public.satark_reports;
create policy satark_reports_analyst_insert on public.satark_reports
  for insert to authenticated with check (
    created_by = (select auth.uid())
    and public.satark_has_membership(tenant_id, array['owner','responder','analyst'])
  );

-- Make the audit event timestamp part of the exact canonical payload that is stored.
create or replace function public.satark_audit_case_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare previous text; payload jsonb; event_time timestamptz := clock_timestamp(); event_details jsonb;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous from public.satark_audit_events where tenant_id = NEW.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object('title', NEW.title, 'severity', NEW.severity);
  payload := jsonb_build_object('tenant_id', NEW.tenant_id, 'case_id', NEW.id, 'actor_id', NEW.created_by,
    'action', 'case.created', 'details', event_details, 'previous_hash', previous, 'created_at', event_time);
  insert into public.satark_audit_events(tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at)
  values (NEW.tenant_id, NEW.id, NEW.created_by, 'case.created', event_details, previous,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'), event_time);
  return NEW;
end; $$;

create or replace function public.satark_audit_evidence_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare previous text; payload jsonb; event_time timestamptz := clock_timestamp(); event_details jsonb;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous from public.satark_audit_events where tenant_id = NEW.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object('evidence_id', NEW.id, 'source_sha256', NEW.source_sha256,
    'record_sha256', NEW.record_sha256, 'observed_at', NEW.observed_at);
  payload := jsonb_build_object('tenant_id', NEW.tenant_id, 'case_id', NEW.case_id, 'actor_id', NEW.created_by,
    'action', 'evidence.uploaded', 'details', event_details, 'previous_hash', previous, 'created_at', event_time);
  insert into public.satark_audit_events(tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at)
  values (NEW.tenant_id, NEW.case_id, NEW.created_by, 'evidence.uploaded', event_details, previous,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'), event_time);
  return NEW;
end; $$;

create or replace function public.satark_audit_finding_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare previous text; payload jsonb; event_time timestamptz := clock_timestamp(); event_details jsonb;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous from public.satark_audit_events where tenant_id = NEW.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object('finding_id', NEW.id, 'finding_key', NEW.finding_key, 'severity', NEW.severity);
  payload := jsonb_build_object('tenant_id', NEW.tenant_id, 'case_id', NEW.case_id, 'actor_id', NEW.created_by,
    'action', 'finding.created', 'details', event_details, 'previous_hash', previous, 'created_at', event_time);
  insert into public.satark_audit_events(tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at)
  values (NEW.tenant_id, NEW.case_id, NEW.created_by, 'finding.created', event_details, previous,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'), event_time);
  return NEW;
end; $$;

create or replace function public.satark_audit_report_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare previous text; payload jsonb; event_time timestamptz := clock_timestamp(); event_details jsonb;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous from public.satark_audit_events where tenant_id = NEW.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object('report_id', NEW.id, 'snapshot_sha256', NEW.snapshot_sha256, 'report_version', NEW.report_version);
  payload := jsonb_build_object('tenant_id', NEW.tenant_id, 'case_id', NEW.case_id, 'actor_id', NEW.created_by,
    'action', 'report.generated', 'details', event_details, 'previous_hash', previous, 'created_at', event_time);
  insert into public.satark_audit_events(tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at)
  values (NEW.tenant_id, NEW.case_id, NEW.created_by, 'report.generated', event_details, previous,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'), event_time);
  return NEW;
end; $$;

revoke all on function public.satark_audit_finding_insert() from public, anon, authenticated;
revoke all on function public.satark_audit_report_insert() from public, anon, authenticated;
drop trigger if exists satark_audit_finding_after_insert on public.satark_findings;
create trigger satark_audit_finding_after_insert after insert on public.satark_findings for each row execute function public.satark_audit_finding_insert();
drop trigger if exists satark_audit_report_after_insert on public.satark_reports;
create trigger satark_audit_report_after_insert after insert on public.satark_reports for each row execute function public.satark_audit_report_insert();
