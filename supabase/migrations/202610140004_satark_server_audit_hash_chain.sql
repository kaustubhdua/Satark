-- Database-generated audit events for case/evidence writes.
-- Hashes are generated server-side in the database and chained per tenant.
create or replace function public.satark_audit_case_insert()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  previous text;
  payload jsonb;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous
    from public.satark_audit_events
    where tenant_id = NEW.tenant_id
    order by id desc limit 1;
  payload := jsonb_build_object(
    'tenant_id', NEW.tenant_id, 'case_id', NEW.id, 'actor_id', NEW.created_by,
    'action', 'case.created', 'details', jsonb_build_object('title', NEW.title, 'severity', NEW.severity),
    'previous_hash', previous, 'created_at', NEW.created_at
  );
  insert into public.satark_audit_events(tenant_id, case_id, actor_id, action, details, previous_hash, event_hash)
  values (NEW.tenant_id, NEW.id, NEW.created_by, 'case.created',
    jsonb_build_object('title', NEW.title, 'severity', NEW.severity), previous,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'));
  return NEW;
end;
$$;

create or replace function public.satark_audit_evidence_insert()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  previous text;
  payload jsonb;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous
    from public.satark_audit_events
    where tenant_id = NEW.tenant_id
    order by id desc limit 1;
  payload := jsonb_build_object(
    'tenant_id', NEW.tenant_id, 'case_id', NEW.case_id, 'actor_id', NEW.created_by,
    'action', 'evidence.uploaded', 'details', jsonb_build_object(
      'evidence_id', NEW.id, 'source_sha256', NEW.source_sha256,
      'record_sha256', NEW.record_sha256, 'observed_at', NEW.observed_at
    ),
    'previous_hash', previous, 'created_at', NEW.created_at
  );
  insert into public.satark_audit_events(tenant_id, case_id, actor_id, action, details, previous_hash, event_hash)
  values (NEW.tenant_id, NEW.case_id, NEW.created_by, 'evidence.uploaded',
    jsonb_build_object('evidence_id', NEW.id, 'source_sha256', NEW.source_sha256,
      'record_sha256', NEW.record_sha256, 'observed_at', NEW.observed_at),
    previous, encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'));
  return NEW;
end;
$$;

revoke all on function public.satark_audit_case_insert() from public, anon, authenticated;
revoke all on function public.satark_audit_evidence_insert() from public, anon, authenticated;
drop trigger if exists satark_audit_case_after_insert on public.satark_cases;
create trigger satark_audit_case_after_insert after insert on public.satark_cases
for each row execute function public.satark_audit_case_insert();
drop trigger if exists satark_audit_evidence_after_insert on public.satark_evidence;
create trigger satark_audit_evidence_after_insert after insert on public.satark_evidence
for each row execute function public.satark_audit_evidence_insert();
