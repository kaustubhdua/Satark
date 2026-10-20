-- Append durable investigation job lifecycle transitions to SATARK's existing hash chain.
-- No other application tables or audit streams are changed.
create or replace function public.satark_audit_investigation_job()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  previous text;
  payload jsonb;
  event_time timestamptz := clock_timestamp();
  event_details jsonb;
  event_action text;
  event_actor uuid;
begin
  if tg_op = 'UPDATE'
     and old.status is not distinct from new.status
     and old.result_sha256 is not distinct from new.result_sha256
     and old.error_code is not distinct from new.error_code then
    return new;
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(new.tenant_id::text, 0));
  select event_hash into previous
  from public.satark_audit_events
  where tenant_id = new.tenant_id
  order by id desc limit 1;

  event_action := case when tg_op = 'INSERT' then 'investigation_job.queued'
                       else 'investigation_job.status_changed' end;
  event_actor := case when tg_op = 'INSERT' then new.requested_by else null end;
  event_details := jsonb_build_object(
    'job_id', new.id,
    'case_id', new.case_id,
    'status', new.status,
    'attempts', new.attempts,
    'max_attempts', new.max_attempts,
    'result_sha256', new.result_sha256,
    'error_code', new.error_code,
    'requester_id', new.requested_by
  );
  payload := jsonb_build_object(
    'tenant_id', new.tenant_id,
    'case_id', new.case_id,
    'actor_id', event_actor,
    'action', event_action,
    'details', event_details,
    'previous_hash', previous,
    'created_at', event_time
  );
  insert into public.satark_audit_events(
    tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at
  ) values (
    new.tenant_id, new.case_id, event_actor, event_action, event_details, previous,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'),
    event_time
  );
  return new;
end;
$$;
revoke all on function public.satark_audit_investigation_job() from public, anon, authenticated;
drop trigger if exists satark_investigation_job_audit_trigger on public.satark_investigation_jobs;
create trigger satark_investigation_job_audit_trigger
after insert or update on public.satark_investigation_jobs
for each row execute function public.satark_audit_investigation_job();
