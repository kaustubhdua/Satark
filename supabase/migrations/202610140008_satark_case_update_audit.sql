-- Record case updates in the append-only tenant audit chain.
create or replace function public.satark_audit_case_update()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare previous text; payload jsonb; event_time timestamptz := clock_timestamp(); event_details jsonb;
begin
  if OLD.title is not distinct from NEW.title
    and OLD.status is not distinct from NEW.status
    and OLD.severity is not distinct from NEW.severity
    and OLD.metadata is not distinct from NEW.metadata then
    return NEW;
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id::text, 0));
  select event_hash into previous from public.satark_audit_events where tenant_id = NEW.tenant_id order by id desc limit 1;
  event_details := jsonb_build_object(
    'case_id', NEW.id,
    'before', jsonb_build_object('title', OLD.title, 'status', OLD.status, 'severity', OLD.severity, 'metadata', OLD.metadata),
    'after', jsonb_build_object('title', NEW.title, 'status', NEW.status, 'severity', NEW.severity, 'metadata', NEW.metadata)
  );
  payload := jsonb_build_object('tenant_id', NEW.tenant_id, 'case_id', NEW.id, 'actor_id', auth.uid(),
    'action', 'case.updated', 'details', event_details, 'previous_hash', previous, 'created_at', event_time);
  insert into public.satark_audit_events(tenant_id, case_id, actor_id, action, details, previous_hash, event_hash, created_at)
  values (NEW.tenant_id, NEW.id, auth.uid(), 'case.updated', event_details, previous,
    encode(extensions.digest(convert_to(payload::text, 'UTF8'), 'sha256'), 'hex'), event_time);
  return NEW;
end; $$;
revoke all on function public.satark_audit_case_update() from public, anon, authenticated;
drop trigger if exists satark_audit_case_after_update on public.satark_cases;
create trigger satark_audit_case_after_update after update on public.satark_cases
for each row execute function public.satark_audit_case_update();
