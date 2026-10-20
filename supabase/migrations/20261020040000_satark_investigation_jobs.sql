-- Durable FIRSTLIGHT investigation queue. This is SATARK-only and additive.
-- The queue is visible to authorized case members; only service_role may claim or
-- transition jobs. No live response execution is performed by this queue.
create table if not exists public.satark_investigation_jobs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid not null,
  requested_by uuid not null references auth.users(id) on delete restrict,
  idempotency_key text not null check (length(btrim(idempotency_key)) between 8 and 160),
  status text not null default 'queued'
    check (status in ('queued','running','succeeded','failed','cancelled')),
  attempts integer not null default 0 check (attempts >= 0 and attempts <= 10),
  max_attempts integer not null default 3 check (max_attempts between 1 and 10),
  run_version text not null default '1.0',
  result jsonb,
  result_sha256 text check (result_sha256 is null or result_sha256 ~ '^[0-9a-f]{64}$'),
  error_code text check (error_code is null or length(error_code) <= 80),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz,
  lease_until timestamptz,
  constraint satark_investigation_jobs_tenant_case_fk
    foreign key (tenant_id, case_id) references public.satark_cases(tenant_id,id) on delete restrict,
  constraint satark_investigation_jobs_result_shape check (
    (status = 'succeeded' and result is not null and result_sha256 is not null and finished_at is not null)
    or status <> 'succeeded'
  )
);
create unique index if not exists satark_investigation_jobs_idempotency_idx
  on public.satark_investigation_jobs(tenant_id,case_id,idempotency_key);
create index if not exists satark_investigation_jobs_claim_idx
  on public.satark_investigation_jobs(status,created_at)
  where status in ('queued','running');
create index if not exists satark_investigation_jobs_case_idx
  on public.satark_investigation_jobs(tenant_id,case_id,created_at desc);

alter table public.satark_investigation_jobs enable row level security;
alter table public.satark_investigation_jobs force row level security;
revoke all on public.satark_investigation_jobs from anon, authenticated;
grant select, insert on public.satark_investigation_jobs to authenticated;
grant select, insert, update on public.satark_investigation_jobs to service_role;

drop policy if exists satark_investigation_jobs_member_read on public.satark_investigation_jobs;
create policy satark_investigation_jobs_member_read on public.satark_investigation_jobs
 for select to authenticated
 using (public.satark_has_membership(tenant_id));

drop policy if exists satark_investigation_jobs_member_enqueue on public.satark_investigation_jobs;
create policy satark_investigation_jobs_member_enqueue on public.satark_investigation_jobs
 for insert to authenticated with check (
   requested_by = (select auth.uid())
   and status = 'queued'
   and attempts = 0
   and result is null
   and result_sha256 is null
   and started_at is null
   and finished_at is null
   and public.satark_has_membership(tenant_id, array['owner','responder','analyst']::text[])
 );

-- Atomically lease one queued job, reclaim expired running leases, and cap retries.
create or replace function public.satark_claim_investigation_job(p_lease_seconds integer default 120)
returns setof public.satark_investigation_jobs
language plpgsql
security definer
set search_path = ''
as $$
declare selected public.satark_investigation_jobs%rowtype;
begin
 if p_lease_seconds < 15 or p_lease_seconds > 600 then
   raise exception 'lease duration must be between 15 and 600 seconds';
 end if;
 update public.satark_investigation_jobs
 set status='failed', error_code='lease_expired_max_attempts', finished_at=now(),
     lease_until=null, updated_at=now()
 where status='running' and lease_until < now() and attempts >= max_attempts;

 select * into selected
 from public.satark_investigation_jobs j
 where (
   j.status = 'queued'
   or (j.status = 'running' and j.lease_until < now())
 )
 and j.attempts < j.max_attempts
 order by j.created_at
 limit 1
 for update skip locked;
 if not found then return; end if;
 update public.satark_investigation_jobs
 set status='running', attempts=attempts+1, started_at=coalesce(started_at,now()),
     lease_until=now() + make_interval(secs => p_lease_seconds),
     updated_at=now(), error_code=null
 where id=selected.id
 returning * into selected;
 return next selected;
end $$;

revoke all on function public.satark_claim_investigation_job(integer) from public, anon, authenticated;
grant execute on function public.satark_claim_investigation_job(integer) to service_role;

create or replace function public.satark_finish_investigation_job(
 p_job_id uuid, p_status text, p_result jsonb default null,
 p_result_sha256 text default null, p_error_code text default null
) returns public.satark_investigation_jobs
language plpgsql
security definer
set search_path = ''
as $$
declare j public.satark_investigation_jobs%rowtype;
begin
 if p_status not in ('succeeded','failed','queued','cancelled') then
   raise exception 'invalid terminal or retry status';
 end if;
 if p_result is not null and pg_column_size(p_result) > 1048576 then
   raise exception 'investigation result exceeds 1 MiB';
 end if;
 if p_result_sha256 is not null and p_result_sha256 !~ '^[0-9a-f]{64}$' then
   raise exception 'invalid result digest';
 end if;
 select * into j from public.satark_investigation_jobs where id=p_job_id for update;
 if not found or j.status <> 'running' then raise exception 'job is not leased'; end if;
 if p_status='succeeded' and (p_result is null or p_result_sha256 is null) then
   raise exception 'successful jobs require a result and digest';
 end if;
 if p_status='queued' and j.attempts >= j.max_attempts then p_status := 'failed'; end if;
 update public.satark_investigation_jobs
 set status=p_status,
     result=case when p_status='succeeded' then p_result else result end,
     result_sha256=case when p_status='succeeded' then p_result_sha256 else result_sha256 end,
     error_code=case when p_status='succeeded' then null else left(coalesce(p_error_code,'worker_error'),80) end,
     finished_at=case when p_status in ('succeeded','failed','cancelled') then now() else null end,
     lease_until=null, updated_at=now()
 where id=p_job_id returning * into j;
 return j;
end $$;
revoke all on function public.satark_finish_investigation_job(uuid,text,jsonb,text,text) from public, anon, authenticated;
grant execute on function public.satark_finish_investigation_job(uuid,text,jsonb,text,text) to service_role;

comment on table public.satark_investigation_jobs is
 'Durable, retryable FIRSTLIGHT deterministic investigation jobs; model analysis is advisory and response execution is not performed here.';
