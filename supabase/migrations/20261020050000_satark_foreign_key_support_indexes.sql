-- Add indexes for SATARK foreign-key columns flagged by the shared Supabase
-- performance advisor. These indexes affect SATARK tables only.
create index if not exists satark_approvals_requested_by_idx
  on public.satark_approvals (requested_by);

create index if not exists satark_approvals_decided_by_idx
  on public.satark_approvals (decided_by);

create index if not exists satark_case_notes_created_by_idx
  on public.satark_case_notes (created_by);

create index if not exists satark_cases_assigned_to_idx
  on public.satark_cases (assigned_to);

create index if not exists satark_investigation_jobs_requested_by_idx
  on public.satark_investigation_jobs (requested_by);
