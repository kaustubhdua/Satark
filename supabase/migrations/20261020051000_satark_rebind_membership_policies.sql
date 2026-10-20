-- Repair SATARK policies left on the public membership wrapper after its EXECUTE
-- grant was revoked. These policies must use the non-exposed, executable helper.
-- Scope is SATARK only; no data rows or other applications are modified.

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

drop policy if exists satark_case_notes_member_read on public.satark_case_notes;
create policy satark_case_notes_member_read on public.satark_case_notes
  for select to authenticated
  using (satark_private.has_membership(tenant_id));

drop policy if exists satark_case_notes_analyst_insert on public.satark_case_notes;
create policy satark_case_notes_analyst_insert on public.satark_case_notes
  for insert to authenticated
  with check (
    created_by = (select auth.uid())
    and satark_private.has_membership(
      tenant_id, array['owner','responder','analyst']::text[]
    )
  );

drop policy if exists satark_investigation_jobs_member_read on public.satark_investigation_jobs;
create policy satark_investigation_jobs_member_read on public.satark_investigation_jobs
  for select to authenticated
  using (satark_private.has_membership(tenant_id));

drop policy if exists satark_investigation_jobs_member_enqueue on public.satark_investigation_jobs;
create policy satark_investigation_jobs_member_enqueue on public.satark_investigation_jobs
  for insert to authenticated
  with check (
    requested_by = (select auth.uid())
    and status = 'queued'
    and attempts = 0
    and result is null
    and result_sha256 is null
    and started_at is null
    and finished_at is null
    and satark_private.has_membership(
      tenant_id, array['owner','responder','analyst']::text[]
    )
  );
