import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const route = await readFile(new URL('../src/app/api/firstlight/jobs/route.ts', import.meta.url), 'utf8');
const migration = await readFile(new URL('../../supabase/migrations/20261020031055_satark_investigation_jobs.sql', import.meta.url), 'utf8');
const worker = await readFile(new URL('../../firstlight_investigation_worker.py', import.meta.url), 'utf8');
const auditMigration = await readFile(new URL('../../supabase/migrations/20261020031618_satark_investigation_job_audit.sql', import.meta.url), 'utf8');
const caseWorkflowMigration = await readFile(new URL('../../supabase/migrations/20261020032710_satark_case_assignment_notes.sql', import.meta.url), 'utf8');

test('durable job API authenticates users and validates tenant/case/idempotency inputs', () => {
  assert.match(route, /\/auth\/v1\/user/);
  assert.match(route, /tenant_id/);
  assert.match(route, /case_id/);
  assert.match(route, /idempotency_key/);
  assert.match(route, /resolution=ignore-duplicates/);
  assert.match(route, /signal: AbortSignal\.timeout/);
  assert.doesNotMatch(route, /SUPABASE_SERVICE_ROLE_KEY/);
});

test('database queue is tenant-scoped and worker-only for claiming/completion', () => {
  assert.match(migration, /enable row level security/i);
  assert.match(migration, /force row level security/i);
  assert.match(migration, /satark_has_membership\(tenant_id, array\['owner','responder','analyst'\]/);
  assert.match(migration, /for update skip locked/i);
  assert.match(migration, /grant execute on function public\.satark_claim_investigation_job\(integer\) to service_role/i);
  assert.match(migration, /revoke all on function public\.satark_claim_investigation_job\(integer\) from public, anon, authenticated/i);
  assert.match(migration, /idempotency_key/);
});

test('worker persists findings and report before marking a deterministic job successful', () => {
  assert.match(worker, /satark_findings/);
  assert.match(worker, /satark_reports/);
  assert.match(worker, /satark_finish_investigation_job/);
  assert.match(worker, /No response actions are executed here/);
  assert.match(worker, /MAX_CASE_EVIDENCE = 500/);
});

test('job state transitions append to the existing tenant audit hash chain', () => {
  assert.match(auditMigration, /after insert or update on public\.satark_investigation_jobs/i);
  assert.match(auditMigration, /public\.satark_audit_events/);
  assert.match(auditMigration, /extensions\.digest/);
  assert.match(auditMigration, /investigation_job\.status_changed/);
  assert.match(auditMigration, /revoke all on function public\.satark_audit_investigation_job\(\) from public, anon, authenticated/i);
});

test('case assignment is tenant-bound and analyst notes are append-only', () => {
  assert.match(caseWorkflowMigration, /assigned_to uuid references auth\.users/i);
  assert.match(caseWorkflowMigration, /case assignee must be an owner, responder, or analyst in the same tenant/);
  assert.match(caseWorkflowMigration, /old\.assigned_to is not distinct from new\.assigned_to/i);
  assert.match(caseWorkflowMigration, /create table if not exists public\.satark_case_notes/i);
  assert.match(caseWorkflowMigration, /force row level security/i);
  assert.match(caseWorkflowMigration, /grant select,insert on public\.satark_case_notes to authenticated/i);
  assert.match(caseWorkflowMigration, /case\.note_added/);
  assert.doesNotMatch(caseWorkflowMigration, /grant .*update.*public\.satark_case_notes/i);
});
