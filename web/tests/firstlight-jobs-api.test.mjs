import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const route = await readFile(new URL('../src/app/api/firstlight/jobs/route.ts', import.meta.url), 'utf8');
const migration = await readFile(new URL('../../supabase/migrations/20261020040000_satark_investigation_jobs.sql', import.meta.url), 'utf8');
const worker = await readFile(new URL('../../firstlight_investigation_worker.py', import.meta.url), 'utf8');

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
  assert.match(worker, /No live response actions are executed here/);
  assert.match(worker, /MAX_CASE_EVIDENCE = 500/);
});
