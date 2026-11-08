import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = path => readFile(new URL(path, import.meta.url), 'utf8');
const [route, worker, backend, compose] = await Promise.all([
  read('../src/app/api/firstlight/jobs/route.ts'),
  read('../../firstlight_investigation_worker.py'),
  read('../../satark_backend.py'),
  read('../../docker-compose.local.yml'),
]);

test('investigation API routes through SATARK-owned session and tenant authorization', () => {
  assert.match(route, /SATARK_API_INTERNAL_URL/);
  assert.match(route, /\/api\/firstlight\/jobs/);
  assert.doesNotMatch(route, /SUPABASE|supabase\.co|\/auth\/v1|\/rest\/v1/i);
});

test('self-hosted job queue persists tenant-scoped jobs and bounded results', () => {
  assert.match(backend, /class InvestigationJob/);
  assert.match(backend, /satark_investigation_jobs/);
  assert.match(backend, /max_attempts/);
  assert.match(backend, /lease_until/);
  assert.match(worker, /with_for_update\(skip_locked=True\)/);
  assert.match(worker, /MAX_EVIDENCE = 500/);
  assert.match(worker, /MAX_RESULT_BYTES/);
});

test('worker persists findings and report before marking deterministic job successful', () => {
  assert.match(worker, /satark_findings|Finding\(/);
  assert.match(worker, /satark_reports|Report\(/);
  assert.match(worker, /job\.status = "succeeded"/);
  assert.match(worker, /No live response action was executed/);
});

test('self-hosted runtime uses a persistent local data volume', () => {
  assert.match(compose, /SATARK_DATABASE_URL/);
  assert.match(compose, /SATARK_EVIDENCE_DIR/);
  assert.match(compose, /satark_data:\/data/);
});
