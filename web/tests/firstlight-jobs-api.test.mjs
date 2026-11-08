import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = path => readFile(new URL(path, import.meta.url), 'utf8');
const [nextConfig, worker, backend, compose] = await Promise.all([
  read('../next.config.ts'),
  read('../../firstlight_investigation_worker.py'),
  read('../../satark_backend.py'),
  read('../../docker-compose.local.yml'),
]);

test('all browser API requests are proxied to SATARK-owned FastAPI routes', () => {
  assert.match(nextConfig, /SATARK_API_INTERNAL_URL/);
  assert.ok(nextConfig.includes("source: '/api/firstlight/:path*'"));
  assert.ok(nextConfig.includes("destination: satarkApi + '/api/firstlight/:path*'"));
  assert.ok(nextConfig.includes("source: '/api/evidence/:path*'"));
  assert.doesNotMatch(nextConfig, /SUPABASE|supabase\.co/i);
});

test('self-hosted job queue persists tenant-scoped jobs and bounded results', () => {
  assert.match(backend, /class InvestigationJob/);
  assert.match(backend, /satark_investigation_jobs/);
  assert.match(backend, /max_attempts/);
  assert.match(backend, /lease_until/);
  assert.match(backend, /idempotency_key/);
  assert.match(worker, /with_for_update\(skip_locked=True\)/);
  assert.match(worker, /MAX_EVIDENCE = 500/);
  assert.match(worker, /MAX_TOTAL_EVIDENCE_BYTES/);
  assert.match(worker, /MAX_RESULT_BYTES/);
});

test('worker persists evidence-linked findings and report before success', () => {
  assert.match(worker, /Finding\(/);
  assert.match(worker, /Report\(/);
  assert.match(worker, /job\.status = "succeeded"/);
  assert.match(worker, /No live response action was executed/);
});

test('self-hosted runtime uses persistent database and evidence storage', () => {
  assert.match(compose, /SATARK_DATABASE_URL/);
  assert.match(compose, /SATARK_EVIDENCE_DIR/);
  assert.match(compose, /satark_data:\/data/);
});
