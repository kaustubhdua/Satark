import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const proxy = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');
const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const worker = await readFile(new URL('../../firstlight_investigation_worker.py', import.meta.url), 'utf8');
const wazuhWorker = await readFile(new URL('../../firstlight_wazuh_worker.py', import.meta.url), 'utf8');
const panel = await readFile(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');
const page = await readFile(new URL('../src/app/firstlight/page.tsx', import.meta.url), 'utf8');

test('FIRSTLIGHT API proxy bounds request bytes and rejects redirects', () => {
  assert.match(proxy, /MAX_REQUEST_BYTES/);
  assert.match(proxy, /request\.arrayBuffer\(\)/);
  assert.match(proxy, /redirect: 'error'/);
});

test('evidence, reports, jobs and findings are bounded and persisted by SATARK', () => {
  assert.match(backend, /MAX_UPLOAD = 4 \* 1024 \* 1024/);
  assert.match(backend, /MAX_UPLOAD = 4 \* 1024 \* 1024/);
  assert.match(worker, /MAX_EVIDENCE = 500/);
  assert.match(worker, /MAX_TOTAL_EVIDENCE_BYTES/);
  assert.match(worker, /Finding\(/);
  assert.match(worker, /Report\(/);
});

test('Wazuh ingestion uses SATARK-owned storage and tenant-scoped checkpoints', () => {
  assert.match(wazuhWorker, /WazuhSatarkWorker/);
  assert.match(wazuhWorker, /IngestionCheckpoint/);
  assert.match(wazuhWorker, /SATARK_EVIDENCE_DIR/);
  assert.match(wazuhWorker, /wazuh\.evidence\.ingested/);
  assert.doesNotMatch(wazuhWorker, /SUPABASE|supabase\.co|service_role|\/rest\/v1|\/storage\/v1/i);
});

test('saved FIRSTLIGHT evidence reload preserves its original browser digest', () => {
  assert.ok(panel.includes("digest: typeof row.metadata?.browser_record_sha256 === 'string' ? row.metadata.browser_record_sha256 : ''"));
  assert.ok(panel.includes('never substitute a different hash'));
});

test('saved FIRSTLIGHT reports distinguish browser activity from durable server audit events', () => {
  assert.ok(page.includes('activity_log: audit'));
  assert.ok(panel.includes('Durable database audit events are recorded separately from this browser activity view'));
  assert.doesNotMatch(panel, /simulated_response_decisions|simulation\.mark_case_contained/);
});

test('independent FIRSTLIGHT model agent implementation remains opt-in and read-only', async () => {
  const agents = await readFile(new URL('../../firstlight_agents.py', import.meta.url), 'utf8');
  assert.ok(agents.includes('FIRSTLIGHT_MODEL_AGENTS_ENABLED'));
  assert.ok(agents.includes('ALLOWED_TOOL_NAMES: frozenset[str] = frozenset()'));
});
