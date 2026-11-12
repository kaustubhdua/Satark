import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const route = await readFile(new URL('../src/app/api/firstlight/wazuh/alerts/route.ts', import.meta.url), 'utf8');
const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const page = await readFile(new URL('../src/app/firstlight/page.tsx', import.meta.url), 'utf8');
const panel = await readFile(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');
const liveResponse = await readFile(new URL('../src/app/firstlight/live-response-panel.tsx', import.meta.url), 'utf8');

test('Wazuh route uses the same-origin self-hosted API proxy', () => {
  assert.match(route, /proxySatarkApi/);
  assert.doesNotMatch(route, /SUPABASE|supabase\.co|FIRSTLIGHT_WAZUH_SYNC_TOKEN/);
  assert.match(backend, /@router\.get\("\/firstlight\/wazuh\/alerts"\)/);
  assert.match(backend, /FIRSTLIGHT_WAZUH_TENANT_ID/);
  assert.match(backend, /fetch_configured_alerts/);
  assert.match(backend, /Wazuh Indexer is temporarily unavailable/);
});

test('FIRSTLIGHT UI retains read-only Wazuh source provenance', () => {
  assert.match(page, /Load real Wazuh alerts/);
  assert.match(page, /WAZUH_ALERTS_IMPORTED/);
  assert.match(page, /source_record_sha256/);
  assert.match(page, /source_document_id/);
  assert.match(panel, /browser_event_timestamp/);
  assert.match(panel, /persisted_by_worker/);
});

test('production FIRSTLIGHT workspace has no seeded scenarios or simulated approvals', () => {
  assert.doesNotMatch(page, /synthetic|training|SIMULATED|FL-WEB-DEMO/i);
  assert.doesNotMatch(panel, /simulation\.mark_case_contained|Simulation-only response approvals|Approve simulation/i);
  assert.match(page, /authenticatedFetch\('\/api\/firstlight\/wazuh\/alerts/);
  assert.doesNotMatch(page, /Authorization:\s*'Bearer '\s*\+\s*session\.access_token/);
  assert.match(page, /No sample events are loaded/);
});
