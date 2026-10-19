import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const route = await readFile(new URL('../src/app/api/firstlight/wazuh/alerts/route.ts', import.meta.url), 'utf8');
const page = await readFile(new URL('../src/app/firstlight/page.tsx', import.meta.url), 'utf8');
const panel = await readFile(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');
const sourceRoute = await readFile(new URL('../src/app/api/firstlight/evidence/source/route.ts', import.meta.url), 'utf8');

test('Wazuh proxy authenticates a user and uses a private server-side connector token', () => {
  assert.match(route, /export async function GET/);
  assert.match(route, /authenticate\(userToken, auth\)/);
  assert.match(route, /FIRSTLIGHT_WAZUH_SYNC_TOKEN/);
  assert.match(route, /syncToken/);
  assert.doesNotMatch(route, /NEXT_PUBLIC_FIRSTLIGHT_WAZUH_SYNC_TOKEN/);
  assert.match(route, /redirect: 'error'/);
  assert.match(route, /AbortSignal\.timeout/);
});

test('Wazuh proxy bounds the requested page and response body', () => {
  assert.match(route, /limit > 500/);
  assert.match(route, /MAX_RESPONSE_BYTES = 4 \* 1024 \* 1024/);
  assert.match(route, /response exceeded the allowed size/);
  assert.match(route, /Cache-Control/);
});

test('FIRSTLIGHT UI imports normalized real alerts and retains source provenance', () => {
  assert.match(page, /Load real Wazuh alerts/);
  assert.match(page, /WAZUH_ALERTS_IMPORTED/);
  assert.match(page, /source_record_sha256/);
  assert.match(page, /source_document_id/);
});

test('persistent case panel preserves metadata and avoids re-saving worker-ingested source records', () => {
  assert.match(panel, /browser_event_timestamp/);
  assert.match(panel, /persisted_by_worker/);
  assert.match(panel, /item\.metadata \|\| \{\}/);
});

test('source evidence download is tenant-scoped and verifies the object digest', () => {
  assert.match(sourceRoute, /satark_memberships/);
  assert.match(sourceRoute, /satark_cases/);
  assert.match(sourceRoute, /storage\/v1\/object\/authenticated\/satark-evidence/);
  assert.match(sourceRoute, /crypto\.subtle\.digest/);
  assert.match(sourceRoute, /X-Content-SHA256/);
  assert.match(page, /downloadWazuhSource/);
});
