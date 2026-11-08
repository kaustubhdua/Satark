import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const proxy = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');

test('case APIs authenticate SATARK sessions and require workspace membership', () => {
  assert.match(backend, /def current_user/);
  assert.match(backend, /def require_membership/);
  assert.match(backend, /@router\.get\("\/cases"\)/);
  assert.match(backend, /@router\.post\("\/cases"/);
  assert.match(backend, /@router\.patch\("\/cases"\)/);
  assert.match(backend, /Workspace access denied/);
});

test('case creation and updates validate fields and audit the mutation', () => {
  assert.match(backend, /class CaseInput/);
  assert.match(backend, /Invalid case status or severity/);
  assert.match(backend, /At least one case field must be provided for update/);
  assert.match(backend, /case\.updated/);
  assert.match(backend, /case\.created/);
});

test('case API proxy is bounded and does not forward database credentials', () => {
  assert.match(proxy, /MAX_REQUEST_BYTES/);
  assert.match(proxy, /redirect: 'error'/);
  assert.doesNotMatch(proxy, /SATARK_DATABASE_URL|SUPABASE_SERVICE_ROLE_KEY/i);
});
