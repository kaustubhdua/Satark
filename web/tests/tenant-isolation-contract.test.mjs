import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const tests = await readFile(new URL('../../tests/test_satark_backend.py', import.meta.url), 'utf8');

test('every tenant-scoped API resolves membership before reading or writing', () => {
  assert.match(backend, /def require_membership/);
  assert.match(backend, /Workspace access denied/);
  assert.match(backend, /def list_cases[\s\S]*?require_membership/);
  assert.match(backend, /def create_case[\s\S]*?require_membership/);
  assert.match(backend, /def create_note[\s\S]*?require_membership/);
  assert.match(backend, /def upload_evidence[\s\S]*?require_membership/);
});

test('SQLite integration tests prove cross-tenant read and write denial', () => {
  assert.match(tests, /test_workspace_case_and_tenant_isolation/);
  assert.match(tests, /outsider@example\.test/);
  assert.match(tests, /denied\.status_code == 403/);
  assert.match(tests, /denied_create\.status_code == 403/);
});
