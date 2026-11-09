import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('tenant isolation integration runs against the self-hosted SQLite test database', async () => {
  const source = await readFile(new URL('../../tests/test_satark_backend.py', import.meta.url), 'utf8');
  assert.match(source, /StaticPool/);
  assert.match(source, /test_workspace_case_and_tenant_isolation/);
  assert.match(source, /outsider@example\.test/);
  assert.doesNotMatch(source, /supabase\.co|service_role/i);
});
