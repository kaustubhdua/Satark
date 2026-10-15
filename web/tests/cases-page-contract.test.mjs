import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const page = await readFile(new URL('../src/app/cases/page.tsx', import.meta.url), 'utf8');
const auth = await readFile(new URL('../src/lib/satark-auth.ts', import.meta.url), 'utf8');
const nav = await readFile(new URL('../src/app/site-header.tsx', import.meta.url), 'utf8');

test('case management is authenticated and tenant-scoped', () => {
  assert.match(page, /getSession\(\)/);
  assert.match(page, /listMyTenants\(\)/);
  assert.match(page, /getActiveTenant\(\)/);
  assert.match(page, /listCases\(active\.id\)/);
  assert.match(page, /tenant_id: tenantId/);
  assert.match(auth, /Authorization: 'Bearer ' \+ session\.access_token/);
  assert.doesNotMatch(page, /SUPABASE_SERVICE_ROLE_KEY|service_role/i);
});

test('case queue exposes create, search, status filters and status updates', () => {
  assert.match(page, /Create a case/);
  assert.match(page, /Search cases/);
  assert.match(page, /case-status-filter/);
  assert.match(page, /changeStatus/);
  assert.match(page, /method: 'PATCH'/);
  assert.match(page, /open.*contained.*resolved.*archived/s);
});

test('case management is reachable from primary navigation', () => {
  assert.match(nav, /href: '\/cases', label: 'Cases'/);
  assert.match(page, /Open FIRSTLIGHT/);
});
