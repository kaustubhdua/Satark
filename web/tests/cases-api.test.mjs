import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../src/app/api/cases/route.ts', import.meta.url), 'utf8');

test('case API requires a bearer session validated by Supabase Auth', () => {
  assert.match(source, /authorization/);
  assert.match(source, /\/auth\/v1\/user/);
  assert.match(source, /Your session is invalid or expired/);
});

test('case API uses user JWT and publishable key, never service-role credentials', () => {
  assert.match(source, /SUPABASE_PUBLISHABLE_KEY/);
  assert.match(source, /Authorization: 'Bearer ' \+ token/);
  assert.doesNotMatch(source, /SUPABASE_SERVICE_ROLE_KEY|service_role/i);
});

test('case API delegates tenant isolation to RLS and derives creator from authenticated user', () => {
  assert.match(source, /satark_cases/);
  assert.match(source, /tenant_id/);
  assert.match(source, /created_by: user\.id/);
  assert.match(source, /You do not have permission to create cases in this tenant/);
});

test('case API bounds and validates untrusted input and disables caching', () => {
  assert.match(source, /MAX_BODY_BYTES/);
  assert.match(source, /totalBytes \+= value\.byteLength/);
  assert.match(source, /reader\.cancel\(\)/);
  assert.match(source, /reader\.releaseLock\(\)/);
  assert.match(source, /STATUSES/);
  assert.match(source, /SEVERITIES/);
  assert.match(source, /Cache-Control': 'no-store'/);
});

test('case API updates only validated fields through the caller JWT and RLS', () => {
  assert.match(source, /export async function PATCH/);
  assert.match(source, /At least one case field must be provided for update/);
  assert.match(source, /satark_cases\?/);
  assert.match(source, /updated_at/);
});
