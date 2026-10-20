import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const migration = readFileSync(
  new URL('../../supabase/migrations/202610200002_satark_trigger_acl_hardening.sql', import.meta.url),
  'utf8',
);

test('SATARK audit trigger function is not callable as a public RPC', () => {
  assert.match(
    migration,
    /revoke all on function public\.satark_reject_audit_mutation\(\) from public, anon, authenticated/i,
  );
});

const approvalGuard = readFileSync(
  new URL('../../supabase/migrations/20261020040028_satark_approval_trigger_acl.sql', import.meta.url),
  'utf8',
);

test('SATARK approval guard trigger function is not directly executable by API roles', () => {
  assert.match(approvalGuard, /revoke all on function public\.satark_approvals_guard\(\) from public, anon, authenticated, service_role/i);
});
