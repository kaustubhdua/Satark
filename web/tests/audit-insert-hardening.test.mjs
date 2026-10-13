import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const migration = readFileSync(new URL('../../supabase/migrations/202610140010_satark_audit_insert_hardening.sql', import.meta.url), 'utf8');

test('authenticated clients cannot append forged SATARK audit events directly', () => {
  assert.match(migration, /revoke insert on public\.satark_audit_events from anon, authenticated/i);
  assert.match(migration, /drop policy if exists satark_audit_member_insert on public\.satark_audit_events/i);
  assert.doesNotMatch(migration, /grant\s+insert\s+on\s+public\.satark_audit_events/i);
});
