import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const migration = readFileSync(new URL('../../supabase/migrations/202610130001_satark_case_storage.sql', import.meta.url), 'utf8');

test('case storage migration enables RLS on all tenant-scoped tables', () => {
  for (const table of ['satark_tenants', 'satark_memberships', 'satark_cases', 'satark_evidence', 'satark_audit_events']) {
    assert.match(migration, new RegExp('alter table public\\.' + table + ' enable row level security', 'i'), table);
  }
});

test('tenant data policies derive identity from auth.uid and membership', () => {
  assert.match(migration, /m\.user_id = \(select auth\.uid\(\)\)/);
  assert.match(migration, /satark_has_membership\(tenant_id\)/);
  assert.match(migration, /created_by = \(select auth\.uid\(\)\)/);
  assert.match(migration, /revoke all on public\.satark_tenants, public\.satark_memberships/i);
});

test('audit trail disallows ordinary update and delete mutations', () => {
  assert.match(migration, /before update or delete on public\.satark_audit_events/i);
  assert.match(migration, /raise exception 'SATARK audit events are append-only'/i);
  assert.match(migration, /event_hash text not null check \(event_hash ~ '\^\[0-9a-f\]\{64\}\$'\)/);
});

test('tenant/case consistency and bounded fields are enforced by database constraints', () => {
  assert.match(migration, /foreign key \(tenant_id, case_id\)/i);
  assert.match(migration, /pg_column_size\(metadata\) <= 65536/);
  assert.match(migration, /length\(summary\) <= 8192/);
});
