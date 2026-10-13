import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const migration = readFileSync(new URL('../../supabase/migrations/202610140001_satark_foreign_key_indexes.sql', import.meta.url), 'utf8');

test('SATARK foreign-key indexes are scoped to SATARK tables and idempotent', () => {
  const expected = [
    /satark_audit_events_actor_id_idx\s+on public\.satark_audit_events \(actor_id\)/i,
    /satark_audit_events_tenant_case_idx\s+on public\.satark_audit_events \(tenant_id, case_id\)/i,
    /satark_cases_created_by_idx\s+on public\.satark_cases \(created_by\)/i,
    /satark_evidence_created_by_idx\s+on public\.satark_evidence \(created_by\)/i,
    /satark_evidence_tenant_case_idx\s+on public\.satark_evidence \(tenant_id, case_id\)/i,
    /satark_evidence_tenant_id_idx\s+on public\.satark_evidence \(tenant_id\)/i,
  ];
  for (const pattern of expected) assert.match(migration, pattern);
  assert.equal((migration.match(/create index if not exists/gi) || []).length, expected.length);
  assert.doesNotMatch(migration, /drop\s+(table|index)|telegram_/i);
});
