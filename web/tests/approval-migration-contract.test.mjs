import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const foundationMigration = readFileSync(
  new URL('../../supabase/migrations/202610200001_satark_durable_approvals.sql', import.meta.url),
  'utf8',
);
const hardeningMigration = readFileSync(
  new URL('../../supabase/migrations/202610200003_satark_approval_security_hardening.sql', import.meta.url),
  'utf8',
);
const migration = foundationMigration + '\\n' + hardeningMigration;

test('durable approvals are tenant-scoped and protected by RLS', () => {
  assert.match(migration, /create table if not exists public\.satark_approvals/i);
  assert.match(migration, /alter table public\.satark_approvals enable row level security/i);
  assert.match(migration, /alter table public\.satark_approvals force row level security/i);
  assert.match(migration, /satark_approvals_member_read[\s\S]*?satark_has_membership\(tenant_id\)/i);
  assert.match(migration, /requested_by = \(select auth\.uid\(\)\)/i);
  assert.match(migration, /revoke all on public\.satark_approvals from anon, authenticated/i);
  assert.match(migration, /grant select, insert on public\.satark_approvals to authenticated/i);
});

test('RLS policies use the private membership helper that has the required execution grant', () => {
  assert.match(hardeningMigration, /satark_private\.has_membership\(tenant_id\)/i);
  assert.doesNotMatch(hardeningMigration, /public\.satark_has_membership/i);
});

test('approval requests bind immutable action and payload identity', () => {
  assert.match(migration, /action_key text not null/i);
  assert.match(migration, /action_payload jsonb not null/i);
  assert.match(migration, /payload_sha256 text not null check \(payload_sha256 ~ '\^\[0-9a-f\]\{64\}\$'\)/i);
  assert.match(migration, /new\.payload_sha256 := encode\(\s*extensions\.digest/i);
  assert.match(migration, /new\.expires_at > now\(\) \+ interval '30 minutes'/i);
  assert.match(migration, /approval request details are immutable/i);
  assert.match(migration, /requester cannot approve own action/i);
});

test('approval decision is role-gated, expiry-aware, one-time, and audited', () => {
  assert.match(migration, /create or replace function public\.satark_decide_approval/i);
  assert.match(migration, /a\.status <> 'pending' or a\.expires_at <= now\(\)/i);
  assert.match(migration, /array\['owner','responder'\]::text\[\]/i);
  assert.match(migration, /approval\.'\|\|p_decision/i);
  assert.match(migration, /insert into public\.satark_audit_events/i);
  assert.match(migration, /create or replace function public\.satark_consume_response_approval/i);
  assert.match(migration, /set status='consumed', consumed_at=event_time/i);
  assert.match(migration, /'approval\.consumed'/i);
  assert.match(migration, /revoke all on function public\.satark_consume_response_approval\(uuid,uuid,uuid,text,text\) from public, anon/i);
});

test('trigger-only approval guard is not exposed as an RPC', () => {
  assert.match(migration, /create trigger satark_approvals_guard_trigger[\s\S]*?execute function public\.satark_approvals_guard\(\)/i);
  assert.match(migration, /revoke all on function public\.satark_approvals_guard\(\) from public, anon, authenticated/i);
});

test('approval authorization fails closed and binds the exact action payload', () => {
  assert.match(migration, /create or replace function public\.satark_authorize_response_action/i);
  assert.match(migration, /auth\.uid\(\) is null then return false/i);
  assert.match(migration, /a\.action_key <> p_action_key or a\.payload_sha256 <> p_payload_sha256/i);
  assert.match(migration, /exception when others then return false/i);
});
