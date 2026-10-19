begin;
select plan(11);

-- Deterministic fixtures for isolated local Supabase only. The enclosing
-- transaction rolls back, so no test records survive.
insert into auth.users (
  id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
) values
  ('11111111-1111-4111-8111-111111111111', 'authenticated', 'authenticated',
   'satark-rls-a@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now()),
  ('22222222-2222-4222-8222-222222222222', 'authenticated', 'authenticated',
   'satark-rls-b@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now());

insert into public.satark_tenants (id, name) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'SATARK RLS tenant A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'SATARK RLS tenant B');

insert into public.satark_memberships (tenant_id, user_id, role) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '11111111-1111-4111-8111-111111111111', 'owner'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '22222222-2222-4222-8222-222222222222', 'owner');

insert into public.satark_cases (id, tenant_id, title, status, severity, created_by) values
  ('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   'Tenant A test case', 'open', 'low', '11111111-1111-4111-8111-111111111111'),
  ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
   'Tenant B test case', 'open', 'medium', '22222222-2222-4222-8222-222222222222');

insert into public.satark_evidence (
  tenant_id, case_id, source_label, event_kind, observed_at, summary, record_sha256, created_by
) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
   'tenant-a.txt', 'note', now(), 'synthetic evidence A', repeat('a',64),
   '11111111-1111-4111-8111-111111111111'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'tenant-b.txt', 'note', now(), 'synthetic evidence B', repeat('b',64),
   '22222222-2222-4222-8222-222222222222');

insert into public.satark_findings (
  tenant_id, case_id, finding_key, title, severity, detail, created_by
) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
   'rls-a', 'Tenant A finding', 'low', 'synthetic finding A',
   '11111111-1111-4111-8111-111111111111'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'rls-b', 'Tenant B finding', 'medium', 'synthetic finding B',
   '22222222-2222-4222-8222-222222222222');

insert into public.satark_reports (
  tenant_id, case_id, title, snapshot, snapshot_sha256, created_by
) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
   'Tenant A report', '{"synthetic":true}'::jsonb, repeat('c',64),
   '11111111-1111-4111-8111-111111111111'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'Tenant B report', '{"synthetic":true}'::jsonb, repeat('d',64),
   '22222222-2222-4222-8222-222222222222');

select ok(
  (select count(*) >= 7 and bool_and(c.relrowsecurity)
   from pg_class c join pg_namespace n on n.oid=c.relnamespace
   where n.nspname='public' and c.relkind='r' and c.relname like 'satark_%'),
  'every existing SATARK table has row-level security enabled'
);
select ok(not has_function_privilege('anon', 'public.satark_reject_audit_mutation()', 'EXECUTE'),
  'anon cannot call the audit trigger function');
select ok(not has_function_privilege('authenticated', 'public.satark_reject_audit_mutation()', 'EXECUTE'),
  'authenticated users cannot call the audit trigger function as an RPC');

set local role authenticated;
select set_config('request.jwt.claim.sub', '11111111-1111-4111-8111-111111111111', true);
select set_config('request.jwt.claims',
  '{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}', true);

select is((select count(*)::integer from public.satark_cases
  where tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 1,
  'a tenant member can read their own case');
select is((select count(*)::integer from public.satark_cases
  where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 0,
  'a tenant member cannot read another tenant case');
select is((select count(*)::integer from public.satark_evidence
  where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 0,
  'a tenant member cannot read another tenant evidence');
select is((select count(*)::integer from public.satark_findings
  where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 0,
  'a tenant member cannot read another tenant findings');
select is((select count(*)::integer from public.satark_reports
  where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 0,
  'a tenant member cannot read another tenant reports');
select is((select count(*)::integer from public.satark_audit_events
  where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 0,
  'a tenant member cannot read another tenant audit events');

select throws_ok(
  $$insert into public.satark_cases (tenant_id, title, created_by)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'forbidden cross-tenant write',
      '11111111-1111-4111-8111-111111111111')$$,
  '42501', null,
  'a tenant member cannot create a case in another tenant'
);
select throws_ok(
  $$insert into public.satark_audit_events
    (tenant_id, case_id, actor_id, action, details, event_hash)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      '11111111-1111-4111-8111-111111111111', 'forged.audit', '{}'::jsonb, repeat('e',64))$$,
  '42501', null,
  'a tenant member cannot forge audit events'
);

reset role;
select * from finish();
rollback;
