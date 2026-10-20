begin;
select plan(35);

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
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now()),
  ('33333333-3333-4333-8333-333333333333', 'authenticated', 'authenticated',
   'satark-rls-viewer@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now());

insert into public.satark_tenants (id, name) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'SATARK RLS tenant A'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'SATARK RLS tenant B');

insert into public.satark_memberships (tenant_id, user_id, role) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '11111111-1111-4111-8111-111111111111', 'owner'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '22222222-2222-4222-8222-222222222222', 'owner'),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '33333333-3333-4333-8333-333333333333', 'viewer');

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

select ok((
  select position('satark_private.has_membership' in coalesce(with_check, '')) > 0
    and position('satark_has_membership' in coalesce(with_check, '')) = 0
    and position('satark_cases' in coalesce(with_check, '')) > 0
  from pg_policies
  where schemaname = 'storage' and tablename = 'objects'
    and policyname = 'satark_evidence_object_insert'
), 'evidence upload policy uses private membership helper and checks the owning case');

select ok((
  select position('satark_private.has_membership' in coalesce(qual, '')) > 0
    and position('satark_has_membership' in coalesce(qual, '')) = 0
    and position('satark_cases' in coalesce(qual, '')) > 0
    and position('analyst' in coalesce(qual, '')) > 0
    and position('wazuh' in coalesce(qual, '')) > 0
  from pg_policies
  where schemaname = 'storage' and tablename = 'objects'
    and policyname = 'satark_evidence_object_read'
), 'evidence read policy uses private membership helper and checks the owning case');

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
insert into storage.objects (bucket_id, name, owner, metadata) values
  ('satark-evidence',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/dddddddd-dddd-4ddd-8ddd-dddddddddddd/22222222-2222-4222-8222-222222222222_foreign.txt',
   '22222222-2222-4222-8222-222222222222',
   '{"mimetype":"text/plain","size":1}'::jsonb),
  ('satark-evidence',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/cccccccc-cccc-4ccc-8ccc-cccccccccccc/wazuh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json',
   '11111111-1111-4111-8111-111111111111',
   '{"mimetype":"application/json","size":64}'::jsonb);

select ok(
  (select count(*) >= 7 and bool_and(c.relrowsecurity)
   from pg_class c join pg_namespace n on n.oid=c.relnamespace
   where n.nspname='public' and c.relkind='r' and c.relname like 'satark_%'),
  'every existing SATARK table has row-level security enabled'
);
select ok(
  (select count(*) = 2
     and bool_and((coalesce(qual,'') || coalesce(with_check,'')) like '%satark_private.has_membership%')
     and bool_and((coalesce(qual,'') || coalesce(with_check,'')) not like '%public.satark_has_membership%')
   from pg_policies
   where schemaname='storage' and tablename='objects'
     and policyname in ('satark_evidence_object_insert','satark_evidence_object_read')),
  'SATARK evidence storage policies use the executable private membership helper'
);
select ok(has_function_privilege('authenticated', 'satark_private.has_membership(uuid,text[])', 'EXECUTE'),
  'authenticated policies can execute the private membership helper');
select ok(not has_function_privilege('anon', 'public.satark_reject_audit_mutation()', 'EXECUTE'),
  'anon cannot call the audit trigger function');
select ok(not has_function_privilege('authenticated', 'public.satark_reject_audit_mutation()', 'EXECUTE'),
  'authenticated users cannot call the audit trigger function as an RPC');

set local role authenticated;
select set_config('request.jwt.claim.sub', '11111111-1111-4111-8111-111111111111', true);
select set_config('request.jwt.claims',
  '{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}', true);

select lives_ok(
  $insert$ insert into storage.objects (bucket_id, name, owner, metadata)
    values ('satark-evidence',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/cccccccc-cccc-4ccc-8ccc-cccccccccccc/11111111-1111-4111-8111-111111111111_own.txt',
      '11111111-1111-4111-8111-111111111111',
      '{"mimetype":"text/plain","size":1}'::jsonb)$insert$,
  'a tenant member can upload evidence to their own case'
);
select throws_ok(
  $insert$ insert into storage.objects (bucket_id, name, owner, metadata)
    values ('satark-evidence',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/cccccccc-cccc-4ccc-8ccc-cccccccccccc/not-a-valid-object-key.txt',
      '11111111-1111-4111-8111-111111111111',
      '{"mimetype":"text/plain","size":1}'::jsonb)$insert$,
  '42501', null, 'evidence uploads reject unsupported object-key formats'
);
select is((select count(*)::integer from storage.objects
  where bucket_id='satark-evidence'
    and name='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/cccccccc-cccc-4ccc-8ccc-cccccccccccc/11111111-1111-4111-8111-111111111111_own.txt'),
  1, 'a tenant member can read their own evidence object');
select is((select count(*)::integer from storage.objects
  where bucket_id='satark-evidence'
    and name='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/dddddddd-dddd-4ddd-8ddd-dddddddddddd/22222222-2222-4222-8222-222222222222_foreign.txt'),
  0, 'a tenant member cannot read another tenant storage object');
select throws_ok(
  $insert$ insert into storage.objects (bucket_id, name, owner, metadata)
    values ('satark-evidence',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/dddddddd-dddd-4ddd-8ddd-dddddddddddd/11111111-1111-4111-8111-111111111111_forbidden.txt',
      '11111111-1111-4111-8111-111111111111',
      '{"mimetype":"text/plain","size":1}'::jsonb)$insert$,
  '42501', null, 'a tenant member cannot upload evidence into another tenant'
);
select is((select count(*)::integer from public.satark_cases
  where tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 1,
  'a tenant member can read their own case');
select is((select count(*)::integer from public.satark_evidence
  where tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 1,
  'a tenant member can read their own evidence');
select is((select count(*)::integer from public.satark_findings
  where tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 1,
  'a tenant member can read their own findings');
select is((select count(*)::integer from public.satark_reports
  where tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 1,
  'a tenant member can read their own reports');
select ok((select count(*) > 0 from public.satark_audit_events
  where tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
  'a tenant member can read their own audit events');
select lives_ok(
  $update$ update public.satark_cases set title='Tenant A updated'
    where id='cccccccc-cccc-4ccc-8ccc-cccccccccccc' $update$,
  'a tenant member can update their own case'
);
select is((select count(*)::integer from public.satark_cases
  where id='cccccccc-cccc-4ccc-8ccc-cccccccccccc' and title='Tenant A updated'),
  1, 'case updates persist in the database');
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
select lives_ok(
  $update$ update public.satark_cases set title='forbidden cross-tenant update'
    where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' $update$,
  'a tenant member cannot update another tenant case'
);
select throws_ok(
  $delete$ delete from public.satark_cases
    where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' $delete$,
  '42501', null, 'a tenant member cannot delete another tenant case'
);
select set_config('request.jwt.claim.sub', '22222222-2222-4222-8222-222222222222', true);
select set_config('request.jwt.claims',
  '{"sub":"22222222-2222-4222-8222-222222222222","role":"authenticated"}', true);
select is((select count(*)::integer from public.satark_cases
  where id='dddddddd-dddd-4ddd-8ddd-dddddddddddd' and title='Tenant B test case'),
  1, 'cross-tenant update and delete attempts leave the other tenant case unchanged');
select set_config('request.jwt.claim.sub', '11111111-1111-4111-8111-111111111111', true);
select set_config('request.jwt.claims',
  '{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}', true);

select throws_ok(
  $$insert into public.satark_cases (tenant_id, title, created_by)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'forbidden cross-tenant write',
      '11111111-1111-4111-8111-111111111111')$$,
  '42501', null,
  'a tenant member cannot create a case in another tenant'
);
select throws_ok(
  $insert$ insert into public.satark_evidence
    (tenant_id, case_id, source_label, event_kind, observed_at, summary, record_sha256, created_by)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'forbidden.txt', 'note', now(),
      'cross-tenant evidence', repeat('f',64), '11111111-1111-4111-8111-111111111111')$insert$,
  '42501', null, 'a tenant member cannot insert evidence in another tenant'
);
select throws_ok(
  $insert$ insert into public.satark_findings
    (tenant_id, case_id, finding_key, title, severity, detail, created_by)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'forbidden-finding', 'Forbidden', 'low',
      'cross-tenant finding', '11111111-1111-4111-8111-111111111111')$insert$,
  '42501', null, 'a tenant member cannot insert findings in another tenant'
);
select throws_ok(
  $insert$ insert into public.satark_reports
    (tenant_id, case_id, title, snapshot, snapshot_sha256, created_by)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'Forbidden report', '{"test":true}'::jsonb,
      repeat('f',64), '11111111-1111-4111-8111-111111111111')$insert$,
  '42501', null, 'a tenant member cannot insert reports in another tenant'
);
select throws_ok(
  $insert$ insert into public.satark_audit_events
    (tenant_id, case_id, actor_id, action, details, event_hash)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      '11111111-1111-4111-8111-111111111111', 'forged.audit', '{}'::jsonb, repeat('e',64))$insert$,
  '42501', null,
  'a tenant member cannot forge audit events'
);

select is((select count(*)::integer from storage.objects
  where bucket_id='satark-evidence'
    and name='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/cccccccc-cccc-4ccc-8ccc-cccccccccccc/wazuh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json'),
  1, 'analyst-capable members can read their case Wazuh source snapshot');
select set_config('request.jwt.claim.sub', '33333333-3333-4333-8333-333333333333', true);
select set_config('request.jwt.claims',
  '{"sub":"33333333-3333-4333-8333-333333333333","role":"authenticated"}', true);
select is((select count(*)::integer from storage.objects
  where bucket_id='satark-evidence'
    and name='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/cccccccc-cccc-4ccc-8ccc-cccccccccccc/11111111-1111-4111-8111-111111111111_own.txt'),
  1, 'viewers can read generic evidence in their own case');
select is((select count(*)::integer from storage.objects
  where bucket_id='satark-evidence'
    and name='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/cccccccc-cccc-4ccc-8ccc-cccccccccccc/wazuh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json'),
  0, 'viewers cannot read raw Wazuh source snapshots');

reset role;
select * from finish();
rollback;
