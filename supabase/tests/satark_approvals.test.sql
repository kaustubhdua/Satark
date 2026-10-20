begin;
select plan(21);

insert into auth.users (
  id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
) values
  ('11111111-1111-4111-8111-111111111111', 'authenticated', 'authenticated',
   'satark-approval-requester@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now()),
  ('22222222-2222-4222-8222-222222222222', 'authenticated', 'authenticated',
   'satark-approval-responder@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now()),
  ('33333333-3333-4333-8333-333333333333', 'authenticated', 'authenticated',
   'satark-approval-viewer@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now()),
  ('44444444-4444-4444-8444-444444444444', 'authenticated', 'authenticated',
   'satark-approval-foreign@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now());

insert into public.satark_tenants (id, name) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'SATARK approval test tenant'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'SATARK approval foreign tenant');
insert into public.satark_memberships (tenant_id, user_id, role) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '11111111-1111-4111-8111-111111111111', 'analyst'),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '22222222-2222-4222-8222-222222222222', 'responder'),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '33333333-3333-4333-8333-333333333333', 'viewer');
insert into public.satark_memberships (tenant_id, user_id, role)
values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '44444444-4444-4444-8444-444444444444', 'owner');
insert into public.satark_cases (id, tenant_id, title, status, severity, created_by)
values ('cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Approval test case', 'open', 'low',
  '11111111-1111-4111-8111-111111111111');
insert into public.satark_cases (id, tenant_id, title, status, severity, created_by)
values ('dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Foreign approval test case', 'open', 'low',
  '44444444-4444-4444-8444-444444444444');

insert into public.satark_approvals (
  id, tenant_id, case_id, action_key, action_payload, payload_sha256,
  status, requested_by, expires_at
) values
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
   'simulation.isolate-host', '{"mode":"simulation","host_id":"host-1"}'::jsonb, repeat('a',64),
   'pending', '11111111-1111-4111-8111-111111111111', now() + interval '30 minutes'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
   'simulation.revoke-session', '{"mode":"simulation","user_id":"user-1"}'::jsonb, repeat('b',64),
   'pending', '11111111-1111-4111-8111-111111111111', now() - interval '1 minute'),
  ('99999999-9999-4999-8999-999999999999',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
   'simulation.disable-account', '{"mode":"simulation","user_id":"user-2"}'::jsonb, repeat('c',64),
   'pending', '11111111-1111-4111-8111-111111111111', now() + interval '30 minutes'),
  ('77777777-7777-4777-8777-777777777777',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   'simulation.isolate-host', '{"mode":"simulation","host_id":"foreign"}'::jsonb, repeat('2',64),
   'pending', '44444444-4444-4444-8444-444444444444', now() + interval '30 minutes');

select ok(not has_function_privilege('authenticated', 'public.satark_has_membership(uuid,text[])', 'EXECUTE'),
  'authenticated cannot call the public membership helper');
select is((select count(*)::integer from pg_policies
  where (coalesce(qual,'') || coalesce(with_check,'')) like '%public.satark_has_membership%'),
  0, 'all RLS policies use the private membership helper before public access is revoked');

select is(
  (select payload_sha256 from public.satark_approvals where id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  encode(extensions.digest(convert_to((select action_payload::text from public.satark_approvals
    where id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),'UTF8'),'sha256'),'hex'),
  'the database derives the immutable payload hash from the stored action payload'
);
select throws_ok(
  $insert$ insert into public.satark_approvals
    (id, tenant_id, case_id, action_key, action_payload, payload_sha256, requested_by, expires_at)
    values ('88888888-8888-4888-8888-888888888888',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      'simulation.isolate-host', '{"mode":"simulation","host_id":"host-3"}'::jsonb, repeat('1',64),
      '11111111-1111-4111-8111-111111111111', now() + interval '31 minutes')$insert$,
  'P0001', null, 'approval lifetime cannot be extended beyond thirty minutes'
);
select ok(
  (select relrowsecurity from pg_class where oid='public.satark_approvals'::regclass),
  'durable approvals enforce row-level security'
);
select ok(not has_function_privilege('anon', 'public.satark_decide_approval(uuid,text,text)', 'EXECUTE'),
  'anonymous callers cannot decide approvals');
select ok(not has_function_privilege('authenticated', 'public.satark_approvals_guard()', 'EXECUTE'),
  'authenticated callers cannot invoke the trigger-only guard');
select ok(not has_table_privilege('authenticated', 'public.satark_approvals', 'UPDATE'),
  'authenticated callers cannot directly update approval rows');

set local role authenticated;
select set_config('request.jwt.claim.sub', '11111111-1111-4111-8111-111111111111', true);
select set_config('request.jwt.claims',
  '{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}', true);
select throws_ok(
  $$select public.satark_decide_approval('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'approved', 'self approval attempt')$$,
  'P0001', null, 'requester cannot approve their own action'
);

select set_config('request.jwt.claim.sub', '22222222-2222-4222-8222-222222222222', true);
select set_config('request.jwt.claims',
  '{"sub":"22222222-2222-4222-8222-222222222222","role":"authenticated"}', true);
select is(
  (select (public.satark_decide_approval('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'approved', 'approved by responder')).status),
  'approved', 'a tenant responder can approve a pending, unexpired request'
);
select ok(public.satark_authorize_response_action(
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  'simulation.isolate-host', encode(extensions.digest(convert_to('{"mode":"simulation","host_id":"host-1"}'::jsonb::text,'UTF8'),'sha256'),'hex')
), 'authorization accepts the exact tenant, case, action and payload hash');
select ok(not public.satark_authorize_response_action(
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  'simulation.isolate-host', repeat('f',64)
), 'authorization rejects a mismatched payload hash');
select ok(public.satark_consume_response_approval(
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  'simulation.isolate-host', encode(extensions.digest(convert_to('{"mode":"simulation","host_id":"host-1"}'::jsonb::text,'UTF8'),'sha256'),'hex')
), 'the exact approved action can be consumed once');
select ok(not public.satark_consume_response_approval(
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  'simulation.isolate-host', encode(extensions.digest(convert_to('{"mode":"simulation","host_id":"host-1"}'::jsonb::text,'UTF8'),'sha256'),'hex')
), 'replaying a consumed approval is rejected');
select is((select status from public.satark_approvals where id='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'),
  'consumed', 'successful consumption leaves a durable terminal state');
select is((select count(*)::integer from public.satark_approvals
  where tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 0,
  'a tenant responder cannot read another tenant approval');
select throws_ok(
  $insert$ insert into public.satark_approvals
    (tenant_id, case_id, action_key, action_payload, payload_sha256, requested_by, expires_at)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'simulation.isolate-host',
      '{"mode":"simulation","host_id":"unauthorized"}'::jsonb, repeat('3',64),
      '22222222-2222-4222-8222-222222222222', now() + interval '30 minutes')$insert$,
  '42501', null, 'a tenant responder cannot request approval in another tenant'
);
select throws_ok(
  $$select public.satark_decide_approval('ffffffff-ffff-4fff-8fff-ffffffffffff', 'approved', 'expired request')$$,
  'P0001', null, 'expired approval requests cannot be approved'
);

select set_config('request.jwt.claim.sub', '33333333-3333-4333-8333-333333333333', true);
select set_config('request.jwt.claims',
  '{"sub":"33333333-3333-4333-8333-333333333333","role":"authenticated"}', true);
select throws_ok(
  $$select public.satark_decide_approval('99999999-9999-4999-8999-999999999999', 'approved', 'viewer attempt')$$,
  'P0001', null, 'viewer role cannot decide approvals'
);
select ok((select chain_valid from public.satark_verify_audit_chain('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')),
  'approval decisions and consumption preserve the audit hash chain');

-- Simulate storage-level tampering in this isolated test transaction only.
-- Disable the immutability trigger as the local database owner, corrupt one hash,
-- re-enable the trigger, and prove the verifier detects the altered record.
reset role;
alter table public.satark_audit_events disable trigger satark_audit_no_update_delete;
update public.satark_audit_events
  set event_hash = repeat('f',64)
  where id = (
    select max(id) from public.satark_audit_events
    where tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  );
alter table public.satark_audit_events enable trigger satark_audit_no_update_delete;

set local role authenticated;
select set_config('request.jwt.claim.sub', '33333333-3333-4333-8333-333333333333', true);
select set_config('request.jwt.claims',
  '{"sub":"33333333-3333-4333-8333-333333333333","role":"authenticated"}', true);
select ok(not (select chain_valid from public.satark_verify_audit_chain('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')),
  'audit-chain verification detects an altered stored event hash');

reset role;
select * from finish();
rollback;
