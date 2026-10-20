begin;
select plan(26);

-- Local-only fixtures. This test runs in the isolated Supabase migration
-- validation job and rolls back all Auth users, tenants, memberships, and audit events.
insert into auth.users (
  id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
) values
  ('51111111-1111-4111-8111-111111111111', 'authenticated', 'authenticated',
   'satark-rpc-owner-a@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now()),
  ('52222222-2222-4222-8222-222222222222', 'authenticated', 'authenticated',
   'satark-rpc-owner-b@example.test', 'test-only-not-a-password', now(),
   '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now());

create temporary table satark_rpc_test_tenants (
  label text primary key,
  tenant_id uuid not null
);
grant select, insert on satark_rpc_test_tenants to authenticated;

select ok(not (
  select p.prosecdef
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public' and p.proname='satark_create_tenant'
), 'the exposed tenant-creation RPC is SECURITY INVOKER');

select ok(not (
  select p.prosecdef
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public' and p.proname='satark_verify_audit_chain'
), 'the exposed audit-verification RPC is SECURITY INVOKER');

select ok((
  select p.prosecdef
    and coalesce(array_to_string(p.proconfig, ','), '') like '%search_path=""%'
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='satark_private' and p.proname='create_tenant'
), 'the private tenant creator is SECURITY DEFINER with an empty fixed search_path');

select ok((
  select p.prosecdef
    and coalesce(array_to_string(p.proconfig, ','), '') like '%search_path=""%'
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='satark_private' and p.proname='verify_audit_chain'
), 'the private audit verifier is SECURITY DEFINER with an empty fixed search_path');


select ok(not (
  select p.prosecdef from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public' and p.proname='satark_decide_approval'
), 'the exposed approval-decision RPC is SECURITY INVOKER');
select ok(not (
  select p.prosecdef from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public' and p.proname='satark_authorize_response_action'
), 'the exposed approval-authorization RPC is SECURITY INVOKER');
select ok(not (
  select p.prosecdef from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public' and p.proname='satark_consume_response_approval'
), 'the exposed approval-consumption RPC is SECURITY INVOKER');
select ok(not (
  select p.prosecdef from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public' and p.proname='satark_list_assignable_members'
), 'the exposed assignable-member RPC is SECURITY INVOKER');
select ok((
  select count(*)=4
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname='satark_private'
    and p.proname in ('decide_approval','authorize_response_action','consume_response_approval','list_assignable_members')
    and p.prosecdef
    and coalesce(array_to_string(p.proconfig, ','), '') like '%search_path=""%'
), 'all four private approval implementations are SECURITY DEFINER with a fixed empty search_path');
select ok(
  not has_function_privilege('anon','satark_private.decide_approval(uuid,text,text)','EXECUTE')
  and not has_function_privilege('anon','satark_private.authorize_response_action(uuid,uuid,uuid,text,text)','EXECUTE')
  and not has_function_privilege('anon','satark_private.consume_response_approval(uuid,uuid,uuid,text,text)','EXECUTE')
  and not has_function_privilege('anon','satark_private.list_assignable_members(uuid)','EXECUTE'),
  'anonymous callers cannot execute private approval implementations');
select ok(
  has_function_privilege('authenticated','public.satark_decide_approval(uuid,text,text)','EXECUTE')
  and has_function_privilege('authenticated','public.satark_authorize_response_action(uuid,uuid,uuid,text,text)','EXECUTE')
  and has_function_privilege('authenticated','public.satark_consume_response_approval(uuid,uuid,uuid,text,text)','EXECUTE')
  and has_function_privilege('authenticated','public.satark_list_assignable_members(uuid)','EXECUTE'),
  'authenticated callers retain access to the four public RPC wrappers');
select ok(
  has_function_privilege('authenticated','satark_private.decide_approval(uuid,text,text)','EXECUTE')
  and has_function_privilege('authenticated','satark_private.authorize_response_action(uuid,uuid,uuid,text,text)','EXECUTE')
  and has_function_privilege('authenticated','satark_private.consume_response_approval(uuid,uuid,uuid,text,text)','EXECUTE')
  and has_function_privilege('authenticated','satark_private.list_assignable_members(uuid)','EXECUTE'),
  'public wrappers can invoke the permissioned private implementations');

select ok(not has_function_privilege('anon', 'public.satark_create_tenant(text)', 'EXECUTE'),
  'anonymous callers cannot execute the tenant-creation wrapper');
select ok(not has_function_privilege('anon', 'public.satark_verify_audit_chain(uuid)', 'EXECUTE'),
  'anonymous callers cannot execute the audit-verification wrapper');
select ok(has_function_privilege('authenticated', 'public.satark_create_tenant(text)', 'EXECUTE'),
  'authenticated users retain access to tenant creation');
select ok(has_function_privilege('authenticated', 'public.satark_verify_audit_chain(uuid)', 'EXECUTE'),
  'authenticated tenant members retain access to audit verification');

set local role authenticated;
select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claims', '{"role":"authenticated"}', true);
select throws_ok(
  $$select public.satark_create_tenant('Unauthenticated tenant probe')$$,
  '28000', null, 'tenant creation rejects a caller without auth.uid()'
);

select set_config('request.jwt.claim.sub', '51111111-1111-4111-8111-111111111111', true);
select set_config('request.jwt.claims',
  '{"sub":"51111111-1111-4111-8111-111111111111","role":"authenticated"}', true);
select lives_ok(
  $$insert into satark_rpc_test_tenants(label,tenant_id)
    values ('a', public.satark_create_tenant('SATARK RPC hardening tenant A'))$$,
  'an authenticated user can create a tenant through the public wrapper'
);
select is((
  select count(*)::integer
  from public.satark_memberships m
  join satark_rpc_test_tenants t on t.tenant_id=m.tenant_id
  where t.label='a' and m.user_id='51111111-1111-4111-8111-111111111111' and m.role='owner'
), 1, 'tenant creation atomically grants owner membership to the authenticated actor');
select ok((
  select event_count > 0 and chain_valid
  from public.satark_verify_audit_chain((select tenant_id from satark_rpc_test_tenants where label='a'))
), 'the creator can verify the newly created tenant audit chain');

select throws_ok(
  $$select public.satark_create_tenant('   ')$$,
  '22023', null, 'tenant creation rejects blank names without creating a tenant'
);

select set_config('request.jwt.claim.sub', '52222222-2222-4222-8222-222222222222', true);
select set_config('request.jwt.claims',
  '{"sub":"52222222-2222-4222-8222-222222222222","role":"authenticated"}', true);
select lives_ok(
  $$insert into satark_rpc_test_tenants(label,tenant_id)
    values ('b', public.satark_create_tenant('SATARK RPC hardening tenant B'))$$,
  'a second authenticated user can create a separate tenant'
);
select is((
  select count(*)::integer
  from public.satark_memberships m
  join satark_rpc_test_tenants t on t.tenant_id=m.tenant_id
  where t.label='b' and m.user_id='52222222-2222-4222-8222-222222222222' and m.role='owner'
), 1, 'the second tenant is owned by its own authenticated creator');
select ok((
  select event_count > 0 and chain_valid
  from public.satark_verify_audit_chain((select tenant_id from satark_rpc_test_tenants where label='b'))
), 'the second creator can verify their tenant audit chain');

select set_config('request.jwt.claim.sub', '51111111-1111-4111-8111-111111111111', true);
select set_config('request.jwt.claims',
  '{"sub":"51111111-1111-4111-8111-111111111111","role":"authenticated"}', true);
select throws_ok(
  $$select * from public.satark_verify_audit_chain((select tenant_id from satark_rpc_test_tenants where label='b'))$$,
  '42501', null, 'a tenant member cannot verify another tenant audit chain'
);
select ok((
  select event_count > 0 and chain_valid
  from public.satark_verify_audit_chain((select tenant_id from satark_rpc_test_tenants where label='a'))
), 'a rejected cross-tenant verification attempt leaves the owner audit chain verifiable');

reset role;
select * from finish();
rollback;
