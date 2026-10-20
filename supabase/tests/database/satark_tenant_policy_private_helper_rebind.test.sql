begin;

select plan(13);

select ok(
  has_function_privilege('authenticated', 'satark_private.has_membership(uuid,text[])', 'EXECUTE'),
  'authenticated can execute the private membership helper'
);

select ok(
  not has_function_privilege('authenticated', 'public.satark_has_membership(uuid,text[])', 'EXECUTE'),
  'authenticated cannot execute the legacy public membership wrapper'
);

select ok(
  not has_function_privilege('anon', 'public.satark_has_membership(uuid,text[])', 'EXECUTE'),
  'anon cannot execute the legacy public membership wrapper'
);

select ok(
  (select qual like '%satark_private.has_membership%' and qual not like '%public.satark_has_membership%'
   from pg_policies where schemaname='public' and tablename='satark_approvals' and policyname='satark_approvals_member_read'),
  'approval read policy uses private helper'
);

select ok(
  (select with_check like '%satark_private.has_membership%' and with_check not like '%public.satark_has_membership%'
   from pg_policies where schemaname='public' and tablename='satark_approvals' and policyname='satark_approvals_request'),
  'approval request policy uses private helper'
);

select ok(
  (select with_check like '%satark_private.has_membership%' and with_check not like '%public.satark_has_membership%'
   from pg_policies where schemaname='public' and tablename='satark_case_notes' and policyname='satark_case_notes_analyst_insert'),
  'case note insert policy uses private helper'
);

select ok(
  (select qual like '%satark_private.has_membership%' and qual not like '%public.satark_has_membership%'
   from pg_policies where schemaname='public' and tablename='satark_case_notes' and policyname='satark_case_notes_member_read'),
  'case note read policy uses private helper'
);

select ok(
  (select with_check like '%satark_private.has_membership%' and with_check not like '%public.satark_has_membership%'
   from pg_policies where schemaname='public' and tablename='satark_investigation_jobs' and policyname='satark_investigation_jobs_member_enqueue'),
  'investigation enqueue policy uses private helper'
);

select ok(
  (select qual like '%satark_private.has_membership%' and qual not like '%public.satark_has_membership%'
   from pg_policies where schemaname='public' and tablename='satark_investigation_jobs' and policyname='satark_investigation_jobs_member_read'),
  'investigation read policy uses private helper'
);

select ok(
  (select count(*) = 2
      and bool_and((coalesce(qual,'') || ' ' || coalesce(with_check,'')) like '%satark_private.has_membership%')
      and bool_and((coalesce(qual,'') || ' ' || coalesce(with_check,'')) not like '%public.satark_has_membership%')
   from pg_policies
   where schemaname='storage'
     and tablename='objects'
     and policyname in ('satark_evidence_object_read','satark_evidence_object_insert')),
  'evidence storage policies use private membership helper'
);

select is(
  (select count(*)::integer from pg_policies
   where schemaname='public'
     and policyname in (
       'satark_approvals_member_read','satark_approvals_request',
       'satark_case_notes_member_read','satark_case_notes_analyst_insert',
       'satark_investigation_jobs_member_read','satark_investigation_jobs_member_enqueue'
     )
     and coalesce(qual,'') || ' ' || coalesce(with_check,'') like '%satark_has_membership%'),
  0,
  'no targeted tenant policy references either membership helper by unqualified legacy name'
);

select ok(
  (select with_check like '%status = ''pending''%' and with_check like '%decided_by IS NULL%'
   from pg_policies where schemaname='public' and tablename='satark_approvals' and policyname='satark_approvals_request'),
  'approval request state constraints remain enforced'
);

select ok(
  (select with_check like '%attempts = 0%' and with_check like '%result_sha256 IS NULL%'
   from pg_policies where schemaname='public' and tablename='satark_investigation_jobs' and policyname='satark_investigation_jobs_member_enqueue'),
  'investigation enqueue state constraints remain enforced'
);

select * from finish();
rollback;
