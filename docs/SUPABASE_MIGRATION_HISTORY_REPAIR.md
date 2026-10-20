# SATARK Supabase migration-history repair

Last verified: 2026-10-20 UTC (read-only migration and index checks refreshed)

## Scope and evidence

Official CLI reference: [Supabase migration repair](https://supabase.com/docs/reference/cli/supabase-migration-repair).

The shared Supabase project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) hosts SATARK alongside Nirdhoom and Saathi. Do not reset it or run a broad `supabase db push` to resolve this mismatch.

A read-only migration-list check on 2026-10-20 found these relevant entries:

- `20261018114039` — `isolate_satark_membership_helper`: recorded.
- `20261018114205` — `harden_satark_audit_verification_rpc`: recorded in the live ledger and now included in the repository migration history by the RPC-hardening PR. The migration keeps the public audit-verification function as a `SECURITY INVOKER` wrapper.
- `20261018114247` — `harden_satark_tenant_creation_rpc`: recorded in the live ledger and now included in the repository migration history by the RPC-hardening PR. The migration keeps the public tenant-creation function as a `SECURITY INVOKER` wrapper.
- `202610200004` — `satark_storage_policy_membership_hardening`: not recorded.
- `20261020042000` — `satark_storage_policy_private_helper_rebind`: not recorded (repository file is a no-op; canonical policy was applied under `20261020044018`).
- `20261020042449` — `satark_evidence_storage_dual_path_policy`: recorded.
- `20261020044018` — `satark_storage_policy_private_helper_rebind`: recorded.
- `20261020050000` — `satark_foreign_key_support_indexes`: not recorded. A read-only `pg_indexes` check also found the five SATARK support indexes from this migration absent in the live database.
- `20261020051000` — `satark_rebind_membership_policies`: not recorded. This migration rebinds six approval, case-note, and investigation-job RLS policies to the private membership helper; PR #174's isolated migration, tenant-isolation, browser/accessibility, CI, and CodeQL checks passed before merge. A read-only live audit still finds all six policies referencing the revoked public wrapper, so these operations may fail closed until the controlled repair and push are completed.
- `20261020052000` — `satark_private_approval_rpc_implementations`: not recorded. The repository migration moves four approval/assignment `SECURITY DEFINER` implementations into the non-exposed `satark_private` schema and leaves `public` functions as `SECURITY INVOKER` wrappers. A read-only security-advisor check on 2026-10-20 still reports these four public RPCs as callable `SECURITY DEFINER` functions in the shared live database. Apply only after the linked migration list and dry-run are verified as described below.

The live private helper, ACLs, and final storage policies have been verified read-only. The later recorded migrations establish the intended final policy. The repository migration `202610200004` remains available for clean database resets; do not change it to a no-op. The repository migration `20261020042000` is already a no-op because the canonical policy was applied under `20261020044018`. The duplicate version `20261020043000` was removed from the repository in PR #164 and is not part of the repair command.

The live SATARK tenant, membership, case, evidence, finding, report, audit-event, ingestion-checkpoint, investigation-job, case-note and approval tables currently contain zero rows. Do not add fake production rows to test the application.

## Required operator procedure

From a trusted checkout, explicitly confirm that the linked project is `igqgtlmnwssjaoxkkzbm` before running any repair:

```sh
supabase migration list --linked
supabase migration repair 202610200004 20261020042000 --status applied --linked
supabase migration list --linked
```

This records only the two already-superseded/missing versions as applied; it does not execute their SQL. Do not repair any other versions, and do not re-mark `20261020042449` or `20261020044018`. If the linked migration list differs from the evidence above, stop and re-review before changing history.

After repair, confirm that versions `202610200004`, `20261018114039`, `20261020042000`, `20261020042449`, and `20261020044018` are recorded. Then preview pending migrations before changing the live schema:

```sh
supabase db push --dry-run --linked
```

**Expected dry-run after the isolated approval-RPC hardening migration is merged:** exactly these three pending repository migrations, in version order:
1. `20261020050000_satark_foreign_key_support_indexes.sql` — creates the five SATARK support indexes.
2. `20261020051000_satark_rebind_membership_policies.sql` — rebinds six SATARK RLS policies from the revoked public wrapper to the private membership helper.

3. `20261020052000_satark_private_approval_rpc_implementations.sql` — moves four privileged implementations into `satark_private` and keeps the public RPC wrappers as `SECURITY INVOKER`.

If any other migration is listed, stop and reconcile the migration set before applying anything. Do not execute the repair or push commands unless the linked project is confirmed as `igqgtlmnwssjaoxkkzbm` and the dry-run matches exactly. If it matches, apply the three pending SATARK-only migrations and verify the resulting history:

```sh
supabase db push --linked
supabase migration list --linked
```

Then verify the four public approval/assignment RPCs are `SECURITY INVOKER`, their private implementations have a fixed empty `search_path`, and anonymous callers cannot execute the private functions. Verify all five index names exist in `pg_indexes`:
`satark_approvals_requested_by_idx`, `satark_approvals_decided_by_idx`, `satark_case_notes_created_by_idx`, `satark_cases_assigned_to_idx`, and `satark_investigation_jobs_requested_by_idx`. Also re-check that the six affected policies call `satark_private.has_membership` and that authenticated/anon cannot execute `public.satark_has_membership`. Run the isolated migration validation workflow after the live repair. Do not run a broad push if the dry-run differs from the expected three migrations.

## Read-only policy and ACL verification

```sql
select version, name
from supabase_migrations.schema_migrations
where version in ('20261018114039', '202610200004', '20261020042000', '20261020042449', '20261020044018')
order by version;

select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'storage'
  and tablename = 'objects'
  and policyname in ('satark_evidence_object_insert', 'satark_evidence_object_read')
order by policyname;

select
  has_function_privilege('authenticated', 'satark_private.has_membership(uuid,text[])', 'EXECUTE') as authenticated_private_helper,
  has_function_privilege('authenticated', 'public.satark_has_membership(uuid,text[])', 'EXECUTE') as authenticated_public_wrapper,
  has_function_privilege('anon', 'public.satark_has_membership(uuid,text[])', 'EXECUTE') as anon_public_wrapper,
  has_function_privilege('authenticated', 'public.satark_reject_audit_mutation()', 'EXECUTE') as authenticated_audit_trigger_rpc;
```

Expected privilege values are `true, false, false, false`. The read policy must allow `viewer` only for generic evidence objects; raw `wazuh/<sha256>.json` source snapshots require owner/responder/analyst membership. Both policies must use `satark_private.has_membership` and verify the owning case/tenant.

## Boundary

This is an operator-run history repair, not a live migration. Migration `20261020044018` was applied after isolated validation and verified read-only; no migration-history repair has been performed. The connected tools can inspect migrations and run read-only SQL but do not expose the Supabase CLI `migration repair` command. The expected pending migration list includes `20261020052000_satark_private_approval_rpc_implementations.sql` only after that migration is merged to `main`. The repair must be run from a trusted CLI environment with the project explicitly linked.
