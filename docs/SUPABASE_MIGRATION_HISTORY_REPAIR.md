# SATARK Supabase migration-history repair

Last verified: 2026-10-20 UTC (read-only migration and index checks refreshed)

## Scope and evidence

Official CLI reference: [Supabase database migrations](https://supabase.com/docs/guides/deployment/database-migrations).

The shared Supabase project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) hosts SATARK alongside Nirdhoom and Saathi. Do not reset it or run a broad `supabase db push` to resolve this mismatch.

A read-only migration-list check on 2026-10-20 found these relevant entries:

- `20261018114039` — `isolate_satark_membership_helper`: recorded.
- `202610200004` — `satark_storage_policy_membership_hardening`: not recorded.
- `20261020042000` — `satark_storage_policy_private_helper_rebind`: not recorded (repository file is a no-op; canonical policy was applied under `20261020044018`).
- `20261020042449` — `satark_evidence_storage_dual_path_policy`: recorded.
- `20261020044018` — `satark_storage_policy_private_helper_rebind`: recorded.
- `20261020050000` — `satark_foreign_key_support_indexes`: not recorded. A read-only `pg_indexes` check also found the five SATARK support indexes from this migration absent in the live database.

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

**Expected dry-run:** the only pending repository migration is `20261020050000_satark_foreign_key_support_indexes.sql`. It adds indexes to SATARK-owned tables only. If any other migration is listed, stop and reconcile the migration set before applying anything. If the dry-run matches exactly, apply the pending SATARK-only index migration:

```sh
supabase db push --linked
supabase migration list --linked
```

Then verify all five index names exist in `pg_indexes`:
`satark_approvals_requested_by_idx`, `satark_approvals_decided_by_idx`, `satark_case_notes_created_by_idx`, `satark_cases_assigned_to_idx`, and `satark_investigation_jobs_requested_by_idx`. Finally run the isolated migration validation workflow. Do not run a broad push if the dry-run differs from the expected single migration.

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

This is an operator-run history repair, not a live migration. Migration `20261020044018` was applied after isolated validation and verified read-only; no migration-history repair has been performed. The connected tools can inspect migrations and run read-only SQL but do not expose the Supabase CLI `migration repair` command. The repair must be run from a trusted CLI environment with the project explicitly linked.
