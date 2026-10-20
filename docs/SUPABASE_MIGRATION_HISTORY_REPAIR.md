# SATARK Supabase migration-history repair

Last verified: 2026-10-20

## Why this is needed

The shared Supabase project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) hosts SATARK alongside Nirdhoom and Saathi. Do not reset it or run a broad `supabase db push` to resolve this mismatch.

A read-only `list_migrations` check on 2026-10-20 showed:

- `202610200004` — `satark_storage_policy_membership_hardening`: **not recorded**; its helper/policy effects are superseded by the later private-helper and dual-path policy migrations.
- `20261020042449` — `satark_evidence_storage_dual_path_policy`: recorded.
- `20261020044018` — `satark_storage_policy_private_helper_rebind`: recorded.
- `20261020042000` — `satark_storage_policy_private_helper_rebind`: **not recorded**.
- `20261020043000` — `satark_storage_insert_policy_private_helper_rebind`: **not recorded**.

The canonical policy SQL is already recorded as `20261020044018`. The repository files for `20261020042000` and `20261020043000` are no-ops because they are superseded and older than the canonical applied migration. Version `202610200004` is also absent remotely. Its helper ACL effects are already present in the live schema after the recorded `20261018114039` membership-helper isolation migration; its older storage-policy definitions are superseded by the recorded `20261020042449` and `20261020044018` migrations. The live schema was verified to have the intended final policies, so the history repair should mark `202610200004` as applied without executing its older policy SQL. This keeps the final policy from being weakened by an out-of-order push.

## Required operator procedure

Run this only from the trusted project checkout after confirming the linked project reference and reviewing `supabase migration list --linked` output:

```sh
supabase migration list --linked
supabase migration repair --status applied 202610200004 20261020042000 20261020043000 --linked
supabase migration list --linked
```

The repair command records the three already-superseded/missing versions as applied; it must not execute the historical SQL for `202610200004`, `20261020042000`, or `20261020043000`. Do not mark `20261020042449` or `20261020044018` applied again and do not repair any other versions as part of this task.

After the repair, confirm that `202610200004`, `20261020042000`, `20261020042449`, `20261020043000`, and `20261020044018` are recorded, then run the isolated migration validation workflow from the repository. Re-run the read-only policy query below and confirm both policies call `satark_private.has_membership`, the read policy permits `viewer` only for generic evidence, and raw `wazuh/<sha256>.json` objects require owner/responder/analyst membership.

## Read-only post-repair verification

```sql
select version, name
from supabase_migrations.schema_migrations
where version in ('202610200004', '20261020042000', '20261020042449', '20261020043000', '20261020044018')
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

Expected function privilege values are `true, false, false, false`. Do not create synthetic tenant, user, membership, case, or evidence rows in the shared project. Tenant-isolation behavior must be proven in the isolated test database or a separately approved test project.

## Status

This is an operator-run history repair, not a live migration. The connected tools in this session can inspect migrations and run read-only SQL, but do not expose the Supabase CLI `migration repair` command. The repair must be run from a trusted CLI environment with the project explicitly linked.
