# SATARK / Saathi environment reconciliation (read-only audit)

Date: 2026-10-22  
Status: **BLOCKED — do not apply migrations or create test identities until the owner selects the canonical project.**

## Why this note exists

The repository's tenant-test guide describes a dedicated non-production project, while older migration-history notes describe the shared `nihdhoom` project as hosting SATARK and Saathi. The linked Supabase organization currently exposes both a project named `Saathi` and a project named `nihdhoom`. Project names and prior notes are not sufficient evidence to change either database.

## Read-only findings

The Supabase project listing returned these active projects:

| Project name | Ref | Region | Status |
| --- | --- | --- | --- |
| Saathi | `ibvgxgvcqcfnoyrlwywa` | `ap-northeast-2` | Active/healthy |
| nihdhoom | `igqgtlmnwssjaoxkkzbm` | `ap-south-1` | Active/healthy |

Read-only SQL on 2026-10-22 returned:

| Check | Saathi project `ibvgxgvcqcfnoyrlwywa` | nihdhoom project `igqgtlmnwssjaoxkkzbm` |
| --- | ---: | ---: |
| Public tables whose names start `satark_` | 11 | 11 |
| Public tables whose names start `saathi_` | 0 | 8 |
| Public RLS policies on tables named `satark_%` | 19 | 18 |

These results prove that SATARK-named tables exist in both projects at audit time. They **do not** prove that either project is the intended production authority, that its schema is identical, or that tenant isolation works. The `Saathi` project name is not enough to infer it is the application's canonical backend: it has zero public tables named `saathi_%`, while `nihdhoom` has eight. The Saathi application may use generic household tables, so this is a signal to reconcile—not proof of a wrong configuration.

## Required safe decision

1. Confirm the canonical Saathi application URL/project ref from its deployed server-side environment and its own repository configuration. Never print or commit secret values.
2. Confirm where SATARK's production data is intended to live. Do not infer this from project labels, empty table counts, or a README.
3. Keep tenant-isolation destructive tests on a separate disposable Supabase project/branch. Do not run cross-tenant write/delete tests against a shared production Saathi or Nirdhoom database.
4. Choose one canonical target for SATARK's production data and document the separation between production and integration-test environments.
5. For each candidate project, compare migration ledger, SATARK table definitions, indexes, constraints, RLS policies, grants, SECURITY DEFINER functions, storage policies and buckets with the repository migrations. Use read-only inspection first.
6. Reconcile migration history only after an owner-reviewed plan, backup/restore verification and a successful dry-run against an isolated copy. Do not reset the shared project or run a broad `supabase db push`.
7. Create test identities and configure the 11 GitHub Actions secrets only for the dedicated non-production test project. The test suite must fail the release gate if it skips.

## Release acceptance evidence still required

- The canonical project ref and environment mapping are confirmed without exposing credentials.
- Migration/schema/policy diffs have been reviewed and reconciled on the correct target.
- The dedicated test project's authenticated tenant/role isolation suite passes with zero skipped tests.
- No unrelated Saathi/Nirdhoom data or policies were changed.
- A sanitized report records the project ref, migration state, test run URL, commit SHA and result.

## Scope of this audit

This was a read-only metadata and SQL inspection. No database rows, migrations, users, secrets, or project settings were changed. It is not a tenant-isolation acceptance result and does not authorize production migration changes.

## Additional security-advisor result

The Supabase Security Advisor on both projects reported `public.satark_ingestion_checkpoints` as RLS-enabled with no policies. The repository migration `supabase/migrations/20261020023851_satark_wazuh_ingestion_checkpoints.sql` explicitly revokes all access from `anon` and `authenticated`, grants the required operations to `service_role`, and documents that the private worker is the intended access path. This finding is therefore not automatically a defect: validate effective grants and the worker's private credential handling, but do not add browser policies simply to silence the advisor.

The `nihdhoom` Security Advisor also reports other authenticated-callable `SECURITY DEFINER` functions and disabled leaked-password protection. Those findings may belong to Nirdhoom or shared Auth configuration rather than SATARK. Do not modify them as part of a SATARK-only patch. Inventory function ownership, call paths and intended grants with the relevant application owner before changing any shared-project function or Auth setting.
