# Supabase tenant-isolation integration test setup

This guide configures the **dedicated non-production** Supabase project used by the SATARK tenant/RLS integration suite. Do not point this test at a production project or real incident data: the suite deliberately attempts cross-tenant writes and deletes.

## What the suite proves

`web/tests/tenant-isolation.integration.test.mjs` signs in as ordinary test users and uses the public PostgREST API. It checks cross-tenant reads and writes for cases, evidence, findings and reports, and verifies that a viewer cannot create or update cases. A skipped test is **not** a pass.

## Saathi project mapping (requested tenant backend)

Use the existing **Saathi** Supabase project as the SATARK tenant backend: project ref `ibvgxgvcqcfnoyrlwywa`, region `ap-northeast-2`. Set `SATARK_TEST_SUPABASE_URL` to that project's HTTPS API URL from Supabase project settings and `SATARK_TEST_SUPABASE_PUBLISHABLE_KEY` to its publishable/anon key. Never use a service-role key in browser tests or GitHub Actions.

The connected project currently reports zero rows in the SATARK tenant, membership, case, evidence, finding, report, approval and ingestion tables. This is a point-in-time observation, not a guarantee that the project will remain empty. The suite uses dedicated Auth users and distinct disposable SATARK tenant IDs; do not point it at any real user's tenant or use any existing user credentials. Test only the dedicated test tenants and keep the normal Saathi application tables and identities untouched.

## 1. Prepare a dedicated test project

1. Create or select a separate Supabase project used only for SATARK integration tests.
2. Apply the repository's reviewed, version-controlled migrations to that test project. Follow the isolated migration validation workflow and compare migration history before applying anything.
3. Confirm the expected SATARK tables, row-level security (RLS) policies, grants, and membership/role functions exist in the test project.
4. Create three distinct, confirmed Auth users with ordinary, non-admin accounts:
   - **Tenant A owner**: owns a disposable test tenant A.
   - **Tenant B owner**: owns a different disposable test tenant B.
   - **Viewer**: has the viewer role in a separate disposable tenant with at least one disposable case.
5. Seed at least one disposable case for Tenant A, Tenant B, and the viewer's tenant. Ensure each test account can access only its intended tenant through the normal membership model.
6. Record the UUID of each tenant. Tenant A and Tenant B must be different. Never use service-role credentials for the integration test.

Use the app's supported tenant/membership flow or reviewed test-only seed procedures to create fixtures. Do not hand-edit the shared production database to make this test pass.

## 2. Add GitHub Actions secrets

In GitHub, open **Settings → Secrets and variables → Actions → New repository secret**. Add the following secrets for this repository:

| Secret name | Value |
| --- | --- |
| `SATARK_TEST_SUPABASE_URL` | URL of the dedicated non-production Supabase project |
| `SATARK_TEST_SUPABASE_PUBLISHABLE_KEY` | That project's publishable/anon key |
| `SATARK_TEST_USER_A_EMAIL` | Tenant A owner's confirmed test email |
| `SATARK_TEST_USER_A_PASSWORD` | Tenant A owner's test password |
| `SATARK_TEST_TENANT_A_ID` | Tenant A UUID |
| `SATARK_TEST_USER_B_EMAIL` | Tenant B owner's confirmed test email |
| `SATARK_TEST_USER_B_PASSWORD` | Tenant B owner's test password |
| `SATARK_TEST_TENANT_B_ID` | Tenant B UUID |
| `SATARK_TEST_VIEWER_EMAIL` | Viewer's confirmed test email |
| `SATARK_TEST_VIEWER_PASSWORD` | Viewer's test password |
| `SATARK_TEST_VIEWER_TENANT_ID` | Viewer's tenant UUID |

These are test-only credentials. Keep them in GitHub's secret store; never commit them to `.env.example`, source control, screenshots, or logs. Use a publishable/anon key, not a service-role key.

## 3. Run the suite

GitHub Actions runs the tenant-isolation job as part of `.github/workflows/ci.yml`. After adding the secrets and seeding fixtures:

1. Push a harmless commit or rerun the CI workflow for the target commit.
2. Open the **Supabase tenant-isolation integration** job.
3. Confirm **Run real Supabase tenant and role isolation tests** has conclusion `success`, not `skipped`.
4. Review the assertions and any database logs for failures. Fix policies/grants in a reviewed migration and rerun the suite.

For a local run, set the same variables in your terminal environment (do not commit them), then run:

```bash
cd web
npm ci
npm run test:integration
```

The local integration command intentionally fails when required fixtures are missing. The ordinary CI job may report its integration step as skipped when secrets are not configured; the production release gate explicitly rejects a skipped tenant-isolation test.

## 4. Release gate

Use **Actions → SATARK production release gate → Run workflow** only after collecting evidence for every required gate. The workflow requires successful CI, Web CI and CodeQL for the exact release commit and checks that the real tenant-isolation step passed. Do not mark migrations, production deployment, real telemetry, evidence verification, AI evaluation or provider response as verified without the corresponding evidence.

## Troubleshooting

- **Test step is skipped:** one or more Actions secrets are empty. Check the exact names above.
- **Login fails:** confirm all three users are confirmed, passwords are correct, and the project URL/key belong to the same test project.
- **Tenant A/B IDs match:** create separate test tenants and update the UUID secrets.
- **Viewer update assertion fails:** check the viewer role's table grants and RLS policies; do not weaken the test to make CI green.
- **No disposable case found:** seed one case for each test tenant through a reviewed, test-only setup path and rerun.
- **Migration history differs:** stop and reconcile history in the isolated test project before attempting any production change.
