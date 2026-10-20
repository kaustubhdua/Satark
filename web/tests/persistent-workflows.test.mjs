import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = path => readFile(new URL(path, import.meta.url), 'utf8');
const [auth, evidence, verify, records, findings, reports, audit, tenantMigration, storageMigration, workflowMigration, auditMigration, uploadLimitMigration, approvalsRoute, approvalsPanel, approvalsMigration, simulationApprovalsMigration] = await Promise.all([
  read('../src/lib/satark-auth.ts'),
  read('../src/app/api/evidence/route.ts'),
  read('../src/app/api/evidence/[id]/verify/route.ts'),
  read('../src/app/api/evidence/records/route.ts'),
  read('../src/app/api/findings/route.ts'),
  read('../src/app/api/reports/route.ts'),
  read('../src/app/api/audit/verify/route.ts'),
  read('../../supabase/migrations/202610140002_satark_trusted_tenant_provisioning.sql'),
  read('../../supabase/migrations/202610140003_satark_private_evidence_storage.sql'),
  read('../../supabase/migrations/202610140005_satark_findings_reports_audit.sql'),
  read('../../supabase/migrations/202610140006_satark_audit_chain_verification.sql'),
  read('../../supabase/migrations/202610140009_satark_evidence_upload_limit.sql'),
  read('../src/app/api/firstlight/approvals/route.ts'),
  read('../src/app/firstlight/persistent-case-panel.tsx'),
  read('../../supabase/migrations/202610200001_satark_durable_approvals.sql'),
  read('../../supabase/migrations/20261020035832_satark_simulation_only_approvals.sql'),
]);

test('browser auth uses publishable key and refreshes sessions without privileged keys', () => {
  assert.match(auth, /grant_type=password/);
  assert.match(auth, /grant_type=refresh_token/);
  assert.match(auth, /auth\/v1\/logout/);
  assert.match(auth, /NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY/);
  assert.doesNotMatch(auth, /SERVICE_ROLE|service_role/i);
});

test('evidence upload calculates SHA-256 on the server and bounds file size', () => {
  assert.match(evidence, /inspectEvidenceFile\(bytes, file\.type\)/);
  assert.match(evidence, /signature_verified: inspection\.signatureVerified/);
  assert.match(evidence, /, 415\)/);
  assert.match(evidence, /createHash\('sha256'\)/);
  assert.match(evidence, /MAX_FILE_BYTES = 4 \* 1024 \* 1024/);
  assert.match(evidence, /satark-evidence/);
  assert.match(evidence, /Cache-Control/);
  assert.doesNotMatch(evidence, /SUPABASE_SERVICE_ROLE_KEY|service_role/i);
});

test('evidence verification downloads private bytes and compares the server digest', () => {
  assert.match(verify, /storage\/v1\/object\/satark-evidence/);
  assert.match(verify, /actual === row\.source_sha256/);
  assert.match(verify, /does not independently prove the original source/);
});

test('findings and reports are authenticated and report snapshots are server-hashed', () => {
  assert.match(records, /record_sha256: recordSha/);
  assert.match(findings, /satark_findings/);
  assert.match(findings, /auth\/v1\/user/);
  assert.match(reports, /createHash\('sha256'\)/);
  assert.match(reports, /satark_reports/);
  assert.match(audit, /satark_verify_audit_chain/);
});

test('trusted workspace provisioning derives owner from auth.uid and records an audit event', () => {
  assert.match(tenantMigration, /actor uuid := auth\.uid\(\)/);
  assert.match(tenantMigration, /values \(created_tenant, actor, 'owner'\)/);
  assert.match(tenantMigration, /tenant\.created/);
  assert.match(tenantMigration, /revoke all on function public\.satark_create_tenant\(text\) from public/);
});

test('evidence storage is private and policies are scoped to tenant membership', () => {
  assert.match(storageMigration, /values \('satark-evidence', 'satark-evidence', false, 10485760\)/);
  assert.match(storageMigration, /for select to authenticated/);
  assert.match(storageMigration, /for insert to authenticated/);
  assert.match(storageMigration, /satark_has_membership/);
  assert.match(uploadLimitMigration, /file_size_limit = 4194304/);
});

test('findings and immutable reports have RLS and append-only audit triggers', () => {
  assert.match(workflowMigration, /alter table public\.satark_findings enable row level security/i);
  assert.match(workflowMigration, /alter table public\.satark_reports enable row level security/i);
  assert.match(workflowMigration, /satark_audit_finding_after_insert/);
  assert.match(workflowMigration, /satark_audit_report_after_insert/);
  assert.match(auditMigration, /satark_verify_audit_chain/);
});


test('durable approval UI and API are simulation-only and keep decisions server-authorized', () => {
  assert.match(approvalsRoute, /simulation\\\./);
  assert.match(approvalsRoute, /mode!==['"]simulation['"]/);
  assert.match(approvalsRoute, /rpc\/satark_decide_approval/);
  assert.match(approvalsPanel, /Request simulated approval/);
  assert.match(approvalsPanel, /Approve simulation/);
  assert.match(approvalsPanel, /Reject simulation/);
  assert.match(approvalsPanel, /No endpoint or account action was executed/);
  assert.match(approvalsMigration, /satark_approvals_not_self_approved/);
  assert.match(approvalsMigration, /satark_consume_response_approval/);
  assert.match(simulationApprovalsMigration, /satark_approvals_simulation_only/);
  assert.match(simulationApprovalsMigration, /action_payload->>'mode' = 'simulation'/);
});
