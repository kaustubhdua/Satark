import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJson, createMemoryStore, exportWorkspace, handleLocalRequest, importWorkspace, isLocalRoute, sha256Hex, verifyAuditChain,
} from '../src/lib/local-workspace.mjs';

const call = (store, method, path, { query = {}, body, form } = {}) =>
  handleLocalRequest(store, { method, path, query: new URLSearchParams(query), body, form });

async function bootstrap() {
  const store = createMemoryStore();
  const ws = (await call(store, 'GET', '/api/workspaces')).json.workspaces[0];
  const created = await call(store, 'POST', '/api/cases', { body: { tenant_id: ws.id, title: ' Phish report ', severity: 'high' } });
  return { store, tenant: ws.id, caseId: created.json.case.id, created };
}

test('sha256 and canonical JSON match known vectors', async () => {
  assert.equal(await sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 1, y: 2 } }), '{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":1}}');
});

test('routes: only workspace endpoints are local', () => {
  for (const p of ['/api/cases', '/api/cases/notes', '/api/evidence/records', '/api/audit/verify', '/api/auth/session', '/api/reports/abc']) assert.ok(isLocalRoute(p), p);
  for (const p of ['/api/analyze', '/api/health', '/api/firstlight/investigate', '/api/firstlight/wazuh/live', '/api/casesx']) assert.ok(!isLocalRoute(p), p);
});

test('session and workspace exist without any account', async () => {
  const store = createMemoryStore();
  const session = await call(store, 'GET', '/api/auth/session');
  assert.equal(session.status, 200);
  assert.match(session.json.user.id, /^[0-9a-f-]{36}$/);
  const login = await call(store, 'POST', '/api/auth/login', { body: { email: 'a@b.c', password: 'x' } });
  assert.equal(login.status, 400);
  assert.match(login.json.error, /browser-only/);
});

test('cases: create, list, update, validation, wrong tenant', async () => {
  const { store, tenant, caseId, created } = await bootstrap();
  assert.equal(created.status, 201);
  assert.equal(created.json.case.title, 'Phish report');
  assert.equal((await call(store, 'POST', '/api/cases', { body: { tenant_id: tenant, title: '' } })).status, 400);
  assert.equal((await call(store, 'POST', '/api/cases', { body: { tenant_id: 'other', title: 'x' } })).status, 404);
  const patched = await call(store, 'PATCH', '/api/cases', { body: { tenant_id: tenant, id: caseId, status: 'contained' } });
  assert.equal(patched.json.case.status, 'contained');
  assert.equal((await call(store, 'PATCH', '/api/cases', { body: { tenant_id: tenant, id: caseId, status: 'bogus' } })).status, 400);
  assert.equal((await call(store, 'PATCH', '/api/cases', { body: { tenant_id: tenant, id: caseId, assigned_to: 'stranger' } })).status, 400);
  const list = await call(store, 'GET', '/api/cases', { query: { tenant_id: tenant } });
  assert.equal(list.json.cases.length, 1);
});

test('notes and findings: limits and duplicate handling', async () => {
  const { store, tenant, caseId } = await bootstrap();
  assert.equal((await call(store, 'POST', '/api/cases/notes', { body: { tenant_id: tenant, case_id: caseId, body: 'x'.repeat(4001) } })).status, 400);
  const note = await call(store, 'POST', '/api/cases/notes', { body: { tenant_id: tenant, case_id: caseId, body: 'Called the user.' } });
  assert.equal(note.status, 201);
  const notes = await call(store, 'GET', '/api/cases/notes', { query: { tenant_id: tenant, case_id: caseId } });
  assert.equal(notes.json.notes.length, 1);
  const finding = { tenant_id: tenant, case_id: caseId, finding_key: 'k', title: 'T', severity: 'Review', detail: 'd', evidence_refs: ['e1'], source: 's' };
  assert.equal((await call(store, 'POST', '/api/findings', { body: finding })).status, 201);
  assert.equal((await call(store, 'POST', '/api/findings', { body: finding })).status, 409);
});

test('evidence records: sealed, idempotent conflict, tamper detected', async () => {
  const { store, tenant, caseId } = await bootstrap();
  const body = { tenant_id: tenant, case_id: caseId, source_label: 'log', event_kind: 'login', observed_at: '2026-11-20T10:00:00Z', summary: 'New device login', metadata: { local_evidence_id: 'ev-1', n: 2 } };
  const saved = await call(store, 'POST', '/api/evidence/records', { body });
  assert.equal(saved.status, 201);
  assert.equal(saved.json.evidence.source_sha256, await sha256Hex(canonicalJson(body.metadata)));
  assert.equal((await call(store, 'POST', '/api/evidence/records', { body })).status, 409);
  assert.equal((await call(store, 'POST', '/api/evidence/records', { body: { ...body, observed_at: '2026-11-20T10:00:00' } })).status, 400);
  const id = saved.json.evidence.id;
  const verify = await call(store, 'GET', `/api/evidence/${id}/verify`, { query: { tenant_id: tenant } });
  assert.equal(verify.json.matched, true);
  const state = await store.load();
  state.evidence[0].metadata.n = 3; // edit stored evidence behind the app's back
  await store.save(state);
  const after = await call(store, 'GET', `/api/evidence/${id}/verify`, { query: { tenant_id: tenant } });
  assert.equal(after.status, 409);
  assert.equal(after.json.matched, false);
});

test('evidence files: upload, verify, download, size limit, tamper detected', async () => {
  const { store, tenant, caseId } = await bootstrap();
  const form = new FormData();
  form.set('tenant_id', tenant); form.set('case_id', caseId); form.set('observed_at', new Date().toISOString());
  form.set('file', new File([new Uint8Array([1, 2, 3, 4])], 'mail.eml'));
  const up = await call(store, 'POST', '/api/evidence', { form });
  assert.equal(up.status, 201);
  assert.equal(up.json.evidence.source_sha256, await sha256Hex(new Uint8Array([1, 2, 3, 4])));
  const id = up.json.evidence.id;
  const dl = await call(store, 'GET', `/api/evidence/${id}/download`, { query: { tenant_id: tenant } });
  assert.deepEqual([...dl.bytes], [1, 2, 3, 4]);
  await store.putBlob(id, new Uint8Array([9, 9, 9, 9]));
  assert.equal((await call(store, 'GET', `/api/evidence/${id}/verify`, { query: { tenant_id: tenant } })).json.matched, false);
  assert.equal((await call(store, 'GET', `/api/evidence/${id}/download`, { query: { tenant_id: tenant } })).status, 409);
  const big = new FormData();
  big.set('tenant_id', tenant); big.set('case_id', caseId); big.set('observed_at', new Date().toISOString());
  big.set('file', new File([new Uint8Array(4 * 1024 * 1024 + 1)], 'big.bin'));
  assert.equal((await call(store, 'POST', '/api/evidence', { form: big })).status, 413);
});

test('reports: sealed snapshot verifies and detects edits', async () => {
  const { store, tenant, caseId } = await bootstrap();
  const snapshot = { schema_version: 1, notes: 'n', nested: { b: 1, a: 2 } };
  const made = await call(store, 'POST', '/api/reports', { body: { tenant_id: tenant, case_id: caseId, title: 'R', snapshot } });
  assert.equal(made.status, 201);
  assert.equal(made.json.snapshot_sha256, await sha256Hex(canonicalJson(snapshot)));
  const id = made.json.report.id;
  const got = await call(store, 'GET', `/api/reports/${id}`, { query: { tenant_id: tenant } });
  assert.equal(got.status, 200);
  assert.equal(got.json.integrity.matched, true);
  const state = await store.load(); state.reports[0].snapshot.notes = 'edited'; await store.save(state);
  const bad = await call(store, 'GET', `/api/reports/${id}`, { query: { tenant_id: tenant } });
  assert.equal(bad.status, 409);
  assert.equal(bad.json.integrity.matched, false);
});

test('audit chain verifies, scopes events to a case, and detects tampering', async () => {
  const { store, tenant, caseId } = await bootstrap();
  await call(store, 'POST', '/api/cases/notes', { body: { tenant_id: tenant, case_id: caseId, body: 'one' } });
  await call(store, 'PATCH', '/api/cases', { body: { tenant_id: tenant, id: caseId, status: 'resolved' } });
  const events = await call(store, 'GET', '/api/audit/events', { query: { tenant_id: tenant, case_id: caseId } });
  assert.deepEqual(events.json.events.map(e => e.action), ['case.created', 'case.note.created', 'case.updated']);
  const verify = await call(store, 'GET', '/api/audit/verify', { query: { tenant_id: tenant } });
  assert.equal(verify.json.chain_valid, true);
  assert.equal(verify.json.events_checked, 4);
  const state = await store.load();
  state.audit[2].payload.note_id = 'forged'; await store.save(state);
  const broken = await call(store, 'GET', '/api/audit/verify', { query: { tenant_id: tenant } });
  assert.equal(broken.json.chain_valid, false);
  assert.equal(broken.json.failed_event_id, state.audit[2].id);
  const removed = await store.load(); removed.audit.splice(1, 1); await store.save(removed);
  assert.equal((await verifyAuditChain(await store.load())).chain_valid, false);
});

test('export/import round-trips and rejects modified or broken backups', async () => {
  const { store, tenant, caseId } = await bootstrap();
  const form = new FormData();
  form.set('tenant_id', tenant); form.set('case_id', caseId); form.set('observed_at', new Date().toISOString());
  form.set('file', new File([new Uint8Array([7, 7, 7])], 'a.bin'));
  await call(store, 'POST', '/api/evidence', { form });
  const backup = JSON.parse(JSON.stringify(await exportWorkspace(store)));
  const target = createMemoryStore();
  const summary = await importWorkspace(target, backup);
  assert.equal(summary.cases, 1); assert.equal(summary.evidence, 1);
  assert.equal((await call(target, 'GET', '/api/audit/verify', { query: { tenant_id: tenant } })).json.chain_valid, true);
  assert.equal((await target.listBlobIds()).length, 1);

  const edited = JSON.parse(JSON.stringify(backup)); edited.state.cases[0].title = 'changed';
  await assert.rejects(importWorkspace(createMemoryStore(), edited), /modified after export/);
  const forged = JSON.parse(JSON.stringify(backup)); forged.state.audit[0].payload.workspace_id = 'x';
  delete forged.export_sha256; forged.export_sha256 = await sha256Hex(canonicalJson(forged));
  await assert.rejects(importWorkspace(createMemoryStore(), forged), /audit chain/);
  await assert.rejects(importWorkspace(createMemoryStore(), { format: 'other' }), /not a SATARK/);
  const untouched = createMemoryStore();
  await assert.rejects(importWorkspace(untouched, edited));
  assert.equal(await untouched.load(), null);
});

test('unavailable features say so plainly instead of pretending', async () => {
  const store = createMemoryStore();
  const invite = await call(store, 'POST', '/api/workspaces/invitations', { body: {} });
  assert.equal(invite.status, 501);
  assert.match(invite.json.error, /hosted SATARK service/);
});

async function addRecord(store, tenant, caseId, n, kind, summary, observed, sourceDetails) {
  const res = await call(store, 'POST', '/api/evidence/records', { body: { tenant_id: tenant, case_id: caseId, source_label: 'EDR', event_kind: kind,
    observed_at: observed, summary, metadata: { local_evidence_id: 'ev-' + n, browser_record_sha256: 'x', source_details: sourceDetails } } });
  assert.equal(res.status, 201);
  return res.json.evidence.id;
}

test('investigation: runs the ten-rule engine in the browser, saves findings and a sealed report, keeps the audit chain valid', async () => {
  const { store, tenant, caseId } = await bootstrap();
  const login = await addRecord(store, tenant, caseId, 1, 'authentication', 'Successful login from a new device', '2026-11-20T09:00:00Z', { account: 'ana', result: 'success', novel_source: true });
  const session = await addRecord(store, tenant, caseId, 2, 'session', 'Session established', '2026-11-20T09:01:00Z', { account: 'ana' });
  const proc = await addRecord(store, tenant, caseId, 3, 'process', 'Process started', '2026-11-20T09:05:00Z', { host: 'ws', parent: 'OUTLOOK.EXE', process: 'powershell.exe' });
  const net = await addRecord(store, tenant, caseId, 4, 'connection', 'Outbound connection', '2026-11-20T09:06:00Z', { host: 'ws', destination: 'c2.example.invalid' });

  const queued = await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'run-000001' } });
  assert.equal(queued.status, 202);
  const jobId = queued.json.job.id;
  const status = await call(store, 'GET', '/api/firstlight/jobs', { query: { tenant_id: tenant, job_id: jobId } });
  assert.equal(status.json.job.status, 'succeeded');
  assert.match(status.json.job.result_sha256, /^[0-9a-f]{64}$/);

  const titles = status.json.job.result.investigation.findings.map(f => f.title).sort();
  assert.deepEqual(titles, ['Follow-on identity session', 'Potentially suspicious network activity', 'Unfamiliar successful login', 'Unusual process ancestry']);
  const network = status.json.job.result.investigation.findings.find(f => f.rule_id === 'FL-NETWORK-001');
  assert.deepEqual(network.evidence_ids, [proc, net], 'network finding links the earlier process on the same host');
  assert.equal(status.json.job.result.integrity_summary.verified, 4);

  const saved = (await call(store, 'GET', '/api/findings', { query: { tenant_id: tenant, case_id: caseId } })).json.findings;
  assert.equal(saved.length, 4);
  assert.ok(saved.every(f => f.source === 'FIRSTLIGHT deterministic rules' && f.evidence_refs.length >= 1));
  assert.ok(saved.some(f => f.evidence_refs.includes(login)) && saved.some(f => f.evidence_refs.includes(session)));

  const reports = (await call(store, 'GET', '/api/reports', { query: { tenant_id: tenant, case_id: caseId } })).json.reports;
  assert.equal(reports.length, 1);
  assert.equal(reports[0].snapshot_sha256, status.json.job.result_sha256);
  const fetched = await call(store, 'GET', `/api/reports/${reports[0].id}`, { query: { tenant_id: tenant } });
  assert.equal(fetched.json.integrity.matched, true);

  assert.equal((await verifyAuditChain(await store.load())).chain_valid, true);
  const actions = (await call(store, 'GET', '/api/audit/events', { query: { tenant_id: tenant, case_id: caseId } })).json.events.map(e => e.action);
  assert.ok(actions.includes('investigation.queued') && actions.includes('investigation.completed'));

  // Same idempotency key returns the same job; a new key re-runs without duplicating findings.
  const again = await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'run-000001' } });
  assert.equal(again.json.job.id, jobId);
  const rerun = await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'run-000002' } });
  assert.equal(rerun.status, 202);
  assert.equal((await call(store, 'GET', '/api/findings', { query: { tenant_id: tenant, case_id: caseId } })).json.findings.length, 4);
  assert.equal((await call(store, 'GET', '/api/firstlight/jobs', { query: { tenant_id: tenant, case_id: caseId } })).json.jobs.length, 2);
});

test('investigation: evidence edited after saving is quarantined and never supports a finding', async () => {
  const { store, tenant, caseId } = await bootstrap();
  await addRecord(store, tenant, caseId, 1, 'email', 'Mailbox rule created: inbox forwarding to outside address', '2026-11-20T09:00:00Z', {});
  const state = await store.load();
  state.evidence[0].summary += ' (edited)'; // summary is not covered by the stored-byte digest, metadata is
  state.evidence[0].metadata.source_details = { edited: true };
  await store.save(state);
  const queued = await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'tamper-001' } });
  const job = (await call(store, 'GET', '/api/firstlight/jobs', { query: { tenant_id: tenant, job_id: queued.json.job.id } })).json.job;
  assert.equal(job.status, 'succeeded');
  assert.equal(job.result.integrity_summary.mismatched, 1);
  assert.equal(job.result.investigation.findings[0].title, 'No rule matched — analyst review required');
  assert.deepEqual(job.result.investigation.findings[0].evidence_ids, []);
});

test('investigation: validation and an empty case', async () => {
  const { store, tenant, caseId } = await bootstrap();
  const bad = await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'x' } });
  assert.equal(bad.status, 400);
  assert.equal((await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: 'missing', idempotency_key: 'valid-key-1' } })).status, 404);
  assert.equal((await call(store, 'GET', '/api/firstlight/jobs', { query: { tenant_id: tenant } })).status, 400);
  const empty = await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'empty-case-1' } });
  const job = (await call(store, 'GET', '/api/firstlight/jobs', { query: { tenant_id: tenant, job_id: empty.json.job.id } })).json.job;
  assert.equal(job.result.investigation.findings[0].title, 'No rule matched — analyst review required');
});

test('investigation: uploaded files are integrity-checked but contribute no event fields', async () => {
  const { store, tenant, caseId } = await bootstrap();
  const form = new FormData();
  form.set('tenant_id', tenant); form.set('case_id', caseId); form.set('observed_at', '2026-11-20T10:00:00Z');
  form.set('event_kind', 'file'); form.set('summary', 'Attachment');
  form.set('file', new File([new Uint8Array([1, 2, 3])], 'a.bin'));
  assert.equal((await call(store, 'POST', '/api/evidence', { form })).status, 201);
  const queued = await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'upload-0001' } });
  const job = (await call(store, 'GET', '/api/firstlight/jobs', { query: { tenant_id: tenant, job_id: queued.json.job.id } })).json.job;
  assert.equal(job.result.integrity_summary.verified, 1);
});

test('backups keep investigation jobs and still verify', async () => {
  const { store, tenant, caseId } = await bootstrap();
  await call(store, 'POST', '/api/firstlight/jobs', { body: { tenant_id: tenant, case_id: caseId, idempotency_key: 'backup-0001' } });
  const backup = await exportWorkspace(store);
  const fresh = createMemoryStore();
  await importWorkspace(fresh, JSON.parse(JSON.stringify(backup)));
  assert.equal((await call(fresh, 'GET', '/api/firstlight/jobs', { query: { tenant_id: tenant, case_id: caseId } })).json.jobs.length, 1);
});
