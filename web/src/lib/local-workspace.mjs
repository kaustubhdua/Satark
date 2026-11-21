// Browser-only SATARK workspace.
//
// When no hosted SATARK API is configured, cases, notes, findings, evidence,
// reports and the audit trail live in the visitor's own browser (IndexedDB).
// Nothing is sent to a server. This module is the pure logic: it mirrors the
// response shapes of the FastAPI backend (satark_backend.py) so the existing
// UI works unchanged, and it uses the same integrity rules:
//
//  * evidence digests are SHA-256 over the stored bytes and are recomputed on
//    verify, so edits to stored evidence are detected;
//  * report snapshots are sealed with SHA-256 over canonical JSON;
//  * the audit trail is a hash chain, verified end to end.
//
// Honest limits: the data is only as durable as the browser profile (clearing
// site data erases it; use Export for backups), and a person with devtools can
// edit their own local data, so the hashes detect accidental or casual
// tampering, not a determined local attacker.

export const LOCAL_FORMAT = 'satark-local-workspace';
export const LOCAL_VERSION = 1;
export const MAX_EVIDENCE_BYTES = 4 * 1024 * 1024;
export const MAX_SNAPSHOT_BYTES = 256 * 1024;
const GENESIS = '0'.repeat(64);
const STATUSES = ['open', 'contained', 'resolved', 'archived'];
const SEVERITIES = ['unknown', 'info', 'low', 'medium', 'high', 'critical'];

/** Path prefixes this module answers. Everything else goes to the network. */
export const LOCAL_ROUTES = [
  '/api/auth/session', '/api/auth/refresh', '/api/auth/logout', '/api/auth/login', '/api/auth/signup',
  '/api/workspaces', '/api/cases', '/api/findings', '/api/reports', '/api/evidence', '/api/audit',
];

export function isLocalRoute(pathname) {
  return LOCAL_ROUTES.some(prefix => pathname === prefix || pathname.startsWith(prefix + '/'));
}

// ---------- hashing ----------
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(value).sort().filter(k => value[k] !== undefined)
    .map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

export async function sha256Hex(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

const uuid = () => globalThis.crypto.randomUUID();
const nowIso = () => new Date().toISOString();

// ---------- storage ----------
/** In-memory adapter: used by tests and as a fallback when IndexedDB is blocked. */
export function createMemoryStore() {
  let state = null;
  const blobs = new Map();
  return {
    kind: 'memory',
    async load() { return state ? structuredClone(state) : null; },
    async save(next) { state = structuredClone(next); },
    async putBlob(id, bytes) { blobs.set(id, new Uint8Array(bytes).slice()); },
    async getBlob(id) { return blobs.has(id) ? blobs.get(id).slice() : null; },
    async listBlobIds() { return [...blobs.keys()]; },
    async clear() { state = null; blobs.clear(); },
  };
}

export function emptyState() {
  const created = nowIso();
  const userId = uuid();
  const tenantId = uuid();
  return {
    format: LOCAL_FORMAT, version: LOCAL_VERSION, created_at: created,
    user: { id: userId, email: 'this-device@satark.local' },
    tenant: { id: tenantId, name: 'This device', role: 'owner' },
    cases: [], notes: [], findings: [], evidence: [], reports: [], audit: [],
  };
}

async function appendAudit(state, eventType, payload) {
  const previous = state.audit.length ? state.audit[state.audit.length - 1].event_hash : GENESIS;
  const record = { tenant_id: state.tenant.id, actor_id: state.user.id, event_type: eventType, payload, previous_hash: previous };
  const eventHash = await sha256Hex(canonicalJson(record));
  state.audit.push({
    id: uuid(), sequence: state.audit.length + 1, tenant_id: state.tenant.id, actor_id: state.user.id,
    event_type: eventType, payload, previous_hash: previous, event_hash: eventHash, created_at: nowIso(),
  });
}

export async function verifyAuditChain(state) {
  let previous = GENESIS;
  for (const row of state.audit) {
    const record = { tenant_id: row.tenant_id, actor_id: row.actor_id, event_type: row.event_type, payload: row.payload, previous_hash: row.previous_hash };
    const actual = await sha256Hex(canonicalJson(record));
    if (row.previous_hash !== previous || actual !== row.event_hash) {
      return { tenant_id: state.tenant.id, chain_valid: false, events_checked: state.audit.length, failed_event_id: row.id, failure: 'hash_or_link_mismatch' };
    }
    previous = row.event_hash;
  }
  return { tenant_id: state.tenant.id, chain_valid: true, events_checked: state.audit.length, head_sha256: previous, verified_at: nowIso() };
}

// ---------- helpers ----------
const ok = (json, status = 200) => ({ status, json });
const fail = (status, message) => ({ status, json: { error: message } });
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);

function caseJson(row) {
  return { id: row.id, tenant_id: row.tenant_id, title: row.title, status: row.status, severity: row.severity,
    assigned_to: row.assigned_to ?? null, created_by: row.created_by, created_at: row.created_at, updated_at: row.updated_at, metadata: row.metadata ?? {} };
}

function requireTenant(state, tenantId) {
  return tenantId === state.tenant.id ? null : fail(404, 'Workspace not found on this device.');
}

function requireCase(state, tenantId, caseId) {
  const found = state.cases.find(c => c.id === caseId && c.tenant_id === tenantId);
  return found ? { row: found } : { error: fail(404, 'Case not found.') };
}

function evidenceJson(row) {
  return { id: row.id, tenant_id: row.tenant_id, case_id: row.case_id, source_label: row.source_label, event_kind: row.event_kind,
    observed_at: row.observed_at, summary: row.summary, source_sha256: row.source_sha256, size_bytes: row.size_bytes,
    content_type: row.content_type, original_filename: row.original_filename, metadata: row.metadata ?? {},
    created_by: row.created_by, created_at: row.created_at };
}

function parseObservedAt(value) {
  const text = String(value ?? '');
  if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(text) || Number.isNaN(Date.parse(text))) return null;
  return new Date(text).toISOString();
}

function notAvailable(what) {
  return fail(501, what + ' needs the hosted SATARK service, which is not configured. Your browser-only workspace keeps working without it.');
}

// ---------- request handling ----------
/**
 * @param {ReturnType<typeof createMemoryStore>} store
 * @param {{method:string, path:string, query:URLSearchParams, body?:any, form?:FormData}} request
 */
export async function handleLocalRequest(store, request) {
  const method = request.method.toUpperCase();
  const path = request.path.replace(/\/+$/, '') || '/';
  const query = request.query ?? new URLSearchParams();
  const body = request.body;

  let state = await store.load();
  let dirty = false;
  if (!state) { state = emptyState(); await appendAudit(state, 'workspace.created', { workspace_id: state.tenant.id }); dirty = true; }
  const commit = async () => { await store.save(state); };
  try {
    const result = await route();
    if (dirty || result.write) await commit();
    return result.response ?? result;
  } catch (error) {
    return fail(500, error instanceof Error ? error.message : 'Local workspace error.');
  }

  async function route() {
    const session = () => {
      const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000);
      return { user: state.user, expires_at: expires.toISOString(), expires_in: 30 * 24 * 3600 };
    };
    if (path === '/api/auth/session' && method === 'GET') return wrap(ok(session()));
    if (path === '/api/auth/refresh' && method === 'POST') return wrap(ok(session()));
    if (path === '/api/auth/logout' && method === 'POST') return wrap(ok({ ok: true }));
    if (path === '/api/auth/login' || path === '/api/auth/signup') {
      return wrap(fail(400, 'This site is running in browser-only mode: your workspace lives on this device and needs no account.'));
    }
    if (path.startsWith('/api/auth/')) return wrap(notAvailable('Account security features'));

    if (path === '/api/workspaces' && method === 'GET') return wrap(ok({ workspaces: [{ id: state.tenant.id, name: state.tenant.name, role: 'owner' }] }));
    if (path === '/api/workspaces' && method === 'POST') {
      const name = typeof body?.name === 'string' ? body.name.trim() : '';
      if (!name || name.length > 120) return wrap(fail(400, 'Workspace name must be 1-120 characters.'));
      state.tenant.name = name;
      await appendAudit(state, 'workspace.renamed', { workspace_id: state.tenant.id });
      return { response: ok({ id: state.tenant.id, name, role: 'owner' }, 201), write: true };
    }
    if (path === '/api/workspaces/members' && method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      return wrap(ok({ members: [{ user_id: state.user.id, email: state.user.email, role: 'owner' }] }));
    }
    if (path === '/api/workspaces/invitations' && method === 'GET') return wrap(ok({ invitations: [] }));
    if (path.startsWith('/api/workspaces')) return wrap(notAvailable('Inviting people'));

    if (path === '/api/cases') return cases();
    if (path === '/api/cases/notes') return notes();
    if (path === '/api/findings') return findings();
    if (path === '/api/reports' || path.startsWith('/api/reports/')) return reports();
    if (path === '/api/evidence' || path.startsWith('/api/evidence/')) return evidence();
    if (path === '/api/audit/events' && method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, query.get('case_id')); if (found.error) return wrap(found.error);
      const events = state.audit.filter(e => e.payload?.case_id === found.row.id).slice(-500)
        .map(e => ({ id: e.id, sequence: e.sequence, action: e.event_type, details: e.payload, actor_id: e.actor_id, created_at: e.created_at, event_hash: e.event_hash }));
      return wrap(ok({ events }));
    }
    if (path === '/api/audit/verify' && method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const result = await verifyAuditChain(state);
      return wrap(ok(result));
    }
    return wrap(fail(404, 'Unknown browser-workspace route.'));
  }

  function wrap(response) { return { response, write: false }; }

  async function cases() {
    if (method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const rows = [...state.cases].sort((a, b) => b.updated_at.localeCompare(a.updated_at)).slice(0, 100);
      return wrap(ok({ cases: rows.map(caseJson) }));
    }
    if (method === 'POST') {
      const denied = requireTenant(state, body?.tenant_id); if (denied) return wrap(denied);
      const title = typeof body?.title === 'string' ? body.title.trim() : '';
      if (!title || title.length > 240) return wrap(fail(400, 'Case title must be 1-240 characters.'));
      const status = body.status ?? 'open'; const severity = body.severity ?? 'unknown';
      if (!STATUSES.includes(status) || !SEVERITIES.includes(severity)) return wrap(fail(400, 'Invalid case status or severity.'));
      const stamp = nowIso();
      const row = { id: uuid(), tenant_id: state.tenant.id, title, status, severity, assigned_to: null, created_by: state.user.id, created_at: stamp, updated_at: stamp, metadata: isObject(body.metadata) ? body.metadata : {} };
      state.cases.push(row);
      await appendAudit(state, 'case.created', { case_id: row.id });
      return { response: ok({ case: caseJson(row) }, 201), write: true };
    }
    if (method === 'PATCH') {
      const denied = requireTenant(state, body?.tenant_id); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, body?.case_id || body?.id); if (found.error) return wrap(found.error);
      const allowed = ['title', 'status', 'severity', 'assigned_to', 'metadata'];
      if (!allowed.some(k => k in body)) return wrap(fail(400, 'At least one case field must be provided for update.'));
      const row = found.row;
      if ('title' in body) {
        if (typeof body.title !== 'string' || !body.title.trim() || body.title.length > 240) return wrap(fail(400, 'Case title is invalid.'));
        row.title = body.title.trim();
      }
      if ('status' in body) { if (!STATUSES.includes(body.status)) return wrap(fail(400, 'Invalid case status.')); row.status = body.status; }
      if ('severity' in body) { if (!SEVERITIES.includes(body.severity)) return wrap(fail(400, 'Invalid case severity.')); row.severity = body.severity; }
      if ('assigned_to' in body) {
        if (body.assigned_to !== null && body.assigned_to !== state.user.id) return wrap(fail(400, 'The assignee must be an active workspace member.'));
        row.assigned_to = body.assigned_to;
      }
      if ('metadata' in body) {
        if (!isObject(body.metadata) || JSON.stringify(body.metadata).length > 16 * 1024) return wrap(fail(400, 'Case metadata is invalid or oversized.'));
        row.metadata = body.metadata;
      }
      row.updated_at = nowIso();
      await appendAudit(state, 'case.updated', { case_id: row.id, fields: allowed.filter(k => k in body).sort() });
      return { response: ok({ case: caseJson(row) }), write: true };
    }
    return wrap(fail(405, 'Method not allowed.'));
  }

  async function notes() {
    if (method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, query.get('case_id')); if (found.error) return wrap(found.error);
      return wrap(ok({ notes: state.notes.filter(n => n.case_id === found.row.id).slice(0, 200) }));
    }
    if (method === 'POST') {
      const denied = requireTenant(state, body?.tenant_id); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, body?.case_id); if (found.error) return wrap(found.error);
      const text = typeof body.body === 'string' ? body.body.trim() : '';
      if (!text || text.length > 4000) return wrap(fail(400, 'Notes must contain 1-4000 characters.'));
      const note = { id: uuid(), tenant_id: state.tenant.id, case_id: found.row.id, body: text, created_by: state.user.id, created_at: nowIso() };
      state.notes.push(note);
      await appendAudit(state, 'case.note.created', { case_id: found.row.id, note_id: note.id });
      return { response: ok({ note }, 201), write: true };
    }
    return wrap(fail(405, 'Method not allowed.'));
  }

  async function findings() {
    if (method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      return wrap(ok({ findings: state.findings.filter(f => f.case_id === query.get('case_id')).slice(0, 500) }));
    }
    if (method === 'POST') {
      const denied = requireTenant(state, body?.tenant_id); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, body?.case_id); if (found.error) return wrap(found.error);
      const key = typeof body.finding_key === 'string' ? body.finding_key.trim() : '';
      const title = typeof body.title === 'string' ? body.title.trim() : '';
      if (!key || key.length > 160 || !title || title.length > 240) return wrap(fail(400, 'Finding key and title are required.'));
      if (state.findings.some(f => f.case_id === found.row.id && f.finding_key === key)) return wrap(fail(409, 'This finding already exists for this case.'));
      const confidence = body.confidence ?? null;
      if (confidence !== null && !(typeof confidence === 'number' && confidence >= 0 && confidence <= 1)) return wrap(fail(400, 'confidence must be between 0 and 1.'));
      const row = { id: uuid(), tenant_id: state.tenant.id, case_id: found.row.id, finding_key: key, title,
        severity: String(body.severity ?? 'Review').slice(0, 40), detail: String(body.detail ?? '').slice(0, 8192),
        evidence_refs: Array.isArray(body.evidence_refs) ? body.evidence_refs.map(String).slice(0, 200) : [],
        source: String(body.source ?? 'manual').slice(0, 160), confidence, created_by: state.user.id, created_at: nowIso() };
      state.findings.push(row);
      return { response: ok({ finding: row }, 201), write: true };
    }
    return wrap(fail(405, 'Method not allowed.'));
  }

  async function reports() {
    const reportMeta = r => ({ id: r.id, tenant_id: r.tenant_id, case_id: r.case_id, title: r.title, report_version: r.report_version, snapshot_sha256: r.snapshot_sha256, created_by: r.created_by, created_at: r.created_at });
    if (path === '/api/reports' && method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const rows = state.reports.filter(r => r.case_id === query.get('case_id')).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 100);
      return wrap(ok({ reports: rows.map(reportMeta) }));
    }
    if (path === '/api/reports' && method === 'POST') {
      const denied = requireTenant(state, body?.tenant_id); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, body?.case_id); if (found.error) return wrap(found.error);
      const snapshot = body.snapshot;
      if (!isObject(snapshot) || new TextEncoder().encode(JSON.stringify(snapshot)).length > MAX_SNAPSHOT_BYTES) return wrap(fail(400, 'A bounded report snapshot is required.'));
      const digest = await sha256Hex(canonicalJson(snapshot));
      const row = { id: uuid(), tenant_id: state.tenant.id, case_id: found.row.id, title: String(body.title || 'Investigation report').slice(0, 240),
        report_version: 1, snapshot: structuredClone(snapshot), snapshot_sha256: digest, created_by: state.user.id, created_at: nowIso() };
      state.reports.push(row);
      await appendAudit(state, 'report.created', { report_id: row.id, case_id: found.row.id, sha256: digest });
      // Backend returns {report}; the UI also reads snapshot_sha256 at top level.
      return { response: ok({ report: reportMeta(row), snapshot_sha256: digest }, 201), write: true };
    }
    const id = decodeURIComponent(path.split('/')[3] || '');
    if (method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const row = state.reports.find(r => r.id === id);
      if (!row) return wrap(fail(404, 'Report not found.'));
      const actual = await sha256Hex(canonicalJson(row.snapshot));
      const matched = actual === row.snapshot_sha256;
      return wrap(ok({ report: { ...reportMeta(row), snapshot: row.snapshot },
        integrity: { algorithm: 'SHA-256', expected_sha256: row.snapshot_sha256, actual_sha256: actual, matched } }, matched ? 200 : 409));
    }
    return wrap(fail(405, 'Method not allowed.'));
  }

  async function evidence() {
    if (path === '/api/evidence' && method === 'POST') {
      const form = request.form;
      if (!form) return wrap(fail(400, 'A multipart upload is required.'));
      const denied = requireTenant(state, form.get('tenant_id')); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, form.get('case_id')); if (found.error) return wrap(found.error);
      const file = form.get('file');
      if (!file || typeof file === 'string' || typeof file.arrayBuffer !== 'function') return wrap(fail(400, 'An evidence file is required.'));
      if (file.size > MAX_EVIDENCE_BYTES) return wrap(fail(413, 'Evidence file exceeds 4 MiB.'));
      const observed = parseObservedAt(form.get('observed_at'));
      if (!observed) return wrap(fail(400, 'observed_at must include an explicit timezone.'));
      const bytes = new Uint8Array(await file.arrayBuffer());
      const id = uuid(); const digest = await sha256Hex(bytes);
      await store.putBlob(id, bytes);
      const row = { id, tenant_id: state.tenant.id, case_id: found.row.id, source_label: String(form.get('source_label') || 'Uploaded evidence').slice(0, 160),
        event_kind: String(form.get('event_kind') || 'file').slice(0, 100), observed_at: observed, summary: String(form.get('summary') || 'Evidence file uploaded.').slice(0, 8192),
        source_sha256: digest, size_bytes: bytes.length, content_type: 'application/octet-stream',
        original_filename: String(file.name || 'evidence.bin').slice(0, 200), blob: true, metadata: {}, created_by: state.user.id, created_at: nowIso() };
      state.evidence.push(row);
      await appendAudit(state, 'evidence.uploaded', { evidence_id: id, case_id: found.row.id, sha256: digest });
      return { response: ok({ evidence: evidenceJson(row) }, 201), write: true };
    }
    if (path === '/api/evidence/records' && method === 'POST') {
      const denied = requireTenant(state, body?.tenant_id); if (denied) return wrap(denied);
      const found = requireCase(state, state.tenant.id, body?.case_id); if (found.error) return wrap(found.error);
      const source = String(body.source_label || 'Imported event').trim();
      const kind = String(body.event_kind || 'observation').trim();
      const summary = String(body.summary || '').trim();
      if (!source || source.length > 160 || !kind || kind.length > 100 || !summary || summary.length > 8192) return wrap(fail(400, 'Evidence metadata is invalid or oversized.'));
      const observed = parseObservedAt(body.observed_at);
      if (!observed) return wrap(fail(400, 'observed_at must include an explicit timezone.'));
      const metadata = isObject(body.metadata) ? body.metadata : {};
      const raw = canonicalJson(metadata);
      if (new TextEncoder().encode(raw).length > MAX_EVIDENCE_BYTES) return wrap(fail(413, 'Evidence metadata exceeds 4 MiB.'));
      const localId = metadata.local_evidence_id;
      if (typeof localId === 'string' && state.evidence.some(e => e.case_id === found.row.id && e.metadata?.local_evidence_id === localId)) {
        return wrap(fail(409, 'This evidence record already exists for this case.'));
      }
      const digest = await sha256Hex(raw);
      const row = { id: uuid(), tenant_id: state.tenant.id, case_id: found.row.id, source_label: source, event_kind: kind, observed_at: observed, summary,
        source_sha256: digest, size_bytes: new TextEncoder().encode(raw).length, content_type: 'application/json', original_filename: 'evidence.json',
        blob: false, metadata: structuredClone(metadata), created_by: state.user.id, created_at: nowIso() };
      state.evidence.push(row);
      await appendAudit(state, 'evidence.record.imported', { evidence_id: row.id, case_id: found.row.id, sha256: digest });
      return { response: ok({ evidence: evidenceJson(row) }, 201), write: true };
    }
    if ((path === '/api/evidence' || path === '/api/evidence/records') && method === 'GET') {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const rows = state.evidence.filter(e => e.case_id === query.get('case_id')).sort((a, b) => a.observed_at.localeCompare(b.observed_at)).slice(0, 500);
      return wrap(ok({ evidence: rows.map(evidenceJson) }));
    }
    const parts = path.split('/');
    const evidenceId = decodeURIComponent(parts[3] || ''); const action = parts[4];
    if (method === 'GET' && (action === 'verify' || action === 'download')) {
      const denied = requireTenant(state, query.get('tenant_id')); if (denied) return wrap(denied);
      const row = state.evidence.find(e => e.id === evidenceId);
      if (!row) return wrap(fail(404, 'Evidence not found.'));
      const bytes = row.blob ? await store.getBlob(row.id) : new TextEncoder().encode(canonicalJson(row.metadata ?? {}));
      if (!bytes) return wrap(fail(409, 'Evidence bytes are missing from this browser.'));
      const actual = await sha256Hex(bytes);
      const matched = actual === row.source_sha256;
      if (action === 'download') {
        if (!matched) return wrap(fail(409, 'Evidence integrity verification failed.'));
        return wrap({ status: 200, bytes, filename: row.original_filename, contentType: 'application/octet-stream' });
      }
      return wrap(ok({ evidence_id: row.id, algorithm: 'SHA-256', expected_sha256: row.source_sha256, actual_sha256: actual, matched, verified_at: nowIso(),
        note: 'Digest match verifies stored bytes against the upload record; it does not prove original source authenticity.' }, matched ? 200 : 409));
    }
    return wrap(fail(404, 'Unknown evidence route.'));
  }
}

// ---------- backup / restore ----------
const toBase64 = bytes => { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return globalThis.btoa(s); };
const fromBase64 = text => Uint8Array.from(globalThis.atob(text), c => c.charCodeAt(0));

export async function exportWorkspace(store) {
  const state = (await store.load()) ?? emptyState();
  const blobs = {};
  for (const row of state.evidence) if (row.blob) { const bytes = await store.getBlob(row.id); if (bytes) blobs[row.id] = toBase64(bytes); }
  const body = { format: LOCAL_FORMAT, version: LOCAL_VERSION, exported_at: nowIso(), state, blobs };
  return { ...body, export_sha256: await sha256Hex(canonicalJson(body)) };
}

/** Validates a backup completely before replacing anything. */
export async function importWorkspace(store, backup) {
  if (!isObject(backup) || backup.format !== LOCAL_FORMAT || backup.version !== LOCAL_VERSION || !isObject(backup.state)) throw new Error('This file is not a SATARK workspace backup.');
  const { export_sha256: claimed, ...body } = backup;
  if (claimed !== await sha256Hex(canonicalJson(body))) throw new Error('The backup file was modified after export (SHA-256 mismatch). Nothing was imported.');
  const state = backup.state;
  for (const key of ['cases', 'notes', 'findings', 'evidence', 'reports', 'audit']) if (!Array.isArray(state[key])) throw new Error('The backup is missing "' + key + '".');
  if (!isObject(state.user) || !isObject(state.tenant) || typeof state.tenant.id !== 'string') throw new Error('The backup is missing its workspace identity.');
  const chain = await verifyAuditChain(state);
  if (!chain.chain_valid) throw new Error('The backup\'s audit chain does not verify. Nothing was imported.');
  for (const row of state.evidence) if (row.blob) {
    const encoded = backup.blobs?.[row.id];
    if (typeof encoded !== 'string' || await sha256Hex(fromBase64(encoded)) !== row.source_sha256) throw new Error('Evidence file ' + row.id + ' does not match its recorded SHA-256. Nothing was imported.');
  }
  await store.clear();
  for (const row of state.evidence) if (row.blob) await store.putBlob(row.id, fromBase64(backup.blobs[row.id]));
  await store.save(state);
  return { cases: state.cases.length, evidence: state.evidence.length, reports: state.reports.length, audit_events: state.audit.length };
}
