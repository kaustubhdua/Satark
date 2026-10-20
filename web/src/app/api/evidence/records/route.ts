import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
import { readBoundedJson } from '@/lib/read-bounded-json';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BODY = 24 * 1024;
function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort().map(key => JSON.stringify(key) + ':' + canonical(obj[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}
function reply(body: unknown, status = 200) { return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } }); }
function config() {
  const raw = process.env.SUPABASE_URL, key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return null;
  try { const url = new URL(raw); if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null; return { url: url.origin, key }; }
  catch { return null; }
}
export async function POST(request: Request) {
  const cfg = config(); if (!cfg) return reply({ error: 'Evidence storage is not configured.' }, 503);
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return reply({ error: 'Sign in is required.' }, 401);
  const token = match[1];
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 4000);
  let userId: string;
  try {
    const auth = await fetch(cfg.url + '/auth/v1/user', { headers: { apikey: cfg.key, Authorization: 'Bearer ' + token }, cache: 'no-store', signal: controller.signal });
    const value: unknown = auth.ok ? await auth.json() : null;
    if (!value || typeof value !== 'object' || !('id' in value) || typeof value.id !== 'string' || !UUID.test(value.id)) return reply({ error: 'Your session is invalid or expired.' }, 401);
    userId = value.id;
  } catch { return reply({ error: 'Authentication service is temporarily unavailable.' }, 503); }
  finally { clearTimeout(timer); }
  const parsed = await readBoundedJson(request, MAX_BODY);
  if (!parsed.ok) return reply({ error: parsed.error }, parsed.status);
  const input = parsed.value;
  if (!input || typeof input !== 'object' || Array.isArray(input)) return reply({ error: 'A bounded JSON object is required.' }, 400);
  const value = input as Record<string, unknown>;
  const tenantId = value.tenant_id, caseId = value.case_id;
  const source = typeof value.source_label === 'string' ? value.source_label.trim() : 'Imported event';
  const kind = typeof value.event_kind === 'string' ? value.event_kind.trim() : 'observation';
  const observedAt = typeof value.observed_at === 'string' ? value.observed_at : '';
  const summary = typeof value.summary === 'string' ? value.summary.trim() : '';
  const metadata = value.metadata && typeof value.metadata === 'object' && !Array.isArray(value.metadata) ? value.metadata : {};
  if (typeof tenantId !== 'string' || !UUID.test(tenantId) || typeof caseId !== 'string' || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  if (!source || source.length > 160 || !kind || kind.length > 100 || !summary || summary.length > 8192) return reply({ error: 'Evidence fields are missing or oversized.' }, 400);
  if (!observedAt || !Number.isFinite(Date.parse(observedAt)) || !/(Z|[+-]\d{2}:?\d{2})$/i.test(observedAt)) return reply({ error: 'observed_at must include an explicit timezone.' }, 400);
  const record = {
    tenant_id: tenantId, case_id: caseId, source_label: source, event_kind: kind,
    observed_at: new Date(observedAt).toISOString(), summary,
    metadata: { ...metadata as Record<string, unknown>, source: 'FIRSTLIGHT event record', record_hash_version: 2 },
    created_by: userId,
  };
  const canonicalRecord = canonical(record);
  const recordSha = createHash('sha256').update(canonicalRecord).digest('hex');
  try {
    const response = await fetch(cfg.url + '/rest/v1/satark_evidence', {
      method: 'POST',
      headers: { apikey: cfg.key, Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', Accept: 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ ...record, record_sha256: recordSha }), cache: 'no-store', signal: AbortSignal.timeout(8_000),
    });
    if (response.status === 401 || response.status === 403) return reply({ error: 'You do not have permission to add evidence to this case.' }, 403);
    if (response.status === 409) return reply({ error: 'This evidence record already exists.' }, 409);
    if (!response.ok) return reply({ error: 'Evidence record could not be saved. Check case access and retry.' }, 422);
    const rows: unknown = await response.json();
    if (!Array.isArray(rows) || !rows[0]) return reply({ error: 'Evidence storage returned an invalid response.' }, 502);
    return reply({ evidence: rows[0], record_sha256: recordSha }, 201);
  } catch { return reply({ error: 'Evidence storage is temporarily unavailable.' }, 503); }
}
