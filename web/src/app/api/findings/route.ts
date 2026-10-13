import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function reply(body: unknown, status = 200) { return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } }); }
function config() {
  const raw = process.env.SUPABASE_URL, key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return null;
  try { const url = new URL(raw); if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null; return { url: url.origin, key }; }
  catch { return null; }
}
async function auth(request: Request, cfg: {url:string;key:string}) {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return { token: null, userId: null, error: reply({ error: 'Sign in is required.' }, 401) };
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(cfg.url + '/auth/v1/user', { headers: { apikey: cfg.key, Authorization: 'Bearer ' + match[1] }, cache: 'no-store', signal: controller.signal });
    const user: unknown = response.ok ? await response.json() : null;
    if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string' || !UUID.test(user.id)) return { token: null, userId: null, error: reply({ error: 'Your session is invalid or expired.' }, 401) };
    return { token: match[1], userId: user.id, error: null };
  } catch { return { token: null, userId: null, error: reply({ error: 'Authentication service is temporarily unavailable.' }, 503) }; }
  finally { clearTimeout(timer); }
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort().map(key => JSON.stringify(key) + ':' + canonical(obj[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

const SEVERITIES = new Set(['info','low','medium','high','critical','review','unknown']);
export async function GET(request: Request) {
  const cfg = config(); if (!cfg) return reply({ error: 'Finding storage is not configured.' }, 503);
  const a = await auth(request, cfg); if (a.error || !a.token) return a.error ?? reply({ error: 'Sign in is required.' }, 401);
  const params = new URL(request.url).searchParams;
  const tenantId = params.get('tenant_id'), caseId = params.get('case_id');
  if (!tenantId || !UUID.test(tenantId) || !caseId || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  try {
    const query = new URLSearchParams({ select: 'id,tenant_id,case_id,finding_key,title,severity,detail,evidence_refs,source,confidence,created_by,created_at', tenant_id: 'eq.'+tenantId, case_id: 'eq.'+caseId, order: 'created_at.asc', limit: '500' });
    const response = await fetch(cfg.url + '/rest/v1/satark_findings?' + query, { headers: { apikey: cfg.key, Authorization: 'Bearer '+a.token }, cache: 'no-store' });
    if (response.status === 401 || response.status === 403) return reply({ error: 'Workspace access denied.' }, 403);
    if (!response.ok) return reply({ error: 'Finding storage is temporarily unavailable.' }, 503);
    return reply({ findings: await response.json() });
  } catch { return reply({ error: 'Finding storage is temporarily unavailable.' }, 503); }
}
export async function POST(request: Request) {
  const cfg = config(); if (!cfg) return reply({ error: 'Finding storage is not configured.' }, 503);
  const a = await auth(request, cfg); if (a.error || !a.token || !a.userId) return a.error ?? reply({ error: 'Sign in is required.' }, 401);
  const length = Number(request.headers.get('content-length') || 0); if (length > 24*1024) return reply({ error: 'Finding is too large.' }, 413);
  let body: unknown; try { body = await request.json(); } catch { return reply({ error: 'A valid JSON object is required.' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body) || Buffer.byteLength(JSON.stringify(body),'utf8') > 24*1024) return reply({ error: 'A bounded JSON object is required.' }, 400);
  const v = body as Record<string, unknown>;
  const tenantId = v.tenant_id, caseId = v.case_id;
  const key = typeof v.finding_key === 'string' ? v.finding_key.trim() : '';
  const title = typeof v.title === 'string' ? v.title.trim() : '';
  const severity = typeof v.severity === 'string' ? v.severity.toLowerCase() : 'unknown';
  const detail = typeof v.detail === 'string' ? v.detail.trim() : '';
  const refs = Array.isArray(v.evidence_refs) ? v.evidence_refs : [];
  const source = typeof v.source === 'string' ? v.source.slice(0,160) : 'FIRSTLIGHT deterministic rules';
  const confidence = typeof v.confidence === 'number' ? v.confidence : null;
  if (typeof tenantId !== 'string' || !UUID.test(tenantId) || typeof caseId !== 'string' || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  if (!key || key.length > 160 || !title || title.length > 240 || !SEVERITIES.has(severity) || !detail || detail.length > 8192 || refs.length > 100 || refs.some(x => typeof x !== 'string' || x.length > 100)) return reply({ error: 'Finding fields are invalid or oversized.' }, 400);
  if (confidence !== null && (!Number.isFinite(confidence) || confidence < 0 || confidence > 1)) return reply({ error: 'confidence must be between 0 and 1.' }, 400);
  try {
    const response = await fetch(cfg.url + '/rest/v1/satark_findings', {
      method: 'POST', headers: { apikey: cfg.key, Authorization: 'Bearer '+a.token, 'Content-Type':'application/json', Accept:'application/json', Prefer:'return=representation' },
      body: JSON.stringify({ tenant_id:tenantId,case_id:caseId,finding_key:key,title,severity,detail,evidence_refs:refs,source,confidence,created_by:a.userId }), cache:'no-store'
    });
    if (response.status === 401 || response.status === 403) return reply({ error: 'You do not have permission to save findings to this case.' }, 403);
    if (response.status === 409 || response.status === 400 && (await response.clone().text()).includes('duplicate key')) return reply({ error: 'This finding has already been saved for this case.' }, 409);
    if (!response.ok) return reply({ error: 'Finding could not be saved. Verify case access and retry.' }, 422);
    const rows: unknown = await response.json(); if (!Array.isArray(rows) || !rows[0]) return reply({ error: 'Finding storage returned an invalid response.' }, 502);
    return reply({ finding: rows[0] }, 201);
  } catch { return reply({ error: 'Finding storage is temporarily unavailable.' }, 503); }
}
