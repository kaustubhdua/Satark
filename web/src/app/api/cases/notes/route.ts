import { NextResponse } from 'next/server';
import { readBoundedJson } from '@/lib/read-bounded-json';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function reply(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
}
function config() {
  const raw = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null;
    return { url: url.origin, key };
  } catch { return null; }
}
async function authenticate(request: Request, cfg: NonNullable<ReturnType<typeof config>>) {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return { token: null, userId: null, error: reply({ error: 'Sign in is required.' }, 401) };
  try {
    const response = await fetch(cfg.url + '/auth/v1/user', {
      headers: { apikey: cfg.key, Authorization: 'Bearer ' + match[1], Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000),
    });
    const user: unknown = response.ok ? await response.json() : null;
    if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string' || !UUID.test(user.id)) {
      return { token: null, userId: null, error: reply({ error: 'Your session is invalid or expired.' }, 401) };
    }
    return { token: match[1], userId: user.id, error: null };
  } catch {
    return { token: null, userId: null, error: reply({ error: 'Authentication is temporarily unavailable.' }, 503) };
  }
}
function supabaseFetch(cfg: {url:string;key:string}, token: string, path: string, init: RequestInit = {}) {
  return fetch(cfg.url + '/rest/v1/' + path, {
    ...init,
    headers: {
      apikey: cfg.key, Authorization: 'Bearer ' + token, Accept: 'application/json',
      ...(init.body ? {'Content-Type':'application/json'} : {}), ...init.headers,
    },
    cache: 'no-store', redirect: 'error', signal: init.signal ?? AbortSignal.timeout(8000),
  });
}

export async function GET(request: Request) {
  const cfg = config();
  if (!cfg) return reply({ error: 'Case notes are not configured.' }, 503);
  const auth = await authenticate(request, cfg);
  if (auth.error || !auth.token) return auth.error ?? reply({ error: 'Sign in is required.' }, 401);
  const params = new URL(request.url).searchParams;
  const tenantId = params.get('tenant_id') || '';
  const caseId = params.get('case_id') || '';
  if (!UUID.test(tenantId) || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  try {
    const query = new URLSearchParams({
      select: 'id,tenant_id,case_id,body,created_by,created_at',
      tenant_id: 'eq.' + tenantId, case_id: 'eq.' + caseId,
      order: 'created_at.asc', limit: '200',
    });
    const response = await supabaseFetch(cfg, auth.token, 'satark_case_notes?' + query);
    if (response.status === 401 || response.status === 403) return reply({ error: 'Workspace access denied.' }, 403);
    if (!response.ok) return reply({ error: 'Case notes are temporarily unavailable.' }, 503);
    const notes: unknown = await response.json();
    if (!Array.isArray(notes)) return reply({ error: 'Case notes returned an invalid response.' }, 502);
    return reply({ notes });
  } catch { return reply({ error: 'Case notes are temporarily unavailable.' }, 503); }
}

export async function POST(request: Request) {
  const cfg = config();
  if (!cfg) return reply({ error: 'Case notes are not configured.' }, 503);
  const auth = await authenticate(request, cfg);
  if (auth.error || !auth.token || !auth.userId) return auth.error ?? reply({ error: 'Sign in is required.' }, 401);
  const parsed = await readBoundedJson(request, 8192);
  if (!parsed.ok) return reply({ error: parsed.error }, parsed.status);
  if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)) return reply({ error: 'A JSON object is required.' }, 400);
  const body = parsed.value as Record<string, unknown>;
  const tenantId = typeof body.tenant_id === 'string' ? body.tenant_id : '';
  const caseId = typeof body.case_id === 'string' ? body.case_id : '';
  const note = typeof body.body === 'string' ? body.body.trim() : '';
  if (!UUID.test(tenantId) || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  if (!note || note.length > 4000) return reply({ error: 'Note must contain 1–4000 characters.' }, 400);
  try {
    const response = await supabaseFetch(cfg, auth.token, 'satark_case_notes', {
      method: 'POST',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({ tenant_id: tenantId, case_id: caseId, body: note, created_by: auth.userId }),
    });
    if (response.status === 401 || response.status === 403) return reply({ error: 'Analyst, responder, or owner access to this case is required.' }, 403);
    if (!response.ok) return reply({ error: 'Note could not be saved. Verify case access and retry.' }, 422);
    const rows: unknown = await response.json();
    if (!Array.isArray(rows) || !rows[0]) return reply({ error: 'Note storage returned an invalid response.' }, 502);
    return reply({ note: rows[0] }, 201);
  } catch { return reply({ error: 'Case notes are temporarily unavailable.' }, 503); }
}
