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
    if (!user || typeof user !== 'object' || !('id' in user) ||
        typeof user.id !== 'string' || !UUID.test(user.id)) {
      return { token: null, userId: null, error: reply({ error: 'Your session is invalid or expired.' }, 401) };
    }
    return { token: match[1], userId: user.id, error: null };
  } catch {
    return { token: null, userId: null, error: reply({ error: 'Authentication is temporarily unavailable.' }, 503) };
  }
}

export async function POST(request: Request) {
  const cfg = config();
  if (!cfg) return reply({ error: 'Durable investigation jobs are not configured.' }, 503);
  const auth = await authenticate(request, cfg);
  if (auth.error || !auth.token || !auth.userId) return auth.error ?? reply({ error: 'Sign in is required.' }, 401);
  const parsed = await readBoundedJson(request, 4096);
  if (!parsed.ok) return reply({ error: parsed.error }, parsed.status);
  if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)) {
    return reply({ error: 'A JSON object is required.' }, 400);
  }
  const body = parsed.value as Record<string, unknown>;
  const tenantId = typeof body.tenant_id === 'string' ? body.tenant_id : '';
  const caseId = typeof body.case_id === 'string' ? body.case_id : '';
  const idempotencyKey = typeof body.idempotency_key === 'string' ? body.idempotency_key.trim() : '';
  if (!UUID.test(tenantId) || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  if (!/^[A-Za-z0-9._:-]{8,160}$/.test(idempotencyKey)) {
    return reply({ error: 'A stable 8–160 character idempotency_key is required for safe retries.' }, 400);
  }
  try {
    const response = await fetch(cfg.url + '/rest/v1/satark_investigation_jobs?on_conflict=tenant_id,case_id,idempotency_key', {
      method: 'POST',
      headers: {
        apikey: cfg.key, Authorization: 'Bearer ' + auth.token,
        'Content-Type': 'application/json', Accept: 'application/json',
        Prefer: 'resolution=ignore-duplicates,return=representation',
      },
      body: JSON.stringify({
        tenant_id: tenantId, case_id: caseId, requested_by: auth.userId,
        idempotency_key: idempotencyKey, status: 'queued',
      }),
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(8000),
    });
    if (response.status === 401 || response.status === 403) return reply({ error: 'Analyst, responder, or owner access to this case is required.' }, 403);
    if (!response.ok) return reply({ error: 'The investigation job could not be queued. Verify case access and database migration status.' }, 503);
    const rows: unknown = await response.json();
    if (!Array.isArray(rows) || !rows[0]) {
      // Ignore-duplicate intentionally returns no representation. Look up the
      // same idempotency key with the same user token; RLS scopes the result.
      const query = new URLSearchParams({
        select: 'id,tenant_id,case_id,requested_by,idempotency_key,status,attempts,max_attempts,run_version,result,result_sha256,error_code,created_at,updated_at,started_at,finished_at',
        tenant_id: 'eq.' + tenantId, case_id: 'eq.' + caseId,
        idempotency_key: 'eq.' + idempotencyKey, limit: '1',
      });
      const existing = await fetch(cfg.url + '/rest/v1/satark_investigation_jobs?' + query, {
        headers: { apikey: cfg.key, Authorization: 'Bearer ' + auth.token, Accept: 'application/json' },
        cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(8000),
      });
      if (!existing.ok) return reply({ error: 'Job was queued but its status could not be read.' }, 503);
      const found: unknown = await existing.json();
      if (!Array.isArray(found) || !found[0]) return reply({ error: 'Job status is not yet available.' }, 503);
      return reply({ job: found[0], idempotent_replay: true }, 200);
    }
    return reply({ job: rows[0], idempotent_replay: false }, 202);
  } catch {
    return reply({ error: 'The durable job queue is temporarily unavailable.' }, 503);
  }
}

export async function GET(request: Request) {
  const cfg = config();
  if (!cfg) return reply({ error: 'Durable investigation jobs are not configured.' }, 503);
  const auth = await authenticate(request, cfg);
  if (auth.error || !auth.token) return auth.error ?? reply({ error: 'Sign in is required.' }, 401);
  const params = new URL(request.url).searchParams;
  const tenantId = params.get('tenant_id') || '';
  const jobId = params.get('job_id') || '';
  if (!UUID.test(tenantId) || !UUID.test(jobId)) return reply({ error: 'Valid tenant_id and job_id are required.' }, 400);
  try {
    const query = new URLSearchParams({
      select: 'id,tenant_id,case_id,requested_by,idempotency_key,status,attempts,max_attempts,run_version,result,result_sha256,error_code,created_at,updated_at,started_at,finished_at',
      id: 'eq.' + jobId, tenant_id: 'eq.' + tenantId, limit: '1',
    });
    const response = await fetch(cfg.url + '/rest/v1/satark_investigation_jobs?' + query, {
      headers: { apikey: cfg.key, Authorization: 'Bearer ' + auth.token, Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(8000),
    });
    if (response.status === 401 || response.status === 403) return reply({ error: 'Workspace access denied.' }, 403);
    if (!response.ok) return reply({ error: 'Job status is temporarily unavailable.' }, 503);
    const rows: unknown = await response.json();
    if (!Array.isArray(rows) || !rows[0]) return reply({ error: 'Job not found.' }, 404);
    return reply({ job: rows[0] });
  } catch {
    return reply({ error: 'Job status is temporarily unavailable.' }, 503);
  }
}
