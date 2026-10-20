import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_SOURCE_BYTES = 4 * 1024 * 1024;

function reply(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
}

function config() {
  const rawUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!rawUrl || !publishableKey) return null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null;
    return { url: url.origin, publishableKey };
  } catch { return null; }
}

function bearer(request: Request): string | null {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  return match?.[1] ?? null;
}

async function getUserId(token: string, cfg: NonNullable<ReturnType<typeof config>>): Promise<string | null> {
  try {
    const response = await fetch(cfg.url + '/auth/v1/user', {
      headers: { apikey: cfg.publishableKey, Authorization: 'Bearer ' + token, Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000),
    });
    if (!response.ok) return null;
    const user: unknown = await response.json();
    return user && typeof user === 'object' && 'id' in user && typeof user.id === 'string' && UUID.test(user.id)
      ? user.id : null;
  } catch { return null; }
}

async function hasMembership(cfg: NonNullable<ReturnType<typeof config>>, token: string, userId: string, tenantId: string, caseId: string): Promise<boolean> {
  const headers = { apikey: cfg.publishableKey, Authorization: 'Bearer ' + token, Accept: 'application/json' };
  const membershipQuery = new URLSearchParams({
    select: 'tenant_id,user_id,role', tenant_id: 'eq.' + tenantId, user_id: 'eq.' + userId,
    role: 'in.(owner,responder,analyst)', limit: '1',
  });
  const caseQuery = new URLSearchParams({
    select: 'id,tenant_id', id: 'eq.' + caseId, tenant_id: 'eq.' + tenantId, limit: '1',
  });
  try {
    const [membership, targetCase] = await Promise.all([
      fetch(cfg.url + '/rest/v1/satark_memberships?' + membershipQuery, { headers, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000) }),
      fetch(cfg.url + '/rest/v1/satark_cases?' + caseQuery, { headers, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000) }),
    ]);
    if (!membership.ok || !targetCase.ok) return false;
    const [members, cases]: [unknown, unknown] = await Promise.all([membership.json(), targetCase.json()]);
    return Array.isArray(members) && members.length > 0 && Array.isArray(cases) && cases.length > 0;
  } catch { return false; }
}

export async function GET(request: Request) {
  const cfg = config();
  if (!cfg) return reply({ error: 'Storage authentication is not configured.' }, 503);
  const token = bearer(request);
  if (!token) return reply({ error: 'Sign in is required.' }, 401);
  const userId = await getUserId(token, cfg);
  if (!userId) return reply({ error: 'Your session is invalid or expired.' }, 401);

  const params = new URL(request.url).searchParams;
  const tenantId = params.get('tenant_id') || '';
  const caseId = params.get('case_id') || '';
  const objectPath = params.get('path') || '';
  if (!UUID.test(tenantId) || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  const pathMatch = new RegExp('^' + tenantId + '/' + caseId + '/wazuh/([0-9a-f]{64})\\.json$').exec(objectPath);
  if (!pathMatch) return reply({ error: 'The source-object path is invalid for this case.' }, 400);
  if (!(await hasMembership(cfg, token, userId, tenantId, caseId))) return reply({ error: 'You do not have an analyst role for this case or workspace.' }, 403);

  try {
    const safePath = objectPath.split('/').map(encodeURIComponent).join('/');
    const response = await fetch(cfg.url + '/storage/v1/object/authenticated/satark-evidence/' + safePath, {
      headers: { apikey: cfg.publishableKey, Authorization: 'Bearer ' + token, Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(12_000),
    });
    if (!response.ok) return reply({ error: response.status === 404 ? 'The preserved source object was not found.' : 'The source object could not be retrieved.' }, response.status === 404 ? 404 : 502);
    const reader = response.body?.getReader();
    if (!reader) return reply({ error: 'The source object response was empty.' }, 502);
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_SOURCE_BYTES) {
          void reader.cancel().catch(() => undefined);
          return reply({ error: 'The source object exceeds the configured 4 MiB bucket limit.' }, 502);
        }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))).map(value => value.toString(16).padStart(2, '0')).join('');
    if (hash !== pathMatch[1]) return reply({ error: 'Source-object integrity verification failed.' }, 409);
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': 'attachment; filename="wazuh-source-' + hash + '.json"',
        'Cache-Control': 'no-store',
        'X-Content-SHA256': hash,
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch {
    return reply({ error: 'Source object retrieval failed.' }, 503);
  }
}
