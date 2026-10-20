import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

function reply(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
}

function authConfig() {
  const rawUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!rawUrl || !publishableKey) return null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null;
    return { url: url.origin, publishableKey };
  } catch { return null; }
}

function backendConfig() {
  const rawUrl = process.env.FIRSTLIGHT_API_URL?.trim();
  const syncToken = process.env.FIRSTLIGHT_WAZUH_SYNC_TOKEN?.trim();
  if (!rawUrl || !syncToken || syncToken.length < 32) return null;
  try {
    const url = new URL(rawUrl);
    const localHosts = new Set(['localhost', '127.0.0.1', '::1', 'firstlight-api']);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && localHosts.has(url.hostname))) return null;
    if (url.username || url.password || url.search || url.hash) return null;
    return { baseUrl: url.origin, syncToken };
  } catch { return null; }
}

function bearer(request: Request): string | null {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  return match?.[1] ?? null;
}

async function authenticate(token: string, config: NonNullable<ReturnType<typeof authConfig>>): Promise<string | null> {
  try {
    const response = await fetch(config.url + '/auth/v1/user', {
      headers: { apikey: config.publishableKey, Authorization: 'Bearer ' + token, Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000),
    });
    if (!response.ok) return null;
    const user: unknown = await response.json();
    return !!user && typeof user === 'object' && 'id' in user && typeof user.id === 'string' && UUID.test(user.id) ? user.id : null;
  } catch { return null; }
}

export async function GET(request: Request) {
  const auth = authConfig();
  if (!auth) return reply({ error: 'Authentication is not configured on this deployment.' }, 503);
  const userToken = bearer(request);
  if (!userToken) return reply({ error: 'Sign in is required.' }, 401);
  const userId = await authenticate(userToken, auth);
  if (!userId) return reply({ error: 'Your session is invalid or expired.' }, 401);

  const requestUrl = new URL(request.url);
  const tenantId = requestUrl.searchParams.get('tenant_id') || '';
  if (!UUID.test(tenantId)) return reply({ error: 'A valid tenant_id is required.' }, 400);
  const membershipQuery = new URLSearchParams({
    select: 'tenant_id,user_id,role',
    tenant_id: 'eq.' + tenantId,
    user_id: 'eq.' + userId,
    role: 'in.(owner,responder,analyst)',
    limit: '1',
  });
  try {
    const membership = await fetch(auth.url + '/rest/v1/satark_memberships?' + membershipQuery.toString(), {
      headers: { apikey: auth.publishableKey, Authorization: 'Bearer ' + userToken, Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000),
    });
    if (membership.status === 401 || membership.status === 403) return reply({ error: 'Workspace access could not be verified.' }, 403);
    if (!membership.ok) return reply({ error: 'Workspace authorization is temporarily unavailable.' }, 503);
    const rows: unknown = await membership.json();
    if (!Array.isArray(rows) || rows.length === 0) return reply({ error: 'An analyst, responder, or owner role in this workspace is required.' }, 403);
  } catch {
    return reply({ error: 'Workspace authorization is temporarily unavailable.' }, 503);
  }

  const backend = backendConfig();
  if (!backend) return reply({ error: 'The private FIRSTLIGHT Wazuh connector is not configured.' }, 503);
  const url = requestUrl;
  const rawLimit = url.searchParams.get('limit') ?? '100';
  const limit = Number(rawLimit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) return reply({ error: 'limit must be an integer between 1 and 500.' }, 400);
  const since = url.searchParams.get('since');
  if (since !== null && (!/(Z|[+-]\d{2}:?\d{2})$/i.test(since) || !Number.isFinite(Date.parse(since)))) {
    return reply({ error: 'since must be an ISO-8601 timestamp with an explicit timezone.' }, 400);
  }

  try {
    const target = new URL(backend.baseUrl + '/api/v1/integrations/wazuh/alerts');
    target.searchParams.set('tenant_id', tenantId);
    target.searchParams.set('limit', String(limit));
    if (since) target.searchParams.set('since', since);
    const response = await fetch(target, {
      headers: { Authorization: 'Bearer ' + backend.syncToken, Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(12_000),
    });
    const reader = response.body?.getReader();
    if (!reader) return reply({ error: 'Wazuh connector returned an empty response.' }, 502);
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_RESPONSE_BYTES) {
          void reader.cancel().catch(() => undefined);
          return reply({ error: 'Wazuh connector response exceeded the allowed size.' }, 502);
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    let payload: unknown;
    try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { return reply({ error: 'Wazuh connector returned invalid JSON.' }, 502); }
    if (!response.ok) {
      const message = payload && typeof payload === 'object' && 'detail' in payload && typeof payload.detail === 'string'
        ? payload.detail : 'Wazuh connector request failed.';
      return reply({ error: message }, response.status >= 400 && response.status < 500 ? response.status : 503);
    }
    return reply(payload);
  } catch {
    return reply({ error: 'The private FIRSTLIGHT Wazuh connector is unreachable.' }, 503);
  }
}
