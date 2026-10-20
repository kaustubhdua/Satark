import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

function bearer(request: Request): string | null {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  return match?.[1] ?? null;
}

async function authenticate(token: string, config: NonNullable<ReturnType<typeof authConfig>>): Promise<boolean> {
  try {
    const response = await fetch(config.url + '/auth/v1/user', {
      headers: { apikey: config.publishableKey, Authorization: 'Bearer ' + token, Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000),
    });
    if (!response.ok) return false;
    const user: unknown = await response.json();
    return !!user && typeof user === 'object' && 'id' in user && typeof user.id === 'string' && UUID.test(user.id);
  } catch { return false; }
}

function backendConfig() {
  const raw = process.env.FIRSTLIGHT_API_URL?.trim();
  const token = process.env.FIRSTLIGHT_API_TOKEN?.trim();
  if (!raw || !token || token.length < 32) return null;
  try {
    const url = new URL(raw);
    const localHosts = new Set(['localhost', '127.0.0.1', '::1', 'firstlight-api']);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && localHosts.has(url.hostname))) return null;
    if (url.username || url.password || url.search || url.hash) return null;
    return { baseUrl: url.origin, token };
  } catch {
    return null;
  }
}

export async function POST(request: Request) {
  const auth = authConfig();
  if (!auth) return reply({ error: 'Authentication is not configured on this deployment.' }, 503);
  const token = bearer(request);
  if (!token) return reply({ error: 'Sign in is required to run the shared investigation.' }, 401);
  if (!(await authenticate(token, auth))) return reply({ error: 'Your session is invalid or expired. Sign in again.' }, 401);

  const config = backendConfig();
  if (!config) return reply({ error: 'The shared FIRSTLIGHT API is not configured. Local deterministic findings remain available.' }, 503);

  const declared = request.headers.get('content-length');
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size < 0) return reply({ error: 'A valid JSON request is required.' }, 400);
    if (size > MAX_BODY_BYTES) return reply({ error: 'Investigation request is too large.' }, 413);
  }

  // Count bytes while streaming so chunked requests cannot force an unbounded
  // allocation before the limit is enforced.
  let raw = '';
  let input: unknown;
  const reader = request.body?.getReader();
  if (!reader) return reply({ error: 'A valid JSON request is required.' }, 400);
  const decoder = new TextDecoder();
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        // Cancellation is best-effort; it must not turn a known oversize body
        // into a misleading 400 if the underlying stream rejects cancellation.
        void reader.cancel().catch(() => undefined);
        return reply({ error: 'Investigation request is too large.' }, 413);
      }
      raw += decoder.decode(value, { stream: true });
    }
    raw += decoder.decode();
    input = JSON.parse(raw);
  } catch {
    return reply({ error: 'A valid JSON request is required.' }, 400);
  } finally {
    reader.releaseLock();
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) return reply({ error: 'A JSON object is required.' }, 400);

  try {
    const response = await fetch(config.baseUrl + '/api/v1/cases/investigate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(config.token ? { Authorization: 'Bearer ' + config.token } : {}),
      },
      body: raw,
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(12_000),
    });
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > MAX_BODY_BYTES) return reply({ error: 'Investigation service returned an oversized response.' }, 502);
    let payload: unknown;
    try { payload = JSON.parse(text); } catch { return reply({ error: 'Investigation service returned an invalid response.' }, 502); }
    if (!response.ok) {
      const message = payload && typeof payload === 'object' && 'detail' in payload && typeof payload.detail === 'string'
        ? payload.detail
        : 'The shared investigation service could not process this case.';
      return reply({ error: message }, response.status >= 400 && response.status < 500 ? response.status : 503);
    }
    return reply(payload);
  } catch {
    return reply({ error: 'The shared FIRSTLIGHT API is unreachable. Local deterministic findings remain available.' }, 503);
  }
}
