import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_TOKEN = 8192;
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]+$/;

function response(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' } });
}


function sameOrigin(request: Request) {
  // This endpoint is a browser session boundary. Do not allow a cross-site page to
  // mint or clear authentication cookies. Reject absent/malformed Origin as well.
  const origin = request.headers.get('origin');
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function configured() {
  const raw = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null;
    return { url: url.origin, key };
  } catch { return null; }
}

async function verify(accessToken: string) {
  const config = configured();
  if (!config) return false;
  try {
    const result = await fetch(config.url + '/auth/v1/user', {
      headers: { apikey: config.key, Authorization: 'Bearer ' + accessToken },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(4000),
    });
    if (!result.ok) return false;
    const user: unknown = await result.json();
    return !!user && typeof user === 'object' && 'id' in user && typeof user.id === 'string';
  } catch { return false; }
}

export async function POST(request: Request) {
  if (!sameOrigin(request)) return response({ error: 'Cross-origin session requests are not allowed.' }, 403);
  const config = configured();
  if (!config) return response({ error: 'Authentication is not configured.' }, 503);
  let input: unknown;
  try { input = await request.json(); } catch { return response({ error: 'A valid JSON object is required.' }, 400); }
  if (!input || typeof input !== 'object') return response({ error: 'A valid session is required.' }, 400);
  const data = input as Record<string, unknown>;
  const access = data.access_token;
  const refresh = data.refresh_token;
  const expiresAt = data.expires_at;
  if (typeof access !== 'string' || access.length < 20 || access.length > MAX_TOKEN || !TOKEN_PATTERN.test(access) ||
      typeof refresh !== 'string' || refresh.length < 20 || refresh.length > MAX_TOKEN || !TOKEN_PATTERN.test(refresh) ||
      typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 86400_000) {
    return response({ error: 'The session payload is invalid or expired.' }, 400);
  }
  if (!(await verify(access))) return response({ error: 'The session is invalid or expired.' }, 401);
  const result = response({ ok: true });
  const secure = new URL(request.url).protocol === 'https:';
  result.cookies.set('satark-access', access, { httpOnly: true, secure, sameSite: 'lax', path: '/', expires: new Date(expiresAt), priority: 'high' });
  result.cookies.set('satark-refresh', refresh, { httpOnly: true, secure, sameSite: 'lax', path: '/api/auth', maxAge: 86400 * 30, priority: 'high' });
  return result;
}

export async function DELETE(request: Request) {
  if (!sameOrigin(request)) return response({ error: 'Cross-origin session requests are not allowed.' }, 403);
  const result = response({ ok: true });
  const secure = new URL(request.url).protocol === 'https:';
  result.cookies.set('satark-access', '', { httpOnly: true, secure, sameSite: 'lax', path: '/', maxAge: 0 });
  result.cookies.set('satark-refresh', '', { httpOnly: true, secure, sameSite: 'lax', path: '/api/auth', maxAge: 0 });
  return result;
}
