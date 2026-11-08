import { NextResponse } from 'next/server';

const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

function upstreamBase(): URL | null {
  const raw = process.env.SATARK_API_INTERNAL_URL;
  if (!raw) return null;
  try {
    const url = new URL(raw);
    const local = new Set(['localhost', '127.0.0.1', '::1', 'firstlight-api']);
    if (url.username || url.password || url.search || url.hash ||
        (url.protocol !== 'https:' && !(url.protocol === 'http:' && local.has(url.hostname)))) return null;
    return url;
  } catch { return null; }
}

/** Same-origin, bounded proxy to the private SATARK FastAPI service. */
export async function proxySatarkApi(request: Request): Promise<Response> {
  const base = upstreamBase();
  if (!base) return NextResponse.json({ error: 'The self-hosted SATARK API is not configured.' }, { status: 503 });
  const incoming = new URL(request.url);
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(request.method.toUpperCase());
  const origin = request.headers.get('origin');
  const bearer = request.headers.get('authorization')?.startsWith('Bearer ');
  let sameOrigin = false;
  try { sameOrigin = Boolean(origin && new URL(origin).origin === incoming.origin); } catch { sameOrigin = false; }
  if (unsafe && !sameOrigin && !bearer) {
    return NextResponse.json({ error: 'Cross-origin API requests are not allowed.' }, { status: 403 });
  }

  let body: ArrayBuffer | undefined;
  if (unsafe) {
    const declared = Number(request.headers.get('content-length') || 0);
    if (declared > MAX_REQUEST_BYTES) return NextResponse.json({ error: 'Request body is too large.' }, { status: 413 });
    try { body = await request.arrayBuffer(); }
    catch { return NextResponse.json({ error: 'The request body could not be read.' }, { status: 400 }); }
    if (body.byteLength > MAX_REQUEST_BYTES) return NextResponse.json({ error: 'Request body is too large.' }, { status: 413 });
  }

  const target = new URL(incoming.pathname + incoming.search, base);
  const headers = new Headers();
  for (const name of ['accept', 'content-type', 'cookie', 'authorization']) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  if (unsafe) headers.set('origin', base.origin);
  headers.set('x-forwarded-proto', incoming.protocol.slice(0, -1));
  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers,
      body,
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(15000),
    });
    const declared = Number(upstream.headers.get('content-length') || 0);
    if (declared > MAX_RESPONSE_BYTES) return NextResponse.json({ error: 'The SATARK API response exceeded its limit.' }, { status: 502 });
    const bytes = await upstream.arrayBuffer();
    if (bytes.byteLength > MAX_RESPONSE_BYTES) return NextResponse.json({ error: 'The SATARK API response exceeded its limit.' }, { status: 502 });
    const responseHeaders = new Headers();
    for (const name of ['content-type', 'content-disposition', 'cache-control', 'x-content-type-options']) {
      const value = upstream.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    responseHeaders.set('Cache-Control', 'no-store');
    const setCookies = typeof upstream.headers.getSetCookie === 'function' ? upstream.headers.getSetCookie() : [];
    for (const cookie of setCookies) responseHeaders.append('Set-Cookie', cookie);
    return new Response(bytes, { status: upstream.status, headers: responseHeaders });
  } catch {
    return NextResponse.json({ error: 'The self-hosted SATARK API is unavailable.' }, { status: 503 });
  }
}
