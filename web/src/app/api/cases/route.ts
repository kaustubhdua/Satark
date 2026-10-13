import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_BODY_BYTES = 16 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const STATUSES = new Set(['open', 'contained', 'resolved', 'archived']);
const SEVERITIES = new Set(['unknown', 'low', 'medium', 'high', 'critical']);

type AuthenticatedUser = { id: string };

function jsonError(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: { 'Cache-Control': 'no-store' } });
}

function configuration() {
  const rawUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!rawUrl || !publishableKey) return null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null;
    return { url: url.origin, publishableKey };
  } catch {
    return null;
  }
}

function bearer(request: Request): string | null {
  const value = request.headers.get('authorization') || '';
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(value);
  return match?.[1] ?? null;
}

async function authenticate(token: string, config: NonNullable<ReturnType<typeof configuration>>): Promise<AuthenticatedUser | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(config.url + '/auth/v1/user', {
      headers: { apikey: config.publishableKey, Authorization: 'Bearer ' + token, Accept: 'application/json' },
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const user: unknown = await response.json();
    if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string' || !UUID.test(user.id)) return null;
    return { id: user.id };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function supabaseRequest(
  config: NonNullable<ReturnType<typeof configuration>>,
  token: string,
  path: string,
  init: RequestInit = {},
) {
  return fetch(config.url + '/rest/v1/' + path, {
    ...init,
    headers: {
      apikey: config.publishableKey,
      Authorization: 'Bearer ' + token,
      Accept: 'application/json',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
    cache: 'no-store',
  });
}

export async function GET(request: Request) {
  const config = configuration();
  if (!config) return jsonError('Case storage is not configured.', 503);
  const token = bearer(request);
  if (!token) return jsonError('Sign in is required.', 401);
  const user = await authenticate(token, config);
  if (!user) return jsonError('Your session is invalid or expired.', 401);

  const tenantId = new URL(request.url).searchParams.get('tenant_id');
  if (!tenantId || !UUID.test(tenantId)) return jsonError('A valid tenant_id is required.', 400);

  try {
    const query = new URLSearchParams({
      select: 'id,tenant_id,title,status,severity,created_by,created_at,updated_at,metadata',
      tenant_id: 'eq.' + tenantId,
      order: 'updated_at.desc',
      limit: '100',
    });
    const response = await supabaseRequest(config, token, 'satark_cases?' + query.toString());
    if (response.status === 401 || response.status === 403) return jsonError('You do not have access to these cases.', 403);
    if (!response.ok) return jsonError('Case storage is temporarily unavailable.', 503);
    const data: unknown = await response.json();
    if (!Array.isArray(data)) return jsonError('Case storage returned an invalid response.', 502);
    return NextResponse.json({ cases: data }, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return jsonError('Case storage is temporarily unavailable.', 503);
  }
}

export async function POST(request: Request) {
  const config = configuration();
  if (!config) return jsonError('Case storage is not configured.', 503);
  const token = bearer(request);
  if (!token) return jsonError('Sign in is required.', 401);
  const user = await authenticate(token, config);
  if (!user) return jsonError('Your session is invalid or expired.', 401);

  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > MAX_BODY_BYTES) return jsonError('Request body is too large.', 413);
  let body: unknown;
  try {
    const raw = await request.text();
    if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) return jsonError('Request body is too large.', 413);
    body = JSON.parse(raw);
  } catch {
    return jsonError('A valid JSON body is required.', 400);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return jsonError('A JSON object is required.', 400);

  const input = body as Record<string, unknown>;
  const tenantId = input.tenant_id;
  const title = typeof input.title === 'string' ? input.title.trim() : '';
  const status = input.status === undefined ? 'open' : input.status;
  const severity = input.severity === undefined ? 'unknown' : input.severity;
  const metadata = input.metadata === undefined ? {} : input.metadata;

  if (typeof tenantId !== 'string' || !UUID.test(tenantId)) return jsonError('A valid tenant_id is required.', 400);
  if (!title || title.length > 240) return jsonError('title must contain 1–240 characters.', 400);
  if (typeof status !== 'string' || !STATUSES.has(status)) return jsonError('Invalid case status.', 400);
  if (typeof severity !== 'string' || !SEVERITIES.has(severity)) return jsonError('Invalid case severity.', 400);
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata) || Buffer.byteLength(JSON.stringify(metadata), 'utf8') > 8192) {
    return jsonError('metadata must be a JSON object no larger than 8 KiB.', 400);
  }

  try {
    const response = await supabaseRequest(config, token, 'satark_cases', {
      method: 'POST',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({ tenant_id: tenantId, title, status, severity, metadata, created_by: user.id }),
    });
    if (response.status === 401 || response.status === 403) return jsonError('You do not have permission to create cases in this tenant.', 403);
    if (!response.ok) return jsonError('Case could not be saved. Verify tenant membership and try again.', 422);
    const rows: unknown = await response.json();
    if (!Array.isArray(rows) || !rows[0]) return jsonError('Case storage returned an invalid response.', 502);
    return NextResponse.json({ case: rows[0] }, { status: 201, headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return jsonError('Case storage is temporarily unavailable.', 503);
  }
}
