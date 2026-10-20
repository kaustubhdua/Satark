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

async function readBoundedJson(request: Request): Promise<{ ok: true; body: unknown } | { ok: false; status: 400 | 413 }> {
  const contentLength = request.headers.get('content-length');
  if (contentLength !== null) {
    const size = Number(contentLength);
    if (!Number.isSafeInteger(size) || size < 0) return { ok: false, status: 400 };
    if (size > MAX_BODY_BYTES) return { ok: false, status: 413 };
  }
  if (!request.body) return { ok: false, status: 400 };
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let raw = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        // Cancellation is best-effort; preserve the known 413 even if the stream rejects cancellation.
        void reader.cancel().catch(() => undefined);
        return { ok: false, status: 413 };
      }
      raw += decoder.decode(value, { stream: true });
    }
    raw += decoder.decode();
    return { ok: true, body: JSON.parse(raw) as unknown };
  } catch {
    return { ok: false, status: 400 };
  } finally {
    reader.releaseLock();
  }
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
      redirect: 'error',
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
    redirect: 'error',
    signal: init.signal ?? AbortSignal.timeout(8_000),
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
      select: 'id,tenant_id,title,status,severity,assigned_to,created_by,created_at,updated_at,metadata',
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

  const parsed = await readBoundedJson(request);
  if (!parsed.ok) return jsonError(parsed.status === 413 ? 'Request body is too large.' : 'A valid JSON body is required.', parsed.status);
  const body = parsed.body;
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


export async function PATCH(request: Request) {
  const config = configuration();
  if (!config) return jsonError('Case storage is not configured.', 503);
  const token = bearer(request);
  if (!token) return jsonError('Sign in is required.', 401);
  const user = await authenticate(token, config);
  if (!user) return jsonError('Your session is invalid or expired.', 401);

  const parsed = await readBoundedJson(request);
  if (!parsed.ok) return jsonError(parsed.status === 413 ? 'Request body is too large.' : 'A valid JSON body is required.', parsed.status);
  const body = parsed.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return jsonError('A JSON object is required.', 400);
  const input = body as Record<string, unknown>;
  const id = input.id, tenantId = input.tenant_id;
  if (typeof id !== 'string' || !UUID.test(id) || typeof tenantId !== 'string' || !UUID.test(tenantId)) {
    return jsonError('Valid id and tenant_id are required.', 400);
  }
  const updates: Record<string, unknown> = {};
  if (input.title !== undefined) {
    if (typeof input.title !== 'string' || !input.title.trim() || input.title.trim().length > 240) return jsonError('title must contain 1–240 characters.', 400);
    updates.title = input.title.trim();
  }
  if (input.status !== undefined) {
    if (typeof input.status !== 'string' || !STATUSES.has(input.status)) return jsonError('Invalid case status.', 400);
    updates.status = input.status;
  }
  if (input.severity !== undefined) {
    if (typeof input.severity !== 'string' || !SEVERITIES.has(input.severity)) return jsonError('Invalid case severity.', 400);
    updates.severity = input.severity;
  }
  if (input.metadata !== undefined) {
    if (!input.metadata || typeof input.metadata !== 'object' || Array.isArray(input.metadata) ||
        Buffer.byteLength(JSON.stringify(input.metadata), 'utf8') > 8192) {
      return jsonError('metadata must be a JSON object no larger than 8 KiB.', 400);
    }
    updates.metadata = input.metadata;
  }
  if (input.assigned_to !== undefined) {
    if (input.assigned_to !== null && (typeof input.assigned_to !== 'string' || !UUID.test(input.assigned_to))) {
      return jsonError('assigned_to must be a valid user UUID or null.', 400);
    }
    const currentRoleQuery = new URLSearchParams({
      select: 'role', tenant_id: 'eq.' + tenantId, user_id: 'eq.' + user.id,
      role: 'in.(owner,responder)', limit: '1',
    });
    const currentRoleResponse = await supabaseRequest(config, token, 'satark_memberships?' + currentRoleQuery.toString());
    if (!currentRoleResponse.ok) return jsonError('Assignment permissions could not be verified.', 503);
    const currentRoles: unknown = await currentRoleResponse.json();
    if (!Array.isArray(currentRoles) || currentRoles.length === 0) return jsonError('Only workspace owners or responders can assign cases.', 403);
    if (typeof input.assigned_to === 'string') {
      const targetResponse = await supabaseRequest(config, token, 'rpc/satark_list_assignable_members', {
        method: 'POST', body: JSON.stringify({ p_tenant_id: tenantId }),
      });
      if (targetResponse.status === 401 || targetResponse.status === 403) return jsonError('Only owners or responders may assign cases.', 403);
      if (!targetResponse.ok) return jsonError('Assignee membership could not be verified.', 503);
      const targetRows: unknown = await targetResponse.json();
      if (!Array.isArray(targetRows) || !targetRows.some(row => !!row && typeof row === 'object' && 'user_id' in row && row.user_id === input.assigned_to)) {
        return jsonError('Assignee must be an owner, responder, or analyst in this workspace.', 400);
      }
    }
    updates.assigned_to = input.assigned_to;
  }
  if (!Object.keys(updates).length) return jsonError('At least one case field must be provided for update.', 400);

  try {
    const query = new URLSearchParams({ id: 'eq.' + id, tenant_id: 'eq.' + tenantId, select: 'id,tenant_id,title,status,severity,assigned_to,created_by,created_at,updated_at,metadata' });
    const response = await supabaseRequest(config, token, 'satark_cases?' + query.toString(), {
      method: 'PATCH', headers: { Prefer: 'return=representation' }, body: JSON.stringify(updates),
    });
    if (response.status === 401 || response.status === 403) return jsonError('You do not have permission to update this case.', 403);
    if (!response.ok) return jsonError('Case could not be updated. Verify workspace membership and role.', 422);
    const rows: unknown = await response.json();
    if (!Array.isArray(rows) || !rows[0]) return jsonError('Case was not found or you do not have permission to update it.', 404);
    return NextResponse.json({ case: rows[0] }, { headers: { 'Cache-Control': 'no-store' } });
  } catch { return jsonError('Case storage is temporarily unavailable.', 503); }
}
