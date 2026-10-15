import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TYPES = new Set(['application/pdf', 'image/png', 'image/jpeg', 'image/webp', 'text/plain', 'text/csv', 'application/zip', 'application/octet-stream']);

function error(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
}
function config() {
  const raw = process.env.SUPABASE_URL, key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return null;
  try { const url = new URL(raw); if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null; return { url: url.origin, key }; }
  catch { return null; }
}
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const cfg = config();
  if (!cfg) return error('Evidence storage is not configured.', 503);
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return error('Sign in is required.', 401);
  const { id } = await context.params;
  if (!UUID.test(id)) return error('A valid evidence ID is required.', 400);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const auth = await fetch(cfg.url + '/auth/v1/user', {
      headers: { apikey: cfg.key, Authorization: 'Bearer ' + match[1] },
      cache: 'no-store', redirect: 'error', signal: controller.signal,
    });
    const user: unknown = auth.ok ? await auth.json() : null;
    if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string' || !UUID.test(user.id)) {
      return error('Your session is invalid or expired.', 401);
    }
  } catch { return error('Authentication service is temporarily unavailable.', 503); }
  finally { clearTimeout(timer); }

  const query = new URLSearchParams({
    select: 'id,tenant_id,case_id,source_label,metadata',
    id: 'eq.' + id,
    limit: '1',
  });
  try {
    const lookup = await fetch(cfg.url + '/rest/v1/satark_evidence?' + query.toString(), {
      headers: { apikey: cfg.key, Authorization: 'Bearer ' + match[1], Accept: 'application/json' },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(8000),
    });
    if (lookup.status === 401 || lookup.status === 403) return error('You do not have permission to access this evidence.', 403);
    if (!lookup.ok) return error('Evidence metadata could not be retrieved.', 422);
    const rows: unknown = await lookup.json();
    if (!Array.isArray(rows) || !rows[0] || typeof rows[0] !== 'object') return error('Evidence was not found or is not accessible to your workspace.', 404);
    const row = rows[0] as Record<string, unknown>;
    if (row.id !== id || typeof row.tenant_id !== 'string' || !UUID.test(row.tenant_id) ||
        typeof row.case_id !== 'string' || !UUID.test(row.case_id)) return error('Evidence metadata is invalid.', 502);
    const metadata = row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata) ? row.metadata as Record<string, unknown> : {};
    const objectKey = metadata.object_key;
    const contentType = metadata.content_type;
    const originalName = metadata.original_filename;
    if (typeof objectKey !== 'string' || typeof contentType !== 'string' || !TYPES.has(contentType) ||
        typeof originalName !== 'string' || !/^[A-Za-z0-9._-]{1,100}$/.test(originalName) || originalName.includes('..')) {
      return error('This evidence record does not reference a supported private file.', 404);
    }
    const parts = objectKey.split('/');
    if (parts.length !== 3 || parts[0] !== row.tenant_id || parts[1] !== row.case_id ||
        parts[2] !== id + '_' + originalName) return error('Evidence storage reference failed integrity validation.', 409);

    const objectUrl = cfg.url + '/storage/v1/object/authenticated/satark-evidence/' + parts.map(encodeURIComponent).join('/');
    const download = await fetch(objectUrl, {
      headers: { apikey: cfg.key, Authorization: 'Bearer ' + match[1] },
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    if (download.status === 401 || download.status === 403 || download.status === 404) return error('Private evidence is unavailable or you do not have access.', 404);
    if (!download.ok) return error('Private evidence storage is temporarily unavailable.', 503);
    const bytes = await download.arrayBuffer();
    if (bytes.byteLength < 1 || bytes.byteLength > 4 * 1024 * 1024) return error('Stored evidence failed the expected size check.', 502);
    const safeName = originalName.replace(/[^A-Za-z0-9._-]/g, '_');
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': 'attachment; filename="' + safeName + '"',
        'Content-Length': String(bytes.byteLength),
        'Cache-Control': 'private, no-store, max-age=0',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox",
      },
    });
  } catch { return error('Evidence storage is temporarily unavailable.', 503); }
}
