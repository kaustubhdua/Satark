import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function reply(body: unknown, status = 200) {
  return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
}
function configuration() {
  const rawUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!rawUrl || !publishableKey) return null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null;
    return { url: url.origin, publishableKey };
  } catch { return null; }
}
async function authenticate(token: string, config: NonNullable<ReturnType<typeof configuration>>) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(config.url + '/auth/v1/user', {
      headers: { apikey: config.publishableKey, Authorization: 'Bearer ' + token },
      cache: 'no-store', signal: controller.signal,
    });
    if (!response.ok) return null;
    const user: unknown = await response.json();
    if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string' || !UUID.test(user.id)) return null;
    return user.id;
  } catch { return null; }
  finally { clearTimeout(timer); }
}

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const config = configuration();
  if (!config) return reply({ error: 'Evidence storage is not configured.' }, 503);
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return reply({ error: 'Sign in is required.' }, 401);
  const userId = await authenticate(match[1], config);
  if (!userId) return reply({ error: 'Your session is invalid or expired.' }, 401);
  const { id } = await context.params;
  if (!UUID.test(id)) return reply({ error: 'A valid evidence id is required.' }, 400);

  const headers = { apikey: config.publishableKey, Authorization: 'Bearer ' + match[1], Accept: 'application/json' };
  try {
    const query = new URLSearchParams({
      select: 'id,tenant_id,case_id,source_sha256,record_sha256,created_by,metadata',
      id: 'eq.' + id, limit: '1',
    });
    const lookup = await fetch(config.url + '/rest/v1/satark_evidence?' + query, { headers, cache: 'no-store' });
    if (lookup.status === 401 || lookup.status === 403) return reply({ error: 'You do not have access to this evidence.' }, 403);
    if (!lookup.ok) return reply({ error: 'Evidence metadata is temporarily unavailable.' }, 503);
    const rows: unknown = await lookup.json();
    if (!Array.isArray(rows) || !rows[0]) return reply({ error: 'Evidence was not found.' }, 404);
    const row = rows[0] as { id:string; tenant_id:string; case_id:string; source_sha256:string|null; record_sha256:string; created_by:string; metadata:Record<string,unknown> };
    const objectKey = row.metadata?.object_key;
    if (typeof objectKey !== 'string' || !objectKey.startsWith(row.tenant_id + '/' + row.case_id + '/')) {
      return reply({ error: 'Evidence storage reference failed validation.' }, 409);
    }
    const download = await fetch(config.url + '/storage/v1/object/satark-evidence/' + objectKey.split('/').map(encodeURIComponent).join('/'), {
      headers: { apikey: config.publishableKey, Authorization: 'Bearer ' + match[1] },
      cache: 'no-store',
    });
    if (download.status === 401 || download.status === 403) return reply({ error: 'You do not have permission to verify this evidence.' }, 403);
    if (!download.ok) return reply({ error: 'The private evidence object could not be retrieved for verification.' }, 503);
    const bytes = Buffer.from(await download.arrayBuffer());
    if (bytes.byteLength > 10 * 1024 * 1024) return reply({ error: 'Stored evidence exceeds the supported verification limit.' }, 413);
    const actual = createHash('sha256').update(bytes).digest('hex');
    const matched = typeof row.source_sha256 === 'string' && actual === row.source_sha256;
    return reply({
      evidence_id: row.id,
      algorithm: 'SHA-256',
      expected_sha256: row.source_sha256,
      actual_sha256: actual,
      matched,
      verified_at: new Date().toISOString(),
      note: matched
        ? 'Retrieved bytes match the digest recorded at upload. This does not independently prove the original source or acquisition process was trustworthy.'
        : 'The retrieved bytes do not match the recorded upload digest. Treat this as an integrity failure and preserve the result for review.',
    }, matched ? 200 : 409);
  } catch {
    return reply({ error: 'Evidence verification is temporarily unavailable.' }, 503);
  }
}
