import { NextResponse } from 'next/server';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function reply(body: unknown, status = 200) { return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } }); }
export async function GET(request: Request) {
  const raw = process.env.SUPABASE_URL, key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return reply({ error: 'Audit verification is not configured.' }, 503);
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return reply({ error: 'Sign in is required.' }, 401);
  const tenantId = new URL(request.url).searchParams.get('tenant_id');
  if (!tenantId || !UUID.test(tenantId)) return reply({ error: 'A valid tenant_id is required.' }, 400);
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return reply({ error: 'Audit verification is not configured.' }, 503);
    const response = await fetch(url.origin + '/rest/v1/rpc/satark_verify_audit_chain', {
      method: 'POST',
      headers: { apikey: key, Authorization: 'Bearer ' + match[1], 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ target_tenant: tenantId }), cache: 'no-store',
    });
    if (response.status === 401 || response.status === 403) return reply({ error: 'Workspace access denied.' }, 403);
    if (!response.ok) return reply({ error: 'Audit chain could not be verified. Check database migration status and workspace permissions.' }, 503);
    const data = await response.json();
    const result = Array.isArray(data) ? data[0] : data;
    if (!result || typeof result.chain_valid !== 'boolean') return reply({ error: 'Audit verifier returned an invalid response.' }, 502);
    return reply({ tenant_id: tenantId, ...result, verified_at: new Date().toISOString() }, result.chain_valid ? 200 : 409);
  } catch { return reply({ error: 'Audit verification is temporarily unavailable.' }, 503); }
}
