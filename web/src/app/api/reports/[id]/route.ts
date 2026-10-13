import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function reply(body: unknown, status = 200) { return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } }); }
function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort().map(key => JSON.stringify(key) + ':' + canonical(obj[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const raw = process.env.SUPABASE_URL, key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return reply({ error: 'Report storage is not configured.' }, 503);
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return reply({ error: 'Sign in is required.' }, 401);
  const { id } = await context.params;
  if (!UUID.test(id)) return reply({ error: 'A valid report id is required.' }, 400);
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return reply({ error: 'Report storage is not configured.' }, 503);
    const query = new URLSearchParams({ select:'id,tenant_id,case_id,title,report_version,snapshot,snapshot_sha256,created_by,created_at',id:'eq.'+id,limit:'1' });
    const response = await fetch(url.origin+'/rest/v1/satark_reports?'+query,{
      headers:{apikey:key,Authorization:'Bearer '+match[1],Accept:'application/json'},cache:'no-store'
    });
    if(response.status===401||response.status===403)return reply({error:'Workspace access denied.'},403);
    if(!response.ok)return reply({error:'Report storage is temporarily unavailable.'},503);
    const rows:unknown=await response.json();
    if(!Array.isArray(rows)||!rows[0])return reply({error:'Report was not found.'},404);
    const report=rows[0] as {snapshot:unknown;snapshot_sha256:string};
    const actual=createHash('sha256').update(canonical(report.snapshot)).digest('hex');
    const integrityMatches=actual===report.snapshot_sha256;
    return reply({report,integrity:{algorithm:'SHA-256',expected_sha256:report.snapshot_sha256,actual_sha256:actual,matched:integrityMatches}},integrityMatches?200:409);
  }catch{return reply({error:'Report retrieval is temporarily unavailable.'},503);}
}
