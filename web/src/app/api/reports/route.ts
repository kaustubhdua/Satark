import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
import { readBoundedJson } from '@/lib/read-bounded-json';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function reply(body: unknown, status = 200) { return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } }); }
function hasBearer(request: Request) {
  return /^Bearer [A-Za-z0-9._~-]+$/.test(request.headers.get('authorization') || '');
}
function config() {
  const raw = process.env.SUPABASE_URL, key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return null;
  try { const url = new URL(raw); if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null; return { url: url.origin, key }; }
  catch { return null; }
}
async function auth(request: Request, cfg: {url:string;key:string}) {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return { token: null, userId: null, error: reply({ error: 'Sign in is required.' }, 401) };
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(cfg.url + '/auth/v1/user', { headers: { apikey: cfg.key, Authorization: 'Bearer ' + match[1] }, cache: 'no-store', redirect: 'error', signal: controller.signal });
    const user: unknown = response.ok ? await response.json() : null;
    if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string' || !UUID.test(user.id)) return { token: null, userId: null, error: reply({ error: 'Your session is invalid or expired.' }, 401) };
    return { token: match[1], userId: user.id, error: null };
  } catch { return { token: null, userId: null, error: reply({ error: 'Authentication service is temporarily unavailable.' }, 503) }; }
  finally { clearTimeout(timer); }
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return '{' + Object.keys(obj).sort().map(key => JSON.stringify(key) + ':' + canonical(obj[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export async function GET(request: Request) {
  if (!hasBearer(request)) return reply({ error: 'Sign in is required.' }, 401);
  const cfg = config(); if (!cfg) return reply({ error: 'Report storage is not configured.' }, 503);
  const a = await auth(request, cfg); if (a.error || !a.token) return a.error ?? reply({ error: 'Sign in is required.' }, 401);
  const params = new URL(request.url).searchParams, tenantId = params.get('tenant_id'), caseId = params.get('case_id');
  if (!tenantId || !UUID.test(tenantId) || !caseId || !UUID.test(caseId)) return reply({ error: 'Valid tenant_id and case_id are required.' }, 400);
  try {
    const query = new URLSearchParams({ select:'id,tenant_id,case_id,title,report_version,snapshot_sha256,created_by,created_at',tenant_id:'eq.'+tenantId,case_id:'eq.'+caseId,order:'created_at.desc',limit:'100' });
    const response = await fetch(cfg.url+'/rest/v1/satark_reports?'+query,{headers:{apikey:cfg.key,Authorization:'Bearer '+a.token},cache:'no-store',redirect:'error',signal:AbortSignal.timeout(8_000)});
    if (response.status===401||response.status===403) return reply({error:'Workspace access denied.'},403);
    if (!response.ok) return reply({error:'Report storage is temporarily unavailable.'},503);
    return reply({reports:await response.json()});
  } catch { return reply({error:'Report storage is temporarily unavailable.'},503); }
}
export async function POST(request: Request) {
  if (!hasBearer(request)) return reply({ error: 'Sign in is required.' }, 401);
  const cfg = config(); if (!cfg) return reply({error:'Report storage is not configured.'},503);
  const a = await auth(request,cfg); if (a.error||!a.token||!a.userId) return a.error ?? reply({error:'Sign in is required.'},401);
  const parsed = await readBoundedJson(request, 1100 * 1024);
  if (!parsed.ok) return reply({ error: parsed.error }, parsed.status);
  const body = parsed.value;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return reply({ error: 'A bounded JSON object is required.' }, 400);
  const v=body as Record<string,unknown>,tenantId=v.tenant_id,caseId=v.case_id,title=typeof v.title==='string'?v.title.trim():'';
  const snapshot=v.snapshot;
  if(typeof tenantId!=='string'||!UUID.test(tenantId)||typeof caseId!=='string'||!UUID.test(caseId)||!title||title.length>240||!snapshot||typeof snapshot!=='object'||Array.isArray(snapshot)) return reply({error:'Report fields are invalid.'},400);
  const snapshotText=canonical(snapshot);
  const snapshotSha=createHash('sha256').update(snapshotText).digest('hex');
  try{
    const response=await fetch(cfg.url+'/rest/v1/satark_reports',{
      method:'POST',headers:{apikey:cfg.key,Authorization:'Bearer '+a.token,'Content-Type':'application/json',Accept:'application/json',Prefer:'return=representation'},
      body:JSON.stringify({tenant_id:tenantId,case_id:caseId,title,report_version:1,snapshot,snapshot_sha256:snapshotSha,created_by:a.userId}),cache:'no-store',redirect:'error',signal:AbortSignal.timeout(8_000)
    });
    if(response.status===401||response.status===403)return reply({error:'You do not have permission to save this report.'},403);
    if(!response.ok)return reply({error:'Report could not be saved. Verify case access and retry.'},422);
    const rows:unknown=await response.json();if(!Array.isArray(rows)||!rows[0])return reply({error:'Report storage returned an invalid response.'},502);
    return reply({report:rows[0],snapshot_sha256:snapshotSha},201);
  }catch{return reply({error:'Report storage is temporarily unavailable.'},503);}
}
