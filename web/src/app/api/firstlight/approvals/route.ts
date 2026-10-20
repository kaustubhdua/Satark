import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
import { readBoundedJson } from '@/lib/read-bounded-json';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ACTION = /^simulation\.[a-z0-9][a-z0-9._-]{0,110}$/;
function reply(body: unknown, status = 200) { return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } }); }
function config() {
  const raw = process.env.SUPABASE_URL, key = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!raw || !key) return null;
  try { const url = new URL(raw); if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null; return { url: url.origin, key }; }
  catch { return null; }
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return '{' + Object.keys(object).sort().map(key => JSON.stringify(key) + ':' + canonical(object[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}
async function auth(request: Request, cfg: {url:string;key:string}) {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  if (!match) return { token: null, userId: null, error: reply({error:'Sign in is required.'},401) };
  try {
    const response = await fetch(cfg.url+'/auth/v1/user',{headers:{apikey:cfg.key,Authorization:'Bearer '+match[1],Accept:'application/json'},cache:'no-store',redirect:'error',signal:AbortSignal.timeout(4000)});
    const user: unknown = response.ok ? await response.json() : null;
    if (!user||typeof user!=='object'||!('id' in user)||typeof user.id!=='string'||!UUID.test(user.id)) return {token:null,userId:null,error:reply({error:'Your session is invalid or expired.'},401)};
    return {token:match[1],userId:user.id,error:null};
  } catch { return {token:null,userId:null,error:reply({error:'Authentication is temporarily unavailable.'},503)}; }
}
export async function GET(request: Request) {
  const cfg=config(); if(!cfg)return reply({error:'Approval storage is not configured.'},503);
  const a=await auth(request,cfg); if(a.error||!a.token)return a.error??reply({error:'Sign in is required.'},401);
  const p=new URL(request.url).searchParams,tenantId=p.get('tenant_id')||'',caseId=p.get('case_id')||'';
  if(!UUID.test(tenantId)||!UUID.test(caseId))return reply({error:'Valid tenant_id and case_id are required.'},400);
  try{
    const q=new URLSearchParams({select:'id,tenant_id,case_id,action_key,action_payload,payload_sha256,status,requested_by,decided_by,decision_reason,decided_at,expires_at,consumed_at,created_at',tenant_id:'eq.'+tenantId,case_id:'eq.'+caseId,order:'created_at.desc',limit:'100'});
    const response=await fetch(cfg.url+'/rest/v1/satark_approvals?'+q,{headers:{apikey:cfg.key,Authorization:'Bearer '+a.token},cache:'no-store',redirect:'error',signal:AbortSignal.timeout(8000)});
    if(response.status===401||response.status===403)return reply({error:'Workspace access denied.'},403);
    if(!response.ok)return reply({error:'Approval records are temporarily unavailable.'},503);
    const rows:unknown=await response.json();if(!Array.isArray(rows))return reply({error:'Approval storage returned an invalid response.'},502);
    return reply({approvals:rows});
  }catch{return reply({error:'Approval records are temporarily unavailable.'},503);}
}
export async function POST(request: Request) {
  const cfg=config();if(!cfg)return reply({error:'Approval storage is not configured.'},503);
  const a=await auth(request,cfg);if(a.error||!a.token||!a.userId)return a.error??reply({error:'Sign in is required.'},401);
  const parsed=await readBoundedJson(request,20*1024);if(!parsed.ok)return reply({error:parsed.error},parsed.status);
  if(!parsed.value||typeof parsed.value!=='object'||Array.isArray(parsed.value))return reply({error:'A JSON object is required.'},400);
  const v=parsed.value as Record<string,unknown>,tenantId=typeof v.tenant_id==='string'?v.tenant_id:'',caseId=typeof v.case_id==='string'?v.case_id:'',actionKey=typeof v.action_key==='string'?v.action_key.trim():'',payload=v.action_payload;
  if(!UUID.test(tenantId)||!UUID.test(caseId)||!ACTION.test(actionKey))return reply({error:'Valid tenant_id, case_id and action_key are required.'},400);
  if(!payload||typeof payload!=='object'||Array.isArray(payload)||(payload as Record<string,unknown>).mode!=='simulation')return reply({error:'Response approvals are simulation-only; action_payload.mode must be simulation.'},400);
  const payloadText=canonical(payload);
  if(Buffer.byteLength(payloadText,'utf8')>16*1024)return reply({error:'Action payload exceeds 16 KiB.'},413);
  const digest=createHash('sha256').update(payloadText).digest('hex');
  try{
    const response=await fetch(cfg.url+'/rest/v1/satark_approvals',{method:'POST',headers:{apikey:cfg.key,Authorization:'Bearer '+a.token,'Content-Type':'application/json',Accept:'application/json',Prefer:'return=representation'},body:JSON.stringify({tenant_id:tenantId,case_id:caseId,action_key:actionKey,action_payload:payload,payload_sha256:digest,requested_by:a.userId}),cache:'no-store',redirect:'error',signal:AbortSignal.timeout(8000)});
    if(response.status===401||response.status===403)return reply({error:'Analyst, responder, or owner access to this case is required.'},403);
    if(!response.ok)return reply({error:'Approval request could not be saved. Verify case access and payload limits.'},422);
    const rows:unknown=await response.json();if(!Array.isArray(rows)||!rows[0])return reply({error:'Approval storage returned an invalid response.'},502);
    return reply({approval:rows[0]},201);
  }catch{return reply({error:'Approval storage is temporarily unavailable.'},503);}
}
export async function PATCH(request: Request) {
  const cfg=config();if(!cfg)return reply({error:'Approval storage is not configured.'},503);
  const a=await auth(request,cfg);if(a.error||!a.token)return a.error??reply({error:'Sign in is required.'},401);
  const parsed=await readBoundedJson(request,8192);if(!parsed.ok)return reply({error:parsed.error},parsed.status);
  if(!parsed.value||typeof parsed.value!=='object'||Array.isArray(parsed.value))return reply({error:'A JSON object is required.'},400);
  const v=parsed.value as Record<string,unknown>,approvalId=typeof v.approval_id==='string'?v.approval_id:'',decision=v.decision,reason=v.reason;
  if(!UUID.test(approvalId)||!['approved','rejected'].includes(String(decision)))return reply({error:'Valid approval_id and approved/rejected decision are required.'},400);
  if(reason!==undefined&&reason!==null&&(typeof reason!=='string'||reason.length>2000))return reply({error:'Decision reason must be at most 2000 characters.'},400);
  try{
    const response=await fetch(cfg.url+'/rest/v1/rpc/satark_decide_approval',{method:'POST',headers:{apikey:cfg.key,Authorization:'Bearer '+a.token,'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({p_approval_id:approvalId,p_decision:decision,p_reason:reason??null}),cache:'no-store',redirect:'error',signal:AbortSignal.timeout(8000)});
    if(response.status===401||response.status===403)return reply({error:'Only a different workspace owner or responder can decide this request.'},403);
    if(!response.ok)return reply({error:'Approval decision was rejected: the request may be expired, already decided, or self-approved.'},422);
    const approval:unknown=await response.json();return reply({approval});
  }catch{return reply({error:'Approval decision service is temporarily unavailable.'},503);}
}
