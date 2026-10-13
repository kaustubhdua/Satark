'use client';

import { useEffect, useState } from 'react';
import { getActiveTenant, getSession, listCases, listMyTenants, setActiveTenant, type SatarkSession, type SatarkTenant } from '../../lib/satark-auth';

type CaseRow = { id:string; title:string; status:string; severity:string; updated_at:string };
type ReportRow = { id:string; case_id:string; title:string; report_version:number; snapshot_sha256:string; created_at:string };
function saveJson(name:string,value:unknown) {
  const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json;charset=utf-8'}));
  const a=document.createElement('a');a.href=url;a.download=name;a.style.display='none';document.body.appendChild(a);a.click();a.remove();window.setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export default function PersistentReports({notes,analysis}:{notes:string;analysis:unknown}) {
  const [session,setSession]=useState<SatarkSession|null>(null);
  const [tenant,setTenant]=useState<SatarkTenant|null>(null);
  const [cases,setCases]=useState<CaseRow[]>([]);
  const [caseId,setCaseId]=useState('');
  const [reports,setReports]=useState<ReportRow[]>([]);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const [notice,setNotice]=useState('');

  async function loadReports(tenantId:string,id:string,token:string) {
    const response=await fetch('/api/reports?tenant_id='+encodeURIComponent(tenantId)+'&case_id='+encodeURIComponent(id),{headers:{Authorization:'Bearer '+token},cache:'no-store'});
    const data=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(typeof data.error==='string'?data.error:'Could not load persistent reports.');
    setReports(Array.isArray(data.reports)?data.reports:[]);
  }
  async function initialize() {
    const current=await getSession();setSession(current);
    if(!current)return;
    const memberships=await listMyTenants();
    let id=getActiveTenant();
    if(!id||!memberships.some(x=>x.id===id)){id=memberships[0]?.id||null;if(id)setActiveTenant(id);}
    const selected=memberships.find(x=>x.id===id)||null;setTenant(selected);
    if(!selected)return;
    const items=await listCases(selected.id) as CaseRow[];setCases(items);
    if(items.length){const active=items[0].id;setCaseId(active);await loadReports(selected.id,active,current.access_token);}
  }
  useEffect(()=>{void initialize().catch(e=>setError(e instanceof Error?e.message:'Could not initialize report workspace.'));},[]);

  async function chooseCase(id:string) {
    setCaseId(id);setReports([]);setError('');setNotice('');
    if(!tenant||!session||!id)return;
    setBusy(true);try{await loadReports(tenant.id,id,session.access_token);}catch(e){setError(e instanceof Error?e.message:'Could not load reports.');}finally{setBusy(false);}
  }
  async function saveSnapshot() {
    if(!tenant||!session||!caseId){setError('Sign in and select a saved case before saving a report.');return;}
    if(!notes.trim()&&!analysis){setError('Add investigation notes or run an analysis before saving.');return;}
    setBusy(true);setError('');setNotice('');
    const snapshot={schema_version:1,generated_at:new Date().toISOString(),case_id:caseId,tenant_id:tenant.id,notes:notes.trim(),analysis_snapshot:analysis,limitations:[
      'Report is an immutable snapshot of the information supplied at generation time.',
      'AI or deterministic analysis results are triage findings and are not independently verified facts.',
      'The report digest detects snapshot changes relative to the saved digest; it does not prove source authenticity.',
    ]};
    try{
      const response=await fetch('/api/reports',{method:'POST',headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},body:JSON.stringify({tenant_id:tenant.id,case_id:caseId,title:'SATARK investigation review',snapshot}),cache:'no-store'});
      const data=await response.json().catch(()=>({}));
      if(!response.ok)throw new Error(typeof data.error==='string'?data.error:'Could not save report snapshot.');
      await loadReports(tenant.id,caseId,session.access_token);
      setNotice('Saved immutable report snapshot. SHA-256: '+data.snapshot_sha256);
    }catch(e){setError(e instanceof Error?e.message:'Could not save report snapshot.');}
    finally{setBusy(false);}
  }
  async function downloadSnapshot(item:ReportRow) {
    if(!session)return;
    setBusy(true);setError('');setNotice('');
    try{
      const response=await fetch('/api/reports/'+encodeURIComponent(item.id),{headers:{Authorization:'Bearer '+session.access_token},cache:'no-store'});
      const data=await response.json().catch(()=>({}));
      if(!response.ok)throw new Error(typeof data.error==='string'?data.error:'Report could not be retrieved or its digest did not match.');
      saveJson('satark-report-'+item.id+'.json',data);
      setNotice('Retrieved report snapshot and verified its SHA-256 digest: '+data.integrity.actual_sha256);
    }catch(e){setError(e instanceof Error?e.message:'Report retrieval failed.');}
    finally{setBusy(false);}
  }

  return <section className="form-panel persistent-reports" aria-labelledby="persistent-reports-title">
    <div className="panel-heading"><div><div className="panel-kicker">SERVER-SAVED REPORTS</div><h2 id="persistent-reports-title">Reproducible snapshots</h2></div><span className={session?'safe-chip':'review-chip'}>{session?'AUTHENTICATED':'LOCAL ONLY'}</span></div>
    {!session?<p className="empty-state">Sign in to save reports against persistent cases. <a href="/login">Open workspace access →</a></p>:!tenant?<p className="empty-state">No workspace membership is available. <a href="/login">Create a workspace →</a></p>:<>
      <p className="hint">Workspace: {tenant.name}. Each saved report is an immutable snapshot with a server-generated SHA-256 digest.</p>
      <label className="field-label" htmlFor="report-case-select">Attach report to case</label>
      <select id="report-case-select" value={caseId} onChange={e=>void chooseCase(e.target.value)} disabled={busy||!cases.length}>
        {!cases.length&&<option value="">No saved cases available</option>}
        {cases.map(item=><option key={item.id} value={item.id}>{item.title} · {item.status}</option>)}
      </select>
      <button className="btn btn-primary" type="button" onClick={()=>void saveSnapshot()} disabled={busy||!caseId}>{busy?'Working…':'Save notes and analysis as report'}</button>
      <div className="saved-cases"><strong>Saved report history</strong>{reports.length?reports.map(item=><div className="report-history-row" key={item.id}><div><strong>{item.title}</strong><small>{new Date(item.created_at).toLocaleString()} · v{item.report_version} · {item.snapshot_sha256.slice(0,16)}…</small></div><button className="mini-btn" type="button" disabled={busy} onClick={()=>void downloadSnapshot(item)}>Verify & export JSON</button></div>):<p className="empty-state">No persistent report snapshots for this case yet.</p>}</div>
    </>}
    {error&&<p className="error-message" role="alert">{error}</p>}
    {notice&&<p className="success-message" role="status">{notice}</p>}
  </section>;
}
