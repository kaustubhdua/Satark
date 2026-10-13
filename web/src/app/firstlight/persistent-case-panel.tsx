'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  authenticatedFetch, createCase, getActiveTenant, getSession, listCases, listMyTenants, setActiveTenant,
  type SatarkSession, type SatarkTenant,
} from '../../lib/satark-auth';

type EvidenceRow = { id: string; time: string; source: string; kind: string; summary: string; digest: string; tampered?: boolean };
type FindingRow = { title: string; detail: string; severity: string; refs: string[] };
type CaseRow = { id: string; tenant_id: string; title: string; status: string; severity: string; created_at: string; updated_at: string };
type AuditRow = { time: string; action: string; detail: string };

export default function PersistentCasePanel({
  evidence, findings, currentCaseId, importName, onLoaded, onSaved,
}: {
  evidence: EvidenceRow[];
  findings: FindingRow[];
  currentCaseId: string;
  importName: string;
  onLoaded: (caseId: string, evidence: EvidenceRow[], audit: AuditRow[]) => void;
  onSaved: (caseId: string, message: string) => void;
}) {
  const [session, setSession] = useState<SatarkSession | null>(null);
  const [tenant, setTenant] = useState<SatarkTenant | null>(null);
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [title, setTitle] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [uploadedId, setUploadedId] = useState('');
  const [auditVerification, setAuditVerification] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function refresh() {
    const current = await getSession();
    setSession(current);
    if (!current) { setTenant(null); setCases([]); return; }
    let active = getActiveTenant();
    let memberships = await listMyTenants();
    if (!active || !memberships.some(x => x.id === active)) {
      active = memberships[0]?.id || null;
      if (active) setActiveTenant(active);
    }
    const selected = memberships.find(x => x.id === active) || null;
    setTenant(selected);
    if (selected) setCases(await listCases(selected.id));
    else setCases([]);
  }
  useEffect(() => { void refresh().catch(e => setError(e instanceof Error ? e.message : 'Could not load workspace.')); }, []);

  async function persistIncident() {
    if (!tenant || !session) { setError('Sign in and select a workspace before saving an incident.'); return; }
    if (!evidence.length) { setError('Load or import evidence before saving.'); return; }
    setBusy(true); setError(''); setMessage('');
    let caseId = currentCaseId;
    try {
      if (!caseId || !cases.some(c => c.id === caseId)) {
        const created = await createCase(tenant.id, title.trim() || (importName ? 'Imported investigation: ' + importName : 'FIRSTLIGHT account-compromise investigation'), 'unknown');
        if (!created || typeof created.id !== 'string') throw new Error('Case was created but the API returned no case ID.');
        caseId = created.id;
      }
      const toSave = evidence.slice(0, 500);
      let savedCount = 0;
      for (const item of toSave) {
        const response = await fetch('/api/evidence/records', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tenant_id: tenant.id, case_id: caseId, source_label: item.source, event_kind: item.kind,
            observed_at: item.time, summary: item.summary,
            metadata: { local_evidence_id: item.id, browser_record_sha256: item.digest, simulated_tamper: Boolean(item.tampered) },
          }), cache: 'no-store',
        });
        if (response.status === 409) continue;
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : 'An evidence record could not be saved.');
        savedCount++;
      }
      let findingCount = 0;
      for (const [i, finding] of findings.entries()) {
        const response = await fetch('/api/findings', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tenant_id: tenant.id, case_id: caseId, finding_key: finding.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 160) || 'finding-' + i,
            title: finding.title, severity: finding.severity, detail: finding.detail,
            evidence_refs: finding.refs, source: 'FIRSTLIGHT deterministic rules',
          }), cache: 'no-store',
        });
        if (response.status === 409) continue;
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : 'A finding could not be saved.');
        findingCount++;
      }
      const snapshot = {
        schema_version: 1, generated_at: new Date().toISOString(), case_id: caseId, tenant_id: tenant.id,
        title: title.trim() || (importName ? 'Imported investigation: ' + importName : 'FIRSTLIGHT account-compromise investigation'),
        source_file: importName || null,
        evidence: evidence.map(e => ({ id: e.id, timestamp: e.time, source: e.source, kind: e.kind, summary: e.summary, browser_digest: e.digest, simulated_tamper: Boolean(e.tampered) })),
        findings, audit_events_visible_in_session: [], limitations: [
          'Report reflects the saved snapshot at generation time; later case changes require a new report.',
          'Browser-calculated record hashes are supporting metadata; uploaded file hashes are calculated server-side.',
          'A matching SHA-256 digest proves byte equality with the recorded upload digest, not source authenticity.',
          'FIRSTLIGHT deterministic findings are leads for human review, not proof of compromise.',
        ],
      };
      const reportResponse = await fetch('/api/reports', {
        method: 'POST', headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenant.id, case_id: caseId, title: snapshot.title, snapshot }), cache: 'no-store',
      });
      const reportData = await reportResponse.json().catch(() => ({}));
      if (!reportResponse.ok) throw new Error(typeof reportData.error === 'string' ? reportData.error : 'Report snapshot could not be saved.');
      await refresh();
      onSaved(caseId, 'Saved case ' + caseId.slice(0, 8) + ': ' + savedCount + ' evidence records, ' + findingCount + ' findings, and a reproducible report snapshot.');
      setMessage('Persisted successfully. Server audit events were generated by database triggers.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not persist this incident.');
      if (caseId) onSaved(caseId, 'Case exists, but one or more persistence steps failed. Review the error and retry; duplicate evidence records are safely skipped.');
    } finally { setBusy(false); }
  }

  async function updateCaseStatus(item: CaseRow, status: string) {
    if (!tenant || !session) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const response = await fetch('/api/cases', { method:'PATCH', headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'}, body:JSON.stringify({id:item.id,tenant_id:tenant.id,status}), cache:'no-store' });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Case status could not be updated.');
      setCases(prev=>prev.map(c=>c.id===item.id?{...c,status:data.case.status,updated_at:data.case.updated_at}:c));
      setMessage('Case status updated. The database appended an audit event.');
    } catch(e) { setError(e instanceof Error?e.message:'Case status update failed.'); }
    finally { setBusy(false); }
  }

  async function loadSavedCase(item: CaseRow) {
    if (!tenant || !session) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const query = new URLSearchParams({
        select: 'id,observed_at,source_label,event_kind,summary,record_sha256,metadata',
        tenant_id: 'eq.' + tenant.id, case_id: 'eq.' + item.id, order: 'observed_at.asc', limit: '500',
      });
      const evidenceResponse = await authenticatedFetch('/rest/v1/satark_evidence?' + query);
      if (!evidenceResponse.ok) throw new Error('Saved evidence could not be loaded.');
      const rows = await evidenceResponse.json() as {id:string;observed_at:string;source_label:string;event_kind:string;summary:string;record_sha256:string;metadata:Record<string,unknown>}[];
      const mapped = rows.map((row, i) => ({
        id: typeof row.metadata?.local_evidence_id === 'string' ? row.metadata.local_evidence_id : row.id,
        time: row.observed_at, source: row.source_label, kind: row.event_kind, summary: row.summary,
        digest: row.record_sha256, tampered: Boolean(row.metadata?.simulated_tamper),
      }));
      const auditQuery = new URLSearchParams({ select:'action,details,created_at',tenant_id:'eq.'+tenant.id,case_id:'eq.'+item.id,order:'id.asc',limit:'500' });
      const auditResponse = await authenticatedFetch('/rest/v1/satark_audit_events?' + auditQuery);
      const audit = auditResponse.ok ? (await auditResponse.json() as {action:string;details:Record<string,unknown>;created_at:string}[]).map(a => ({
        time:a.created_at, action:a.action, detail:JSON.stringify(a.details),
      })) : [];
      onLoaded(item.id, mapped, audit);
      setMessage('Loaded ' + item.title + ' from persistent storage. ' + mapped.length + ' evidence records recovered.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load saved case.'); }
    finally { setBusy(false); }
  }

  async function uploadOriginal() {
    if (!tenant || !session || !currentCaseId || !file) { setError('Select a workspace, load a saved case, and choose a file first.'); return; }
    setBusy(true); setError(''); setMessage('');
    try {
      const form = new FormData();
      form.set('file', file); form.set('tenant_id', tenant.id); form.set('case_id', currentCaseId);
      form.set('source_label', file.name.slice(0,160)); form.set('event_kind', 'source_file');
      form.set('observed_at', new Date().toISOString()); form.set('summary', 'Private original evidence file uploaded through FIRSTLIGHT.');
      const response = await fetch('/api/evidence', { method:'POST', headers:{Authorization:'Bearer '+session.access_token}, body:form, cache:'no-store' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : 'Private evidence upload failed.');
      setUploadedId(result.evidence.id); setMessage('Private file uploaded. Server SHA-256: ' + result.integrity.source_sha256);
      setFile(null);
    } catch (e) { setError(e instanceof Error ? e.message : 'Private evidence upload failed.'); }
    finally { setBusy(false); }
  }

  async function verifyAuditChain() {
    if (!tenant || !session) return;
    setBusy(true); setError(''); setAuditVerification('');
    try {
      const response = await fetch('/api/audit/verify?tenant_id=' + encodeURIComponent(tenant.id), { headers:{Authorization:'Bearer '+session.access_token}, cache:'no-store' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok && response.status !== 409) throw new Error(typeof result.error === 'string' ? result.error : 'Audit verification failed.');
      setAuditVerification((result.chain_valid ? 'AUDIT CHAIN VALID' : 'AUDIT CHAIN INVALID') + ' · ' + result.event_count + ' events · verified ' + result.verified_at + (result.first_invalid_event_id ? ' · first invalid event ' + result.first_invalid_event_id : ''));
    } catch (e) { setError(e instanceof Error ? e.message : 'Audit verification failed.'); }
    finally { setBusy(false); }
  }

  async function verifyOriginal() {
    if (!uploadedId || !session) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const response = await fetch('/api/evidence/' + encodeURIComponent(uploadedId) + '/verify', { headers:{Authorization:'Bearer '+session.access_token}, cache:'no-store' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok && response.status !== 409) throw new Error(typeof result.error === 'string' ? result.error : 'Integrity verification failed.');
      setMessage((result.matched ? 'INTEGRITY MATCH' : 'INTEGRITY MISMATCH') + ' · ' + result.actual_sha256 + ' · ' + result.note);
    } catch (e) { setError(e instanceof Error ? e.message : 'Integrity verification failed.'); }
    finally { setBusy(false); }
  }

  return <section className="persistent-case-panel panel" aria-labelledby="persistent-case-heading">
    <div className="panel-heading"><div><div className="panel-kicker">PERSISTENT CASE WORKSPACE</div><h2 id="persistent-case-heading">Save beyond this browser session</h2></div><span className={session ? 'safe-chip' : 'review-chip'}>{session ? 'AUTHENTICATED' : 'LOCAL MODE'}</span></div>
    {!session ? <p className="empty-state">Training and imports still work locally. <Link href="/login">Sign in or create a workspace</Link> to save cases, evidence, findings, reports, and audit events in persistent storage.</p> : !tenant ? <p className="empty-state">This account has no workspace membership. <Link href="/login">Create a workspace</Link> to begin.</p> : <>
      <p className="hint">Workspace: <strong>{tenant.name}</strong> · role: {tenant.role}. Case and evidence reads are tenant-scoped by database row-level security.</p>
      <div className="persistent-controls">
        <label className="field-label" htmlFor="persistent-case-title">Incident title</label>
        <input id="persistent-case-title" maxLength={240} value={title} onChange={e=>setTitle(e.target.value)} placeholder="Describe this incident" />
        <button className="btn btn-primary" type="button" disabled={busy || !evidence.length} onClick={()=>void persistIncident()}>{busy?'Saving…':'Save case, evidence, findings & report'}</button>
      </div>
      <div className="saved-cases"><strong>Saved cases</strong>{cases.length ? cases.map(item=><div className="saved-case-row" key={item.id}><button type="button" className="workspace-choice" disabled={busy} onClick={()=>void loadSavedCase(item)}><span><strong>{item.title}</strong><small>{item.status} · {item.severity} · updated {new Date(item.updated_at).toLocaleString()}</small></span><span aria-hidden="true">→</span></button><label className="sr-only" htmlFor={'status-'+item.id}>Update status for {item.title}</label><select id={'status-'+item.id} value={item.status} disabled={busy} onChange={e=>void updateCaseStatus(item,e.target.value)}><option value="open">Open</option><option value="contained">Contained</option><option value="resolved">Resolved</option><option value="archived">Archived</option></select></div>) : <p className="empty-state">No saved cases yet. Load or import evidence and save the incident.</p>}</div>
      <div className="private-upload"><div className="panel-heading"><strong>Audit history integrity</strong><button className="mini-btn" type="button" disabled={busy} onClick={()=>void verifyAuditChain()}>Verify audit chain</button></div>{auditVerification && <p className={auditVerification.startsWith('AUDIT CHAIN VALID')?'success-message':'error-message'} role="status">{auditVerification}</p>}<label className="field-label" htmlFor="private-evidence-file">Upload original evidence privately</label><input id="private-evidence-file" type="file" onChange={e=>setFile(e.currentTarget.files?.[0] || null)} disabled={busy} /><p className="hint">Maximum 4 MiB. The server hashes uploaded bytes and stores them in a private bucket. A saved case must be selected first.</p><div className="actions"><button className="btn btn-secondary" type="button" disabled={busy || !file || !currentCaseId} onClick={()=>void uploadOriginal()}>Upload private file</button><button className="btn btn-secondary" type="button" disabled={busy || !uploadedId} onClick={()=>void verifyOriginal()}>Verify last uploaded file</button></div></div>
    </>}
    {error && <p className="error-message" role="alert">{error}</p>}
    {message && <p className="success-message" role="status">{message}</p>}
  </section>;
}
