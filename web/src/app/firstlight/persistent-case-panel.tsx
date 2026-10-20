'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  authenticatedFetch, createCase, getActiveTenant, getSession, listCases, listMyTenants, setActiveTenant,
  type SatarkSession, type SatarkTenant,
} from '../../lib/satark-auth';

type EvidenceRow = { id: string; time: string; source: string; kind: string; summary: string; digest: string; tampered?: boolean; details?: Record<string, unknown>; metadata?: Record<string, unknown> };
type FindingRow = { title: string; detail: string; severity: string; refs: string[] };
type CaseRow = { id: string; tenant_id: string; title: string; status: string; severity: string; assigned_to?: string | null; created_at: string; updated_at: string };
type MemberRow = { user_id: string; role: string };
type CaseNote = { id: string; tenant_id: string; case_id: string; body: string; created_by: string; created_at: string };
type ApprovalRow = { id: string; action_key: string; action_payload: Record<string, unknown>; payload_sha256: string; status: string; requested_by: string; decided_by?: string | null; decision_reason?: string | null; created_at: string; expires_at: string };
type AuditRow = { time: string; action: string; detail: string };

export default function PersistentCasePanel({
  evidence, findings, audit, actions, currentCaseId, importName, onLoaded, onSaved,
}: {
  evidence: EvidenceRow[];
  findings: FindingRow[];
  audit: AuditRow[];
  actions: string[];
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
  const [jobStatus, setJobStatus] = useState('');
  const [members, setMembers] = useState<MemberRow[]>([]);
  const [selectedAssignee, setSelectedAssignee] = useState('');
  const [notes, setNotes] = useState<CaseNote[]>([]);
  const [noteDraft, setNoteDraft] = useState('');
  const [requestedCaseId, setRequestedCaseId] = useState('');
  const [caseListLoaded, setCaseListLoaded] = useState(false);
  const [approvals, setApprovals] = useState<ApprovalRow[]>([]);
  const [approvalReason, setApprovalReason] = useState('');
  const [approvalDecisionReason, setApprovalDecisionReason] = useState('');
  const [approvalMessage, setApprovalMessage] = useState('');

  async function refresh() {
    setCaseListLoaded(false);
    const current = await getSession();
    setSession(current);
    if (!current) {
      setTenant(null);
      setCases([]);
      setCaseListLoaded(true);
      setRequestedCaseId('');
      return;
    }
    const memberships = await listMyTenants();
    let active = getActiveTenant();
    if (!active || !memberships.some(x => x.id === active)) {
      active = memberships[0]?.id || null;
      if (active) setActiveTenant(active);
    }
    const selected = memberships.find(x => x.id === active) || null;
    setTenant(selected);
    if (selected) {
      setCases(await listCases(selected.id));
      try {
        const memberResponse = await authenticatedFetch('/rest/v1/rpc/satark_list_assignable_members', {
          method: 'POST', body: JSON.stringify({ p_tenant_id: selected.id }),
        });
        const memberRows: unknown = memberResponse.ok ? await memberResponse.json() : [];
        setMembers(Array.isArray(memberRows) ? memberRows.filter((row): row is MemberRow =>
          !!row && typeof row === 'object' && 'user_id' in row && typeof row.user_id === 'string' &&
          'role' in row && typeof row.role === 'string') : []);
      } catch { setMembers([]); }
    } else {
      setCases([]);
      setMembers([]);
    }
    setCaseListLoaded(true);
  }
  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get('case_id') || '';
    if (requested) setRequestedCaseId(requested);
    void refresh().catch(e => setError(e instanceof Error ? e.message : 'Could not load workspace.'));
  }, []);

  useEffect(() => {
    if (!requestedCaseId || !tenant || !session || !caseListLoaded || busy) return;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestedCaseId)) {
      setError('The requested case link is invalid. Choose a saved case from this workspace.');
      setRequestedCaseId('');
      return;
    }
    const requested = cases.find(item => item.id === requestedCaseId);
    setRequestedCaseId('');
    window.history.replaceState(window.history.state, '', window.location.pathname);
    if (!requested) {
      setError('That case is not available in the currently selected workspace.');
      return;
    }
    void loadSavedCase(requested);
  }, [requestedCaseId, tenant, session, cases, caseListLoaded, busy]);

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
      if (evidence.length > 500) throw new Error('This case contains more than 500 evidence records. Split the import before saving so no evidence is silently omitted.');
      let savedCount = 0;
      let duplicateEvidenceCount = 0;
      for (const item of toSave) {
        if (caseId === currentCaseId && item.metadata?.persisted_by_worker === true) {
          if (item.tampered) throw new Error('Worker-ingested source evidence is immutable. Reload the saved case before continuing after a simulated tamper.');
          duplicateEvidenceCount++;
          continue;
        }
        const response = await fetch('/api/evidence/records', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tenant_id: tenant.id, case_id: caseId, source_label: item.source, event_kind: item.kind,
            observed_at: item.time, summary: item.summary,
            metadata: { ...(item.metadata || {}), source_details: item.details || {}, local_evidence_id: item.id, browser_record_sha256: item.digest, browser_event_timestamp: item.time, simulated_tamper: Boolean(item.tampered) },
          }), cache: 'no-store',
        });
        if (response.status === 409) {
          // A conflict is not proof of an identical retry. Compare the persisted
          // browser digest and normalized fields before treating it as idempotent.
          const query = new URLSearchParams({
            select: 'id,observed_at,source_label,event_kind,summary,metadata',
            tenant_id: 'eq.' + tenant.id, case_id: 'eq.' + caseId, limit: '500',
          });
          const existingResponse = await authenticatedFetch('/rest/v1/satark_evidence?' + query);
          if (!existingResponse.ok) throw new Error('Evidence already exists, but its stored version could not be checked safely.');
          const existingRows = await existingResponse.json() as {observed_at:string;source_label:string;event_kind:string;summary:string;metadata:Record<string,unknown>}[];
          const existing = existingRows.find(row => row.metadata?.local_evidence_id === item.id);
          if (!existing ||
              existing.metadata?.browser_record_sha256 !== item.digest ||
              existing.source_label !== item.source ||
              existing.event_kind !== item.kind ||
              existing.summary !== item.summary ||
              Date.parse(existing.observed_at) !== Date.parse(item.time) ||
              Boolean(existing.metadata?.simulated_tamper) !== Boolean(item.tampered)) {
            throw new Error('Evidence conflict detected: the stored record differs from this version. Nothing was overwritten; review the case before retrying.');
          }
          duplicateEvidenceCount++;
          continue;
        }
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : 'An evidence record could not be saved.');
        savedCount++;
      }
      let findingCount = 0;
      let duplicateFindingCount = 0;
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
        if (response.status === 409) {
          const query = new URLSearchParams({ tenant_id: tenant.id, case_id: caseId });
          const existingResponse = await fetch('/api/findings?' + query, {
            headers: { Authorization: 'Bearer ' + session.access_token }, cache: 'no-store',
          });
          if (!existingResponse.ok) throw new Error('Finding already exists, but its stored version could not be checked safely.');
          const existingPayload = await existingResponse.json() as {findings?: {finding_key:string;title:string;severity:string;detail:string;evidence_refs:string[];source:string}[]};
          const expectedKey = finding.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 160) || 'finding-' + i;
          const existing = (existingPayload.findings || []).find(row => row.finding_key === expectedKey);
          if (!existing ||
              existing.title !== finding.title ||
              existing.severity !== finding.severity ||
              existing.detail !== finding.detail ||
              existing.source !== 'FIRSTLIGHT deterministic rules' ||
              JSON.stringify(existing.evidence_refs) !== JSON.stringify(finding.refs)) {
            throw new Error('Finding conflict detected: the stored finding differs from this version. Nothing was overwritten; review the case before retrying.');
          }
          duplicateFindingCount++;
          continue;
        }
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : 'A finding could not be saved.');
        findingCount++;
      }
      const snapshot = {
        schema_version: 1, generated_at: new Date().toISOString(), case_id: caseId, tenant_id: tenant.id,
        title: title.trim() || (importName ? 'Imported investigation: ' + importName : 'FIRSTLIGHT account-compromise investigation'),
        source_file: importName || null,
        evidence: evidence.map(e => ({ id: e.id, timestamp: e.time, source: e.source, kind: e.kind, summary: e.summary, details: e.details || {}, browser_digest: e.digest, metadata: e.metadata || {}, simulated_tamper: Boolean(e.tampered) })),
        findings,
        audit_events_visible_in_session: audit.map(event => ({ ...event })),
        simulated_response_decisions: [...actions],
        limitations: [
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
      onSaved(caseId, 'Saved case ' + caseId.slice(0, 8) + ': ' + savedCount + ' new evidence records, ' + duplicateEvidenceCount + ' verified identical evidence retries, ' + findingCount + ' new findings, ' + duplicateFindingCount + ' verified identical finding retries, and a reproducible report snapshot.');
      setMessage('Saved case, evidence, findings, report snapshot, visible session audit, and simulated response decisions. Database-triggered audit events are separate from this session log.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not persist this incident.');
      if (caseId) onSaved(caseId, 'Case exists, but one or more persistence steps failed. Review the error and retry; duplicate records are skipped only after exact stored-content verification.');
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

  async function refreshApprovals(caseId: string) {
    if (!tenant || !session) return;
    try {
      const response = await fetch('/api/firstlight/approvals?tenant_id=' + encodeURIComponent(tenant.id) + '&case_id=' + encodeURIComponent(caseId), {
        headers: { Authorization: 'Bearer ' + session.access_token }, cache: 'no-store',
      });
      const payload = await response.json().catch(() => ({}));
      setApprovals(response.ok && Array.isArray(payload.approvals) ? payload.approvals as ApprovalRow[] : []);
      if (!response.ok) setApprovalMessage(typeof payload.error === 'string' ? payload.error : 'Approval history is unavailable.');
      else setApprovalMessage('');
    } catch {
      setApprovals([]);
      setApprovalMessage('Approval history is unavailable.');
    }
  }

  async function requestSimulatedApproval() {
    if (!tenant || !session || !currentCaseId || !cases.some(c => c.id === currentCaseId)) {
      setError('Save or load a persistent case before requesting approval.');
      return;
    }
    const reason = approvalReason.trim();
    if (reason.length < 8 || reason.length > 1000) {
      setError('Describe the simulated action in 8–1000 characters.');
      return;
    }
    setBusy(true); setError(''); setMessage(''); setApprovalMessage('');
    try {
      const response = await fetch('/api/firstlight/approvals', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: tenant.id, case_id: currentCaseId, action_key: 'simulation.mark_case_contained',
          action_payload: { mode: 'simulation', operation: 'mark_case_contained', target: { tenant_id: tenant.id, case_id: currentCaseId }, reason },
        }),
        cache: 'no-store',
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.approval) throw new Error(typeof payload.error === 'string' ? payload.error : 'Simulation approval request could not be saved.');
      setApprovalReason('');
      setMessage('Simulation-only approval request saved. No endpoint or account action was executed.');
      await refreshApprovals(currentCaseId);
    } catch (e) { setError(e instanceof Error ? e.message : 'Simulation approval request failed.'); }
    finally { setBusy(false); }
  }

  async function decideSimulatedApproval(approvalId: string, decision: 'approved' | 'rejected') {
    if (!tenant || !session || !['owner','responder'].includes(tenant.role)) {
      setError('Only a different workspace owner or responder may decide an approval.');
      return;
    }
    setBusy(true); setError(''); setMessage(''); setApprovalMessage('');
    try {
      const response = await fetch('/api/firstlight/approvals', {
        method: 'PATCH',
        headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ approval_id: approvalId, decision, reason: approvalDecisionReason.trim() || null }),
        cache: 'no-store',
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.approval) throw new Error(typeof payload.error === 'string' ? payload.error : 'Approval decision could not be saved.');
      setApprovalDecisionReason('');
      setMessage('Approval decision recorded in the audit chain. This records a simulated decision only; no live response action ran.');
      if (currentCaseId) await refreshApprovals(currentCaseId);
    } catch (e) { setError(e instanceof Error ? e.message : 'Approval decision failed.'); }
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
        time: typeof row.metadata?.browser_event_timestamp === "string" ? row.metadata.browser_event_timestamp : row.observed_at, source: row.source_label, kind: row.event_kind, summary: row.summary, details: row.metadata?.source_details && typeof row.metadata.source_details === "object" && !Array.isArray(row.metadata.source_details) ? row.metadata.source_details as Record<string, unknown> : {}, metadata: row.metadata,
        // record_sha256 seals the server-side database envelope, not the browser
        // canonical event used by FIRSTLIGHT's integrity verifier. Keep the
        // original browser digest distinct; never substitute a different hash
        // and accidentally make a saved record appear trusted.
        digest: typeof row.metadata?.browser_record_sha256 === 'string' ? row.metadata.browser_record_sha256 : '',
        tampered: Boolean(row.metadata?.simulated_tamper),
      }));
      const auditQuery = new URLSearchParams({ select:'action,details,created_at',tenant_id:'eq.'+tenant.id,case_id:'eq.'+item.id,order:'id.asc',limit:'500' });
      const auditResponse = await authenticatedFetch('/rest/v1/satark_audit_events?' + auditQuery);
      const audit = auditResponse.ok ? (await auditResponse.json() as {action:string;details:Record<string,unknown>;created_at:string}[]).map(a => ({
        time:a.created_at, action:a.action, detail:JSON.stringify(a.details),
      })) : [];
      onLoaded(item.id, mapped, audit);
      setSelectedAssignee(item.assigned_to || '');
      try {
        const notesResponse = await fetch('/api/cases/notes?tenant_id=' + encodeURIComponent(tenant.id) + '&case_id=' + encodeURIComponent(item.id), {
          headers: { Authorization: 'Bearer ' + session.access_token }, cache: 'no-store',
        });
        const notesPayload = await notesResponse.json().catch(() => ({}));
        setNotes(notesResponse.ok && Array.isArray(notesPayload.notes) ? notesPayload.notes as CaseNote[] : []);
      } catch { setNotes([]); }
      await refreshApprovals(item.id);
      setMessage('Loaded ' + item.title + ' from persistent storage. ' + mapped.length + ' evidence records recovered.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load saved case.'); }
    finally { setBusy(false); }
  }

  async function runDurableInvestigation() {
    if (!tenant || !session || !currentCaseId) {
      setError('Save or load a persistent case before queueing a durable investigation.');
      return;
    }
    setBusy(true); setError(''); setMessage(''); setJobStatus('Queueing investigation…');
    try {
      const queuedResponse = await fetch('/api/firstlight/jobs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: tenant.id, case_id: currentCaseId,
          idempotency_key: crypto.randomUUID(),
        }),
        cache: 'no-store',
      });
      const queued = await queuedResponse.json().catch(() => ({}));
      if (!queuedResponse.ok || !queued.job?.id) {
        throw new Error(typeof queued.error === 'string' ? queued.error : 'The durable investigation could not be queued.');
      }
      const jobId = String(queued.job.id);
      setJobStatus('Job ' + jobId.slice(0, 8) + ' · ' + String(queued.job.status || 'queued'));
      for (let attempt = 0; attempt < 30; attempt++) {
        const statusResponse = await fetch('/api/firstlight/jobs?tenant_id=' + encodeURIComponent(tenant.id) + '&job_id=' + encodeURIComponent(jobId), {
          headers: { Authorization: 'Bearer ' + session.access_token },
          cache: 'no-store',
        });
        const statusPayload = await statusResponse.json().catch(() => ({}));
        if (!statusResponse.ok || !statusPayload.job) {
          throw new Error(typeof statusPayload.error === 'string' ? statusPayload.error : 'Job status could not be read.');
        }
        const job = statusPayload.job;
        setJobStatus('Job ' + jobId.slice(0, 8) + ' · ' + String(job.status) + ' · attempt ' + String(job.attempts || 0));
        if (job.status === 'succeeded') {
          setMessage('Durable investigation completed. Result and report hashes are persisted; reload the case to review saved findings.');
          return;
        }
        if (job.status === 'failed' || job.status === 'cancelled') {
          throw new Error('Durable investigation ' + job.status + (job.error_code ? ': ' + job.error_code : '.'));
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
      setMessage('The job remains queued or running. Its status is durable; check again after the private worker processes it.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Durable investigation failed.');
    } finally { setBusy(false); }
  }

  async function assignCase() {
    if (!tenant || !session || !currentCaseId || !cases.some(c => c.id === currentCaseId)) {
      setError('Load a saved case before assigning it.');
      return;
    }
    if (!['owner', 'responder'].includes(tenant.role)) {
      setError('Only workspace owners and responders can assign cases.');
      return;
    }
    setBusy(true); setError(''); setMessage('');
    try {
      const response = await fetch('/api/cases', {
        method: 'PATCH',
        headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: currentCaseId, tenant_id: tenant.id, assigned_to: selectedAssignee || null }),
        cache: 'no-store',
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : 'Case assignment failed.');
      setCases(prev => prev.map(item => item.id === currentCaseId ? { ...item, assigned_to: result.case.assigned_to ?? null } : item));
      setMessage(selectedAssignee ? 'Case assigned. The assignment change was added to the audit chain.' : 'Case unassigned. The change was added to the audit chain.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Case assignment failed.'); }
    finally { setBusy(false); }
  }

  async function addCaseNote() {
    if (!tenant || !session || !currentCaseId || !cases.some(c => c.id === currentCaseId)) {
      setError('Load a saved case before adding an analyst note.');
      return;
    }
    if (!noteDraft.trim() || noteDraft.trim().length > 4000) {
      setError('Notes must contain 1–4000 characters.');
      return;
    }
    setBusy(true); setError(''); setMessage('');
    try {
      const response = await fetch('/api/cases/notes', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenant.id, case_id: currentCaseId, body: noteDraft.trim() }),
        cache: 'no-store',
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.note) throw new Error(typeof result.error === 'string' ? result.error : 'Note could not be saved.');
      setNotes(prev => [...prev, result.note as CaseNote]);
      setNoteDraft('');
      setMessage('Analyst note saved as an immutable record and added to the audit chain.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Note could not be saved.'); }
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
      setAuditVerification((result.chain_valid ? 'Audit chain valid' : 'Audit chain invalid') + ' · ' + result.event_count + ' events · verified ' + result.verified_at + (result.first_invalid_event_id ? ' · first invalid event ' + result.first_invalid_event_id : ''));
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
      setMessage((result.matched ? 'Integrity match' : 'INTEGRITY MISMATCH') + ' · ' + result.actual_sha256 + ' · ' + result.note);
    } catch (e) { setError(e instanceof Error ? e.message : 'Integrity verification failed.'); }
    finally { setBusy(false); }
  }

  return <section className="persistent-case-panel panel" aria-labelledby="persistent-case-heading">
    <div className="panel-heading"><div><div className="panel-kicker">Persistent case workspace</div><h2 id="persistent-case-heading">Save beyond this browser session</h2></div><span className={session ? 'safe-chip' : 'review-chip'}>{session ? 'Authenticated' : 'Local mode'}</span></div>
    {!session ? <p className="empty-state">Training and imports still work locally. <Link href="/login">Sign in or create a workspace</Link> to save cases, evidence, findings, reports, and audit events in persistent storage.</p> : !tenant ? <p className="empty-state">This account has no workspace membership. <Link href="/login">Create a workspace</Link> to begin.</p> : <>
      <p className="hint">Workspace: <strong>{tenant.name}</strong> · role: {tenant.role}. Case and evidence reads are tenant-scoped by database row-level security.</p>
      <div className="persistent-controls">
        <label className="field-label" htmlFor="persistent-case-title">Incident title</label>
        <input id="persistent-case-title" maxLength={240} value={title} onChange={e=>setTitle(e.target.value)} placeholder="Describe this incident" />
        <button className="btn btn-primary" type="button" disabled={busy || !evidence.length} onClick={()=>void persistIncident()}>{busy?'Saving…':'Save case, evidence, findings & report'}</button>
        <button className="btn btn-secondary" type="button" disabled={busy || !currentCaseId || !cases.some(c => c.id === currentCaseId) || !['owner','responder','analyst'].includes(tenant.role)} onClick={()=>void runDurableInvestigation()}>{busy && jobStatus.startsWith('Queueing') ? 'Queueing…' : 'Run durable investigation'}</button>
      </div>
      {jobStatus && <p className="hint" role="status">{jobStatus}</p>}
      {currentCaseId && cases.some(c => c.id === currentCaseId) && <>
        <div className="private-upload">
          <label className="field-label" htmlFor="case-assignee">Assign case (owner/responder only)</label>
          <select id="case-assignee" value={selectedAssignee} disabled={busy || !['owner','responder'].includes(tenant.role)} onChange={e=>setSelectedAssignee(e.target.value)}>
            <option value="">Unassigned</option>
            {members.map(member=><option key={member.user_id} value={member.user_id}>{member.role} · {member.user_id.slice(0,8)}</option>)}
          </select>
          <button className="btn btn-secondary" type="button" disabled={busy || !['owner','responder'].includes(tenant.role)} onClick={()=>void assignCase()}>Save assignment</button>
        </div>
        <div className="private-upload" aria-labelledby="simulation-approvals-heading">
          <strong id="simulation-approvals-heading">Simulation-only response approvals</strong>
          <p className="hint">Approval records are bound to the exact action payload and audited in Postgres. They never execute endpoint isolation, account changes, or other live response.</p>
          <label className="field-label" htmlFor="simulation-approval-reason">Proposed simulated action and rationale</label>
          <textarea id="simulation-approval-reason" maxLength={1000} rows={2} value={approvalReason} onChange={e=>setApprovalReason(e.target.value)} disabled={busy} placeholder="Explain why the case should be marked contained in the simulation." />
          <button className="btn btn-secondary" type="button" disabled={busy || approvalReason.trim().length < 8 || !['owner','responder','analyst'].includes(tenant.role)} onClick={()=>void requestSimulatedApproval()}>Request simulated approval</button>
          <label className="field-label" htmlFor="simulation-approval-decision-reason">Decision rationale (optional)</label>
          <input id="simulation-approval-decision-reason" maxLength={2000} value={approvalDecisionReason} onChange={e=>setApprovalDecisionReason(e.target.value)} disabled={busy} placeholder="Why approve or reject this request?" />
          {approvalMessage && <p className="hint" role="status">{approvalMessage}</p>}
          <div className="case-notes-list">{approvals.length ? approvals.map(approval=><article className="case-note" key={approval.id}>
            <p><strong>{approval.action_key}</strong> · {approval.status}</p>
            <small>Requested {new Date(approval.created_at).toLocaleString()} · expires {new Date(approval.expires_at).toLocaleString()} · requester {approval.requested_by.slice(0,8)}</small>
            <p>{typeof approval.action_payload.reason === 'string' ? approval.action_payload.reason : 'Simulation payload saved.'}</p>
            {approval.status === 'pending' && approval.requested_by !== session.user.id && ['owner','responder'].includes(tenant.role) && <div className="actions">
              <button className="btn btn-secondary" type="button" disabled={busy} onClick={()=>void decideSimulatedApproval(approval.id,'approved')}>Approve simulation</button>
              <button className="btn btn-secondary" type="button" disabled={busy} onClick={()=>void decideSimulatedApproval(approval.id,'rejected')}>Reject simulation</button>
            </div>}
            {approval.decided_by && <small>Decision by {approval.decided_by.slice(0,8)}{approval.decision_reason ? ' · ' + approval.decision_reason : ''}</small>}
          </article>) : <p className="empty-state">No durable approval requests for this case.</p>}</div>
        </div>
        <div className="private-upload">
          <strong>Immutable analyst notes</strong>
          <div className="case-notes-list">{notes.length ? notes.map(note=><article className="case-note" key={note.id}><p>{note.body}</p><small>{new Date(note.created_at).toLocaleString()} · {note.created_by.slice(0,8)}</small></article>) : <p className="empty-state">No notes yet.</p>}</div>
          <label className="field-label" htmlFor="case-note-draft">Add note</label>
          <textarea id="case-note-draft" maxLength={4000} rows={3} value={noteDraft} onChange={e=>setNoteDraft(e.target.value)} disabled={busy} placeholder="Record an observation, decision, or evidence limitation." />
          <button className="btn btn-secondary" type="button" disabled={busy || !noteDraft.trim() || !['owner','responder','analyst'].includes(tenant.role)} onClick={()=>void addCaseNote()}>Add immutable note</button>
          <p className="hint">Notes cannot be edited or deleted through the application. Their digest and author are recorded in the tenant audit chain.</p>
        </div>
      </>}
      <div className="saved-cases"><strong>Saved cases</strong>{cases.length ? cases.map(item=><div className="saved-case-row" key={item.id}><button type="button" className="workspace-choice" disabled={busy} onClick={()=>void loadSavedCase(item)}><span><strong>{item.title}</strong><small>{item.status} · {item.severity} · updated {new Date(item.updated_at).toLocaleString()}</small></span><span aria-hidden="true">→</span></button><label className="sr-only" htmlFor={'status-'+item.id}>Update status for {item.title}</label><select id={'status-'+item.id} value={item.status} disabled={busy} onChange={e=>void updateCaseStatus(item,e.target.value)}><option value="open">Open</option><option value="contained">Contained</option><option value="resolved">Resolved</option><option value="archived">Archived</option></select></div>) : <p className="empty-state">No saved cases yet. Load or import evidence and save the incident.</p>}</div>
      <div className="private-upload"><div className="panel-heading"><strong>Audit history integrity</strong><button className="mini-btn" type="button" disabled={busy} onClick={()=>void verifyAuditChain()}>Verify audit chain</button></div>{auditVerification && <p className={auditVerification.startsWith('Audit chain valid')?'success-message':'error-message'} role="status">{auditVerification}</p>}<label className="field-label" htmlFor="private-evidence-file">Upload original evidence privately</label><input id="private-evidence-file" type="file" onChange={e=>setFile(e.currentTarget.files?.[0] || null)} disabled={busy} /><p className="hint">Maximum 4 MiB. The server hashes uploaded bytes and stores them in a private bucket. A saved case must be selected first.</p><div className="actions"><button className="btn btn-secondary" type="button" disabled={busy || !file || !currentCaseId} onClick={()=>void uploadOriginal()}>Upload private file</button><button className="btn btn-secondary" type="button" disabled={busy || !uploadedId} onClick={()=>void verifyOriginal()}>Verify last uploaded file</button></div></div>
    </>}
    {error && <p className="error-message" role="alert">{error}</p>}
    {message && <p className="success-message" role="status">{message}</p>}
  </section>;
}
