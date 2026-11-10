'use client';

import { useEffect, useState } from 'react';
import { authenticatedFetch } from '../../lib/satark-auth';

type LiveApproval = {
  approval_id: string;
  action: string;
  target: string;
  reason: string;
  payload: Record<string, unknown>;
  requested_by: string;
  status: string;
  expires_at: string;
  approved_by?: string | null;
  executor_id?: string | null;
  provider_reference?: string | null;
  result_detail?: string | null;
  decision_reason?: string | null;
};

type AuditEvent = { sequence: number; event_type: string; actor_id: string; occurred_at: string; payload?: Record<string, unknown> };
type Props = { tenantId: string; caseId: string; userId: string; role: string };

async function readJson(response: Response) {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof payload.detail === 'string' ? payload.detail : 'The response service could not complete this request.');
  return payload;
}

export default function LiveResponsePanel({ tenantId, caseId, userId, role }: Props) {
  const [enabled, setEnabled] = useState(false);
  const [configured, setConfigured] = useState(false);
  const [rows, setRows] = useState<LiveApproval[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [chainValid, setChainValid] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState<'verified' | 'failed' | 'unknown'>('verified');
  const [action, setAction] = useState('wazuh.block_ip');
  const [target, setTarget] = useState('');
  const [reason, setReason] = useState('');
  const [responseValue, setResponseValue] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [verifyReference, setVerifyReference] = useState('');
  const [verifyDetail, setVerifyDetail] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const canRequest = ['owner', 'responder', 'analyst'].includes(role);
  const canDecide = ['owner', 'responder'].includes(role);

  async function refresh() {
    const query = '?tenant_id=' + encodeURIComponent(tenantId) + '&case_id=' + encodeURIComponent(caseId);
    const [statusResponse, approvalsResponse, auditResponse] = await Promise.all([
      authenticatedFetch('/api/firstlight/live-response/status' + query),
      authenticatedFetch('/api/firstlight/live-response/approvals' + query),
      authenticatedFetch('/api/firstlight/live-response/audit' + query),
    ]);
    const [status, approvals, audit] = await Promise.all([readJson(statusResponse), readJson(approvalsResponse), readJson(auditResponse)]);
    setEnabled(status.enabled === true);
    setConfigured(status.credentials_configured === true);
    setRows(Array.isArray(approvals.approvals) ? approvals.approvals : []);
    setAuditEvents(Array.isArray(audit.events) ? audit.events : []);
    setChainValid(audit.chain_valid === true);
  }

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const query = '?tenant_id=' + encodeURIComponent(tenantId) + '&case_id=' + encodeURIComponent(caseId);
        const [statusResponse, approvalsResponse, auditResponse] = await Promise.all([
          authenticatedFetch('/api/firstlight/live-response/status' + query),
          authenticatedFetch('/api/firstlight/live-response/approvals' + query),
          authenticatedFetch('/api/firstlight/live-response/audit' + query),
        ]);
        const [status, approvals, audit] = await Promise.all([readJson(statusResponse), readJson(approvalsResponse), readJson(auditResponse)]);
        if (!active) return;
        setEnabled(status.enabled === true);
        setConfigured(status.credentials_configured === true);
        setRows(Array.isArray(approvals.approvals) ? approvals.approvals : []);
        setAuditEvents(Array.isArray(audit.events) ? audit.events : []);
        setChainValid(audit.chain_valid === true);
      } catch (e) {
        if (active) setError(e instanceof Error ? e.message : 'Live response status is unavailable.');
      }
    };
    void load();
    return () => { active = false; };
  }, [tenantId, caseId]);

  async function run(operation: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('');
    try { await operation(); await refresh(); }
    catch (e) { setError(e instanceof Error ? e.message : 'The response operation failed.'); }
    finally { setBusy(false); }
  }

  async function requestApproval() {
    if (!target.trim() || !responseValue.trim() || reason.trim().length < 8) throw new Error('Enter an allowlisted Wazuh agent ID, an action value, and a reason of at least 8 characters.');
    const idempotency = globalThis.crypto?.randomUUID?.();
    if (!idempotency) throw new Error('A secure browser UUID generator is required for an idempotent request.');
    const response = await authenticatedFetch('/api/firstlight/live-response/approvals', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: tenantId, case_id: caseId, action, target: target.trim(), reason: reason.trim(),
        payload: action === 'wazuh.block_ip' ? { ip_address: responseValue.trim() } : { username: responseValue.trim() },
        idempotency_key: idempotency,
      }),
    });
    await readJson(response);
    setTarget(''); setResponseValue(''); setReason('');
    setNotice('Response request recorded. A different owner/responder must approve it. No provider action has run.');
  }

  async function decide(approvalId: string, decision: 'approved' | 'denied') {
    const response = await authenticatedFetch('/api/firstlight/live-response/approvals', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenant_id: tenantId, case_id: caseId, approval_id: approvalId, decision, reason: 'Reviewed by authorized FIRSTLIGHT operator.' }),
    });
    await readJson(response);
    setNotice(decision === 'approved' ? 'Approval recorded. Execution remains a separate, explicitly gated step.' : 'Response request denied.');
  }

  async function execute(approval: LiveApproval) {
    const expected = (approval.action === 'wazuh.block_ip' ? 'CONFIRM BLOCK_IP ' : 'CONFIRM DISABLE_ACCOUNT ') + approval.target;
    if (confirmation !== expected) throw new Error('Type the exact confirmation string shown for this target.');
    const response = await authenticatedFetch('/api/firstlight/live-response/execute', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenant_id: tenantId, case_id: caseId, approval_id: approval.approval_id, confirmation }),
    });
    const result = await readJson(response);
    setConfirmation('');
    setNotice('Provider response: ' + result.outcome.status + '. A submission is not proof of completed containment.');
  }

  async function verify(approval: LiveApproval) {
    if (verifyReference.trim().length < 3 || verifyDetail.trim().length < 8) throw new Error('Enter the provider action/audit reference and describe the independent Wazuh agent-side check.');
    const response = await authenticatedFetch('/api/firstlight/live-response/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: tenantId, case_id: caseId, approval_id: approval.approval_id,
        status: verificationStatus, provider_reference: verifyReference.trim(), detail: verifyDetail.trim(),
      }),
    });
    await readJson(response);
    setVerifyReference(''); setVerifyDetail(''); setVerificationStatus('verified');
    setNotice('Independent operator attestation recorded. SATARK does not independently query or certify the provider state.');
  }

  return <section className="private-upload" aria-labelledby="firstlight-live-response-heading">
    <strong id="firstlight-live-response-heading">Guarded live response integrations</strong>
    <p className="hint">Optional Wazuh endpoint response using two fixed built-in commands. Live actions are disabled by default, never triggered by AI, and require a case-bound approval plus a separate executor and exact target confirmation.</p>
    <p className={enabled && configured ? 'success-message' : 'hint'} role="status">
      {enabled && configured ? 'Server feature flag enabled · credentials present' : 'Live response disabled or not configured · simulation and investigation remain available'}
    </p>
    {canRequest && <>
      <label className="field-label" htmlFor="live-response-action">Response action</label>
      <select id="live-response-action" value={action} disabled={busy} onChange={e=>setAction(e.target.value)}>
        <option value="wazuh.block_ip">Wazuh · block IPv4 address</option>
        <option value="wazuh.disable_account">Wazuh · disable local account</option>
      </select>
      <label className="field-label" htmlFor="live-response-target">Exact Wazuh agent ID (must be on the server allowlist)</label>
      <input id="live-response-target" maxLength={256} value={target} onChange={e=>setTarget(e.target.value)} disabled={busy} placeholder="001" />
      <label className="field-label" htmlFor="live-response-value">{action === 'wazuh.block_ip' ? 'IPv4 address to block' : 'Local account name to disable'}</label>
      <input id="live-response-value" maxLength={128} value={responseValue} onChange={e=>setResponseValue(e.target.value)} disabled={busy} placeholder={action === 'wazuh.block_ip' ? '203.0.113.10' : 'lab-user'} />
      <label className="field-label" htmlFor="live-response-reason">Case-specific rationale</label>
      <textarea id="live-response-reason" rows={2} maxLength={1000} value={reason} onChange={e=>setReason(e.target.value)} disabled={busy} placeholder="Explain the evidence and why this exact response is necessary." />
      <button className="btn btn-secondary" type="button" disabled={busy || !target.trim() || !responseValue.trim() || reason.trim().length < 8} onClick={()=>void run(requestApproval)}>Request live-response approval</button>
    </>}
    {rows.length === 0 ? <p className="empty-state">No live-response approvals for this case.</p> : <div className="case-notes-list">{rows.map(row=><article className="case-note" key={row.approval_id}>
      <p><strong>{row.action}</strong> · {row.status}</p>
      <small>Target: {row.target} · requester {row.requested_by.slice(0,8)} · expires {new Date(row.expires_at).toLocaleString()}</small>
      <p>{row.reason}</p>
      {row.status === 'pending' && row.requested_by !== userId && canDecide && <div className="actions">
        <button className="btn btn-secondary" type="button" disabled={busy} onClick={()=>void run(()=>decide(row.approval_id,'approved'))}>Approve</button>
        <button className="btn btn-secondary" type="button" disabled={busy} onClick={()=>void run(()=>decide(row.approval_id,'denied'))}>Deny</button>
      </div>}
      {row.status === 'approved' && enabled && configured && row.requested_by !== userId && row.approved_by !== userId && canDecide && <>
        <p className="hint">Type exactly: <code>{(row.action === 'wazuh.block_ip' ? 'CONFIRM BLOCK_IP ' : 'CONFIRM DISABLE_ACCOUNT ') + row.target}</code></p>
        <label className="field-label" htmlFor={'live-confirm-'+row.approval_id}>Target confirmation</label>
        <input id={'live-confirm-'+row.approval_id} value={confirmation} onChange={e=>setConfirmation(e.target.value)} disabled={busy} />
        <button className="btn btn-primary" type="button" disabled={busy} onClick={()=>void run(()=>execute(row))}>Execute approved action once</button>
      </>}
      {(row.status === 'submitted' || row.status === 'unknown') && row.executor_id !== userId && row.requested_by !== userId && row.approved_by !== userId && canDecide && <>
        <label className="field-label" htmlFor={'live-reference-'+row.approval_id}>Provider action / audit reference</label>
        <input id={'live-reference-'+row.approval_id} value={verifyReference} onChange={e=>setVerifyReference(e.target.value)} disabled={busy} placeholder="Reference from provider console" />
        <label className="field-label" htmlFor={'live-verification-status-'+row.approval_id}>Provider-side result</label>
        <select id={'live-verification-status-'+row.approval_id} value={verificationStatus} onChange={e=>setVerificationStatus(e.target.value as 'verified' | 'failed' | 'unknown')} disabled={busy}>
          <option value="verified">Verified</option><option value="failed">Failed</option><option value="unknown">Still unknown</option>
        </select>
        <label className="field-label" htmlFor={'live-verification-'+row.approval_id}>Independent verification note</label>
        <textarea id={'live-verification-'+row.approval_id} rows={2} value={verifyDetail} onChange={e=>setVerifyDetail(e.target.value)} disabled={busy} placeholder="Describe the independent Wazuh agent-side verification." />
        <button className="btn btn-secondary" type="button" disabled={busy} onClick={()=>void run(()=>verify(row))}>Record independent verification</button>
      </>}
      {row.provider_reference && <p className="hint">Provider reference: <code>{row.provider_reference}</code></p>}
      {row.result_detail && <p className="hint">{row.result_detail}</p>}
      {row.decision_reason && <p className="hint">Decision rationale: {row.decision_reason}</p>}
    </article>)}</div>}
    <div className="private-upload">
      <strong>Response audit trail</strong>
      <p className={chainValid ? 'success-message' : 'error-message'} role="status">
        {chainValid ? 'Local response audit chain verifies.' : 'Response audit chain could not be verified.'}
      </p>
      {auditEvents.length === 0 ? <p className="hint">No response audit events have been recorded for this case.</p> :
        <div className="case-notes-list">{auditEvents.slice().reverse().map(event=><p className="case-note" key={event.sequence}>
          <strong>#{event.sequence} · {event.event_type}</strong>
          <small>{event.occurred_at ? new Date(event.occurred_at).toLocaleString() : 'Timestamp unavailable'} · actor {String(event.actor_id || '').slice(0,8)}</small>
        </p>)}</div>}
      <p className="hint">The chain is stored locally. It is tamper-evident against ordinary application edits, not an external signature or proof against a privileged database administrator.</p>
    </div>
    {notice && <p className="success-message" role="status">{notice}</p>}
    {error && <p className="error-message" role="alert">{error}</p>}
  </section>;
}
