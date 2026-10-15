'use client';

import Link from 'next/link';
import { FormEvent, useEffect, useMemo, useState } from 'react';
import SiteHeader from '../site-header';
import {
  createCase, getActiveTenant, getSession, listCases, listMyTenants, setActiveTenant,
  type SatarkSession, type SatarkTenant,
} from '../../lib/satark-auth';

type EvidenceRecord = { id: string; source_label: string; event_kind: string; observed_at: string; summary: string; source_sha256: string; record_sha256: string; created_at: string };

type CaseRow = {
  id: string;
  tenant_id: string;
  title: string;
  status: 'open' | 'contained' | 'resolved' | 'archived';
  severity: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
};

const STATUSES: CaseRow['status'][] = ['open', 'contained', 'resolved', 'archived'];
const SEVERITIES: CaseRow['severity'][] = ['unknown', 'low', 'medium', 'high', 'critical'];

function pretty(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
}

export default function CasesPage() {
  const [session, setSession] = useState<SatarkSession | null>(null);
  const [tenants, setTenants] = useState<SatarkTenant[]>([]);
  const [tenantId, setTenantId] = useState('');
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [title, setTitle] = useState('');
  const [evidenceCaseId, setEvidenceCaseId] = useState('');
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [evidenceSummary, setEvidenceSummary] = useState('Evidence file uploaded.');
  const [evidenceReceipt, setEvidenceReceipt] = useState<{ id: string; source_sha256: string; record_sha256: string } | null>(null);
  const [evidenceRecords, setEvidenceRecords] = useState<EvidenceRecord[]>([]);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState('');
  const [evidenceRefresh, setEvidenceRefresh] = useState(0);
  const [severity, setSeverity] = useState<CaseRow['severity']>('unknown');
  const [statusFilter, setStatusFilter] = useState<'all' | CaseRow['status']>('all');
  const [search, setSearch] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function initialize() {
    setLoading(true);
    setError('');
    try {
      const current = await getSession();
      setSession(current);
      if (!current) { setTenants([]); setCases([]); return; }
      const memberships = await listMyTenants();
      setTenants(memberships);
      const stored = getActiveTenant();
      const active = memberships.find(item => item.id === stored) || memberships[0] || null;
      if (active) {
        setTenantId(active.id);
        setActiveTenant(active.id);
        const loadedCases = await listCases(active.id) as CaseRow[];
        setCases(loadedCases);
        setEvidenceCaseId(loadedCases[0]?.id || '');
      } else {
        setTenantId('');
        setCases([]);
        setEvidenceCaseId('');
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load the case workspace.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void initialize(); }, []);

  useEffect(() => {
    if (!session || !tenantId || !evidenceCaseId) { setEvidenceRecords([]); setEvidenceError(''); setEvidenceLoading(false); return; }
    let cancelled = false;
    setEvidenceLoading(true); setEvidenceError('');
    fetch('/api/evidence/records?tenant_id=' + encodeURIComponent(tenantId) + '&case_id=' + encodeURIComponent(evidenceCaseId), {
      headers: { Authorization: 'Bearer ' + session.access_token }, cache: 'no-store',
    }).then(async response => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Could not load evidence records.');
      if (!Array.isArray(data.evidence)) throw new Error('Evidence service returned an invalid record list.');
      if (!cancelled) setEvidenceRecords(data.evidence as EvidenceRecord[]);
    }).catch(cause => {
      if (!cancelled) { setEvidenceRecords([]); setEvidenceError(cause instanceof Error ? cause.message : 'Could not load evidence records.'); }
    }).finally(() => { if (!cancelled) setEvidenceLoading(false); });
    return () => { cancelled = true; };
  }, [session, tenantId, evidenceCaseId, evidenceRefresh]);

  const visibleCases = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return cases.filter(item =>
      (statusFilter === 'all' || item.status === statusFilter) &&
      (!needle || item.title.toLowerCase().includes(needle) || item.id.toLowerCase().includes(needle))
    );
  }, [cases, search, statusFilter]);

  async function selectTenant(id: string) {
    setTenantId(id);
    setActiveTenant(id);
    setCases([]);
    setEvidenceCaseId('');
    setEvidenceReceipt(null);
    setEvidenceFile(null);
    setError('');
    setNotice('');
    if (!id) return;
    setLoading(true);
    try {
      const loadedCases = await listCases(id) as CaseRow[];
      setCases(loadedCases);
      setEvidenceCaseId(loadedCases[0]?.id || '');
    }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not load cases for this workspace.'); }
    finally { setLoading(false); }
  }

  async function submitCase(event: FormEvent) {
    event.preventDefault();
    if (!tenantId) { setError('Choose a workspace before creating a case.'); return; }
    if (!title.trim()) { setError('Enter a case title.'); return; }
    setBusy(true); setError(''); setNotice('');
    try {
      const created = await createCase(tenantId, title.trim(), severity) as CaseRow;
      if (!created?.id) throw new Error('The case was not returned by the storage service.');
      setCases(previous => [created, ...previous.filter(item => item.id !== created.id)]);
      setEvidenceCaseId(created.id);
      setTitle('');
      setSeverity('unknown');
      setNotice('Case created and saved to the selected workspace.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create the case.');
    } finally { setBusy(false); }
  }

  async function uploadEvidence(event: FormEvent) {
    event.preventDefault();
    if (!session || !tenantId || !evidenceCaseId || !evidenceFile) { setError('Choose a saved case and evidence file first.'); return; }
    if (evidenceFile.size < 1 || evidenceFile.size > 4 * 1024 * 1024) { setError('Choose a non-empty file no larger than 4 MiB.'); return; }
    setBusy(true); setError(''); setNotice(''); setEvidenceReceipt(null);
    try {
      const form = new FormData();
      form.set('file', evidenceFile); form.set('tenant_id', tenantId); form.set('case_id', evidenceCaseId);
      form.set('source_label', evidenceFile.name.slice(0, 160)); form.set('event_kind', 'file');
      form.set('summary', evidenceSummary.trim() || 'Evidence file uploaded.');
      const response = await fetch('/api/evidence', { method: 'POST', headers: { Authorization: 'Bearer ' + session.access_token }, body: form, cache: 'no-store' });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Evidence upload failed.');
      const row = data.evidence as { id?: string } | undefined;
      const digest = data.integrity as { source_sha256?: string; record_sha256?: string } | undefined;
      if (!row?.id || !digest?.source_sha256 || !digest?.record_sha256) throw new Error('Upload response did not include a complete integrity receipt. Contact an administrator before retrying.');
      setEvidenceReceipt({ id: row.id, source_sha256: digest.source_sha256, record_sha256: digest.record_sha256 });
      setEvidenceRefresh(value => value + 1);
      setEvidenceFile(null); setEvidenceSummary('Evidence file uploaded.');
      const input = document.getElementById('case-evidence-file') as HTMLInputElement | null;
      if (input) input.value = '';
      setNotice('Evidence uploaded to private storage and the metadata record was saved. Keep the integrity receipt with your case notes.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Evidence upload failed.'); }
    finally { setBusy(false); }
  }

  async function changeStatus(item: CaseRow, status: CaseRow['status']) {
    if (!session || !tenantId || item.status === status) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const response = await fetch('/api/cases', {
        method: 'PATCH',
        headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: item.id, tenant_id: tenantId, status }),
        cache: 'no-store',
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Case status could not be updated.');
      setCases(previous => previous.map(row => row.id === item.id ? data.case as CaseRow : row));
      setNotice('Case status updated.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Case status could not be updated.');
    } finally { setBusy(false); }
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">WORKSPACE / CASE MANAGEMENT</div>
        <h1>Keep incidents accountable.</h1>
        <p className="lead">Create and track tenant-scoped cases, manage status and severity, and continue evidence-led investigation in FIRSTLIGHT. Access is enforced by Supabase Auth and row-level security.</p>

        {!session ? (
          <section className="form-panel">
            <h2>Sign in to view saved cases</h2>
            <p className="muted">Saved cases are private to their workspace. Sign in before creating or reviewing incident records.</p>
            <Link className="btn btn-primary" href="/login">Open secure workspace sign-in →</Link>
          </section>
        ) : (
          <>
            <section className="form-panel" aria-labelledby="case-workspace-heading">
              <div className="panel-heading">
                <div><div className="panel-kicker">AUTHENTICATED WORKSPACE</div><h2 id="case-workspace-heading">Workspace and case queue</h2></div>
                <span className="safe-chip">RLS PROTECTED</span>
              </div>
              <p className="hint">Signed in as {session.user.email || session.user.id}. Only cases visible to your membership are returned.</p>
              <label className="field-label" htmlFor="case-tenant">Workspace</label>
              <select id="case-tenant" value={tenantId} onChange={event => void selectTenant(event.target.value)} disabled={busy || loading || !tenants.length}>
                {!tenants.length && <option value="">No workspace membership</option>}
                {tenants.map(tenant => <option key={tenant.id} value={tenant.id}>{tenant.name} · {tenant.role}</option>)}
              </select>
              {!tenants.length && <p className="empty-state">You do not have a workspace yet. <Link href="/login">Create one in workspace access →</Link></p>}
              <form onSubmit={submitCase} className="case-create-form">
                <h3>Create a case</h3>
                <label className="field-label" htmlFor="case-title">Case title</label>
                <input id="case-title" value={title} onChange={event => setTitle(event.target.value)} maxLength={240} required placeholder="e.g. Suspected mailbox compromise" disabled={!tenantId || busy} />
                <label className="field-label" htmlFor="case-severity">Initial severity</label>
                <select id="case-severity" value={severity} onChange={event => setSeverity(event.target.value as CaseRow['severity'])} disabled={!tenantId || busy}>
                  {SEVERITIES.map(item => <option key={item} value={item}>{pretty(item)}</option>)}
                </select>
                <button className="btn btn-primary" type="submit" disabled={!tenantId || busy || !title.trim()}>{busy ? 'Saving…' : 'Create saved case'}</button>
              </form>
            </section>

            <section className="form-panel" aria-labelledby="case-list-heading">
              <div className="panel-heading"><div><div className="panel-kicker">PERSISTENT RECORDS</div><h2 id="case-list-heading">Case queue</h2></div><span className="pill">{visibleCases.length} shown</span></div>
              <div className="case-filters">
                <div><label className="field-label" htmlFor="case-search">Search cases</label><input id="case-search" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search title or case ID" /></div>
                <div><label className="field-label" htmlFor="case-status-filter">Status</label><select id="case-status-filter" value={statusFilter} onChange={event => setStatusFilter(event.target.value as typeof statusFilter)}>{(['all', ...STATUSES] as const).map(item => <option key={item} value={item}>{item === 'all' ? 'All statuses' : pretty(item)}</option>)}</select></div>
              </div>
              {loading ? <p className="empty-state" role="status">Loading workspace cases…</p> : !cases.length ? <div className="empty-state"><strong>No saved cases yet.</strong><p>Create a case above or open FIRSTLIGHT to save an investigation with evidence, findings and an immutable report snapshot.</p><Link className="text-link" href="/firstlight">Open FIRSTLIGHT →</Link></div> : !visibleCases.length ? <p className="empty-state">No cases match these filters.</p> : (
                <div className="case-queue-list" aria-label="Saved cases">
                  {visibleCases.map(item => (
                    <article className="report-history-row" key={item.id}>
                      <div className="case-row-main">
                        <strong>{item.title}</strong>
                        <small>{item.id} · Updated {new Date(item.updated_at).toLocaleString()}</small>
                        <div className="case-meta"><span className="pill">{pretty(item.severity)} severity</span><span className="pill">{pretty(item.status)}</span></div>
                      </div>
                      <div className="case-row-actions">
                        <label className="field-label" htmlFor={'status-' + item.id}>Update status</label>
                        <select id={'status-' + item.id} value={item.status} disabled={busy} onChange={event => void changeStatus(item, event.target.value as CaseRow['status'])}>
                          {STATUSES.map(status => <option key={status} value={status}>{pretty(status)}</option>)}
                        </select>
                        <Link className="mini-btn" href="/firstlight">Open FIRSTLIGHT</Link>
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="form-panel" aria-labelledby="case-evidence-heading">
              <div className="panel-heading"><div><div className="panel-kicker">PRIVATE EVIDENCE STORAGE</div><h2 id="case-evidence-heading">Attach evidence to a case</h2></div><span className="safe-chip">SHA-256 RECEIPT</span></div>
              <p className="field-note">Upload a supported file up to 4 MiB. SATARK validates basic file signatures, calculates a server-side SHA-256 digest and stores the object privately. A digest proves byte equality, not source authenticity or safety.</p>
              <form className="case-create-form" onSubmit={uploadEvidence}>
                <label className="field-label" htmlFor="evidence-case-select">Saved case</label>
                <select id="evidence-case-select" value={evidenceCaseId} onChange={event => setEvidenceCaseId(event.target.value)} disabled={busy || !cases.length} required>
                  {!cases.length && <option value="">Create a case first</option>}
                  {cases.map(item => <option key={item.id} value={item.id}>{item.title} · {pretty(item.status)}</option>)}
                </select>
                <label className="field-label" htmlFor="case-evidence-file">Evidence file</label>
                <input id="case-evidence-file" type="file" onChange={event => { setEvidenceFile(event.target.files?.[0] ?? null); setEvidenceReceipt(null); }} disabled={busy || !cases.length} required />
                {evidenceFile && <p className="hint">{evidenceFile.name} · {(evidenceFile.size / 1024).toFixed(1)} KiB</p>}
                <label className="field-label" htmlFor="evidence-summary">Observation / summary</label>
                <textarea id="evidence-summary" value={evidenceSummary} onChange={event => setEvidenceSummary(event.target.value)} maxLength={8192} rows={3} disabled={busy} />
                <button className="btn btn-primary" type="submit" disabled={busy || !cases.length || !evidenceFile}>{busy ? 'Uploading privately…' : 'Upload evidence & calculate digest'}</button>
              </form>
              {evidenceReceipt && <div className="notice-panel" role="status" aria-live="polite"><h3>Evidence integrity receipt</h3><p><strong>Evidence ID:</strong> <code>{evidenceReceipt.id}</code></p><p><strong>File SHA-256:</strong></p><code>{evidenceReceipt.source_sha256}</code><p><strong>Record SHA-256:</strong></p><code>{evidenceReceipt.record_sha256}</code><p className="muted">This receipt supports later integrity comparison; it does not prove source authenticity.</p></div>}
              <div className="saved-cases" aria-labelledby="saved-evidence-heading"><strong id="saved-evidence-heading">Saved evidence records</strong>
                {evidenceLoading ? <p className="empty-state" role="status">Loading evidence records…</p> : evidenceError ? <p className="error-message" role="alert">{evidenceError}</p> : evidenceRecords.length ? evidenceRecords.map(item => <article className="report-history-row" key={item.id}><div><strong>{item.source_label}</strong><small>{pretty(item.event_kind)} · {new Date(item.observed_at).toLocaleString()} · ID {item.id}</small><p>{item.summary}</p><small>File SHA-256: {item.source_sha256}</small><small>Record SHA-256: {item.record_sha256}</small></div></article>) : <p className="empty-state">No saved evidence records for this case yet. Uploaded file contents remain in private storage; this list exposes only authorized metadata and integrity digests.</p>}
              </div>
            </section>
          </>
        )}
        {error && <p className="error-message" role="alert">{error}</p>}
        {notice && <p className="success-message" role="status" aria-live="polite">{notice}</p>}
        <p className="field-note">A case record is an operational container, not a verdict. Confirm source timestamps, retain original evidence securely, and independently verify any recommended response action.</p>
      </div>
    </main>
  );
}
