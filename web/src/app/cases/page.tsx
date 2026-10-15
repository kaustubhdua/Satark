'use client';

import Link from 'next/link';
import { FormEvent, useEffect, useMemo, useState } from 'react';
import SiteHeader from '../site-header';
import {
  createCase, getActiveTenant, getSession, listCases, listMyTenants, setActiveTenant,
  type SatarkSession, type SatarkTenant,
} from '../../lib/satark-auth';

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
        setCases(await listCases(active.id) as CaseRow[]);
      } else {
        setTenantId('');
        setCases([]);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load the case workspace.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void initialize(); }, []);

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
    setError('');
    setNotice('');
    if (!id) return;
    setLoading(true);
    try { setCases(await listCases(id) as CaseRow[]); }
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
      setTitle('');
      setSeverity('unknown');
      setNotice('Case created and saved to the selected workspace.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create the case.');
    } finally { setBusy(false); }
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
          </>
        )}
        {error && <p className="error-message" role="alert">{error}</p>}
        {notice && <p className="success-message" role="status" aria-live="polite">{notice}</p>}
        <p className="field-note">A case record is an operational container, not a verdict. Confirm source timestamps, retain original evidence securely, and independently verify any recommended response action.</p>
      </div>
    </main>
  );
}
