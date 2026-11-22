'use client';

import Link from 'next/link';
import { type FormEvent, useEffect, useMemo, useState } from 'react';
import { Activity, ArrowUpRight, RefreshCw, ShieldCheck } from 'lucide-react';
import SiteHeader from '../site-header';
import { DeviceWorkspacePanel, useLocalMode } from '../local-workspace-panel';
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
};

const STATUSES: CaseRow['status'][] = ['open', 'contained', 'resolved', 'archived'];
const SEVERITIES: CaseRow['severity'][] = ['unknown', 'low', 'medium', 'high', 'critical'];

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown date' : date.toLocaleString();
}

export default function CasesPage() {
  const localMode = useLocalMode();
  const [session, setSession] = useState<SatarkSession | null>(null);
  const [tenants, setTenants] = useState<SatarkTenant[]>([]);
  const [tenant, setTenant] = useState<SatarkTenant | null>(null);
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<CaseRow['severity']>('unknown');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | CaseRow['status']>('all');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [busyCase, setBusyCase] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function loadCaseList(tenantId: string) {
    const rows = await listCases(tenantId) as CaseRow[];
    setCases(rows);
  }

  async function initialize() {
    setLoading(true);
    setError('');
    try {
      const current = await getSession();
      setSession(current);
      if (!current) return;
      const memberships = await listMyTenants();
      setTenants(memberships);
      if (!memberships.length) {
        setTenant(null);
        setCases([]);
        return;
      }
      const rememberedId = getActiveTenant();
      const selected = memberships.find(item => item.id === rememberedId) || memberships[0];
      setTenant(selected);
      setActiveTenant(selected.id);
      await loadCaseList(selected.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The case workspace could not be loaded.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void initialize(); }, []);

  async function refresh() {
    if (!tenant) return;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      await loadCaseList(tenant.id);
      setNotice('Case list refreshed.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Cases could not be refreshed.');
    } finally {
      setLoading(false);
    }
  }

  async function chooseTenant(id: string) {
    const selected = tenants.find(item => item.id === id);
    if (!selected) return;
    setTenant(selected);
    setActiveTenant(selected.id);
    setCases([]);
    setLoading(true);
    setError('');
    setNotice('');
    try {
      await loadCaseList(selected.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Cases could not be loaded for this workspace.');
    } finally {
      setLoading(false);
    }
  }

  async function submitCase(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!tenant) return;
    setSaving(true);
    setError('');
    setNotice('');
    try {
      await createCase(tenant.id, title.trim(), severity);
      setTitle('');
      await loadCaseList(tenant.id);
      setNotice('Case created and saved to this workspace.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The case could not be created.');
    } finally {
      setSaving(false);
    }
  }

  async function updateCaseField(
    item: CaseRow,
    field: 'status' | 'severity',
    value: CaseRow['status'] | CaseRow['severity'],
  ) {
    if (!tenant || !session) return;
    setBusyCase(item.id);
    setError('');
    setNotice('');
    try {
      const current = await getSession();
      if (!current) throw new Error('Your session expired. Sign in again.');
      const response = await fetch('/api/cases', {
        method: 'PATCH',
        headers: { Authorization: 'Bearer ' + current.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: item.id, tenant_id: tenant.id, [field]: value }),
        cache: 'no-store',
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Case update failed.');
      const updated = data.case as CaseRow | undefined;
      if (!updated || updated.id !== item.id || updated.tenant_id !== tenant.id) {
        throw new Error('The server returned an unexpected case. Refresh before continuing.');
      }
      setCases(currentCases => currentCases.map(row => row.id === updated.id ? updated : row));
      setNotice('Case updated.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The case could not be updated.');
      try { await loadCaseList(tenant.id); } catch { /* Preserve the original error; retry remains available. */ }
    } finally {
      setBusyCase('');
    }
  }

  const visibleCases = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return cases.filter(item => (statusFilter === 'all' || item.status === statusFilter) &&
      (!needle || item.title.toLowerCase().includes(needle) || item.id.toLowerCase().includes(needle)));
  }, [cases, search, statusFilter]);

  const summary = useMemo(() => ({
    open: cases.filter(item => item.status === 'open').length,
    contained: cases.filter(item => item.status === 'contained').length,
    resolved: cases.filter(item => item.status === 'resolved').length,
    highPriority: cases.filter(item => item.severity === 'high' || item.severity === 'critical').length,
  }), [cases]);

  const readOnly = tenant?.role.toLowerCase() === 'viewer';

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">Case management</div>
        <h1>Manage <span>saved cases.</span></h1>
        {localMode.active
          ? <p className="lead">Create and track investigations in a workspace that lives in this browser. Every change is recorded in a hash-chained audit trail you can verify, and nothing leaves your device.</p>
          : <p className="lead">Create and track investigations across your workspaces. Case access and changes are authorized by the server and enforced by database row-level security—not by this interface alone.</p>}
        <DeviceWorkspacePanel />

        {!session ? (
          <section className="form-panel" aria-labelledby="case-access-title">
            <div className="card-head"><span>Authentication required</span><span className="pill">Private workspace</span></div>
            <h2 id="case-access-title">Sign in to manage saved cases</h2>
            <p className="muted">Public analysis tools remain available without an account. Persistent cases require a valid session and workspace membership.</p>
            <div className="actions">
              <Link className="btn btn-primary" href="/login">Open workspace access <ArrowUpRight size={15} /></Link>
              <Link className="btn btn-secondary" href="/investigate">Use public investigation tools</Link>
            </div>
          </section>
        ) : !tenant && !loading ? (
          <section className="form-panel" aria-labelledby="case-workspace-empty-title">
            <h2 id="case-workspace-empty-title">No workspace found</h2>
            <p className="muted">Create a workspace or ask an administrator to add your account to an existing one.</p>
            <Link className="btn btn-primary" href="/login">Open workspace setup <ArrowUpRight size={15} /></Link>
          </section>
        ) : (
          <>
            <section className="form-panel" aria-labelledby="case-workspace-heading">
              <div className="panel-heading">
                <div><div className="panel-kicker">Persistent workspace</div><h2 id="case-workspace-heading">Investigation overview</h2></div>
                <span className="safe-chip"><ShieldCheck size={14} /> {localMode.active ? 'Stored on this device' : 'Server-authorized'}</span>
              </div>
              <div className="form-bottom case-toolbar">
                <div className="case-workspace-picker">
                  <label className="field-label" htmlFor="case-workspace-select">Workspace</label>
                  <select id="case-workspace-select" value={tenant?.id || ''} onChange={event => void chooseTenant(event.target.value)} disabled={loading || tenants.length < 2}>
                    {tenants.map(item => <option key={item.id} value={item.id}>{item.name} · {item.role}</option>)}
                  </select>
                </div>
                <button className="btn btn-secondary" type="button" onClick={() => void refresh()} disabled={loading || !tenant}>
                  <RefreshCw size={15} /> {loading ? 'Refreshing…' : 'Refresh cases'}
                </button>
              </div>
              {tenant && <p className="hint">Workspace: {tenant.name} · Role: {tenant.role} · {cases.length} saved case{cases.length === 1 ? '' : 's'}</p>}
              <div className="workspace-grid case-metrics" aria-label="Case summary">
                <article className="workspace-card"><div className="eyebrow">Open</div><h3>{summary.open}</h3><p>Cases needing active review.</p></article>
                <article className="workspace-card"><div className="eyebrow">Contained</div><h3>{summary.contained}</h3><p>Cases marked as contained.</p></article>
                <article className="workspace-card"><div className="eyebrow">High priority</div><h3>{summary.highPriority}</h3><p>Cases with high or critical severity.</p></article>
              </div>
              {error && <p className="error-message" role="alert">{error}</p>}
              {notice && <p className="success-message" role="status">{notice}</p>}
            </section>

            {tenant && !readOnly && (
              <section className="form-panel" aria-labelledby="new-case-heading">
                <div className="panel-kicker">New investigation</div>
                <h2 id="new-case-heading">Create a case</h2>
                <p className="muted">Record a short, factual title. Add evidence and findings after the case has been created. Avoid putting passwords, tokens, or unnecessary personal data in case titles.</p>
                <form onSubmit={submitCase}>
                  <label className="field-label" htmlFor="new-case-title">Case title</label>
                  <input id="new-case-title" name="title" required minLength={1} maxLength={240} value={title} onChange={event => setTitle(event.target.value)} placeholder="e.g. Suspicious invoice message reported by finance" />
                  <label className="field-label" htmlFor="new-case-severity">Initial severity</label>
                  <select id="new-case-severity" value={severity} onChange={event => setSeverity(event.target.value as CaseRow['severity'])}>
                    {SEVERITIES.map(item => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}
                  </select>
                  <div className="actions">
                    <button className="btn btn-primary" type="submit" disabled={saving || !title.trim() || !tenant}>
                      {saving ? 'Creating case…' : 'Create saved case'}
                    </button>
                  </div>
                </form>
              </section>
            )}
            {readOnly && <p className="notice-panel">Your workspace role is read-only. You can review cases here; a workspace owner or administrator must make changes.</p>}

            <section className="form-panel" aria-labelledby="saved-cases-heading">
              <div className="panel-heading">
                <div><div className="panel-kicker">Case register</div><h2 id="saved-cases-heading">Saved cases</h2></div>
                <span className="pill">{visibleCases.length} SHOWN</span>
              </div>
              <div className="case-filters">
                <div><label className="field-label" htmlFor="case-search">Search by title or case ID</label>
                  <input id="case-search" type="search" maxLength={240} value={search} onChange={event => setSearch(event.target.value)} placeholder="Search saved cases…" /></div>
                <div><label className="field-label" htmlFor="case-status-filter">Filter by status</label>
                  <select id="case-status-filter" value={statusFilter} onChange={event => setStatusFilter(event.target.value as typeof statusFilter)}>
                    <option value="all">All statuses</option>{STATUSES.map(item => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}
                  </select></div>
              </div>
              {loading ? <p className="empty-state" role="status">Loading workspace cases…</p> :
                visibleCases.length ? <div className="case-register">
                  {visibleCases.map((item, index) => <article className="workspace-card case-register-card" key={item.id}>
                    <div className="case-register-top">
                      <span className="eyebrow">CASE / {(index + 1).toString().padStart(2, '0')}</span>
                      <span className={'pill case-status-' + item.status}>{item.status.toUpperCase()}</span>
                    </div>
                    <h3>{item.title}</h3>
                    <p className="case-id">ID: <code>{item.id}</code></p>
                    <p className="hint">Created {formatDate(item.created_at)} · Updated {formatDate(item.updated_at)}</p>
                    <div className="case-field-grid">
                      <div><label className="field-label" htmlFor={'case-status-' + item.id}>Status</label>
                        <select id={'case-status-' + item.id} aria-label={'Status for ' + item.title} value={item.status} disabled={readOnly || busyCase === item.id} onChange={event => void updateCaseField(item, 'status', event.target.value as CaseRow['status'])}>
                          {STATUSES.map(value => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
                        </select></div>
                      <div><label className="field-label" htmlFor={'case-severity-' + item.id}>Severity</label>
                        <select id={'case-severity-' + item.id} aria-label={'Severity for ' + item.title} value={item.severity} disabled={readOnly || busyCase === item.id} onChange={event => void updateCaseField(item, 'severity', event.target.value as CaseRow['severity'])}>
                          {SEVERITIES.map(value => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
                        </select></div>
                    </div>
                    <div className="actions case-open-actions"><Link className="btn btn-secondary" href={'/firstlight?case_id=' + encodeURIComponent(item.id)}>Open in FIRSTLIGHT <ArrowUpRight size={15} /></Link></div>
                    {busyCase === item.id && <p className="hint" role="status">Saving case update…</p>}
                  </article>)}
                </div> :
                  <div className="empty-state">
                    <Activity size={22} />
                    <h3>{cases.length ? 'No cases match these filters' : 'No cases in this workspace yet'}</h3>
                    <p>{cases.length ? 'Clear the search or choose another status.' : 'Create the first case above. Your saved cases remain scoped to this workspace.'}</p>
                    {cases.length > 0 && <button type="button" className="btn btn-secondary" onClick={() => { setSearch(''); setStatusFilter('all'); }}>Clear filters</button>}
                  </div>}
              {summary.resolved > 0 && <p className="hint">{summary.resolved} resolved case{summary.resolved === 1 ? '' : 's'} retained in the workspace history.</p>}
            </section>
          </>
        )}
      </div>
    </main>
  );
}
