'use client';

import Link from 'next/link';
import { FormEvent, useEffect, useState } from 'react';
import SiteHeader from '../site-header';
import { createTenant, getSession, listMyTenants, setActiveTenant, signIn, signOut, signUp, type SatarkSession, type SatarkTenant } from '../../lib/satark-auth';

export default function LoginPage() {
  const [session, setSession] = useState<SatarkSession | null>(null);
  const [tenants, setTenants] = useState<SatarkTenant[]>([]);
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [workspaceName, setWorkspaceName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function loadWorkspaces() {
    const current = await getSession();
    setSession(current);
    if (!current) { setTenants([]); return; }
    try { setTenants(await listMyTenants()); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not load workspaces.'); }
  }

  useEffect(() => { void loadWorkspaces(); }, []);

  async function submitAuth(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      if (mode === 'signin') {
        await signIn(email.trim(), password);
        await loadWorkspaces();
        setNotice('Signed in. Choose a workspace or create one to continue.');
      } else {
        const result = await signUp(email.trim(), password);
        if (result.session) {
          setSession(result.session);
          await loadWorkspaces();
          setNotice('Account created. Choose a workspace or create one to continue.');
        } else {
          setNotice('Check your email for the confirmation link, then return here to sign in.');
          setMode('signin');
        }
      }
    } catch (e) { setError(e instanceof Error ? e.message : 'Authentication failed.'); }
    finally { setBusy(false); }
  }

  async function submitWorkspace(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      const id = await createTenant(workspaceName.trim());
      setActiveTenant(id);
      window.location.assign('/firstlight');
    } catch (e) { setError(e instanceof Error ? e.message : 'Workspace could not be created.'); }
    finally { setBusy(false); }
  }

  async function chooseTenant(tenant: SatarkTenant) {
    setActiveTenant(tenant.id);
    window.location.assign('/firstlight');
  }

  async function logout() {
    setBusy(true);
    await signOut();
    setSession(null); setTenants([]); setNotice('You have signed out.'); setBusy(false);
  }

  return (
    <div className="shell">
      <SiteHeader status />
      <main id="main-content" className="container">
        <div className="eyebrow">SECURE WORKSPACE ACCESS</div>
        <section className="hero" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(320px, .85fr)', alignItems: 'start' }}>
          <div>
            <h1 style={{ fontSize: 'clamp(38px, 5vw, 64px)' }}>Investigations that <span>remember.</span></h1>
            <p className="lead">Sign in to access tenant-scoped incidents, evidence, and investigation history. Your access is enforced by Supabase authentication and database row-level security.</p>
            <div className="info-panel" style={{ marginTop: 28 }}>
              <strong>Access model</strong>
              <p className="muted">Workspace membership controls access. The browser never receives a service-role credential. A newly created workspace grants owner access only to the signed-in account.</p>
            </div>
            <p style={{ marginTop: 24 }}><Link className="btn btn-secondary" href="/investigate">Continue to public investigation tools ↗</Link></p>
          </div>
          <section className="form-panel" aria-labelledby="auth-title">
            {!session ? <>
              <div className="card-head"><span>IDENTITY</span><span className="pill">{mode === 'signin' ? 'SIGN IN' : 'CREATE ACCOUNT'}</span></div>
              <h2 id="auth-title">{mode === 'signin' ? 'Welcome back' : 'Create your account'}</h2>
              <p className="muted">Use your workspace account. Email confirmation may be required depending on the Supabase Auth configuration.</p>
              <form onSubmit={submitAuth}>
                <label className="field-label" htmlFor="email">Email address</label>
                <input id="email" type="email" autoComplete="email" required maxLength={254} value={email} onChange={e => setEmail(e.target.value)} />
                <label className="field-label" htmlFor="password">Password</label>
                <input id="password" type="password" autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} required minLength={8} maxLength={128} value={password} onChange={e => setPassword(e.target.value)} />
                <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? 'Please wait…' : mode === 'signin' ? 'Sign in securely' : 'Create account'}</button>
              </form>
              <p className="muted">{mode === 'signin' ? 'New to SATARK?' : 'Already have an account?'} <button type="button" className="text-button" onClick={() => { setMode(mode === 'signin' ? 'signup' : 'signin'); setError(''); setNotice(''); }}>{mode === 'signin' ? 'Create an account' : 'Sign in'}</button></p>
            </> : <>
              <div className="card-head"><span>AUTHENTICATED</span><span className="pill">SESSION ACTIVE</span></div>
              <h2 id="auth-title">Your workspaces</h2>
              <p className="muted">Signed in as {session.user.email || session.user.id}</p>
              {tenants.length ? <div className="workspace-list" aria-label="Available workspaces">
                {tenants.map(tenant => <button type="button" className="workspace-choice" key={tenant.id} onClick={() => void chooseTenant(tenant)}>
                  <span><strong>{tenant.name}</strong><small>{tenant.role} · {tenant.id.slice(0, 8)}</small></span><span aria-hidden="true">→</span>
                </button>)}
              </div> : <p className="empty-state">No workspace membership found yet. Create a workspace to begin.</p>}
              <form onSubmit={submitWorkspace} style={{ marginTop: 22 }}>
                <label className="field-label" htmlFor="workspace">New workspace name</label>
                <input id="workspace" required minLength={1} maxLength={160} value={workspaceName} onChange={e => setWorkspaceName(e.target.value)} placeholder="e.g. Incident Response Team" />
                <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create workspace'}</button>
              </form>
              <button className="btn btn-secondary" type="button" onClick={() => void logout()} disabled={busy} style={{ marginTop: 12 }}>Sign out</button>
            </>}
            {error && <p className="error-message" role="alert">{error}</p>}
            {notice && <p className="success-message" role="status">{notice}</p>}
          </section>
        </section>
      </main>
    </div>
  );
}
