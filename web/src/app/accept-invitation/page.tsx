'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import SiteHeader from '../site-header';
import { acceptWorkspaceInvitation, getSession, setActiveTenant } from '../../lib/satark-auth';

export default function AcceptInvitationPage() {
  const [status, setStatus] = useState<'checking' | 'success' | 'error'>('checking');
  const [message, setMessage] = useState('Checking your workspace invitation…');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token') || '';
    window.history.replaceState(null, '', window.location.pathname);
    if (!token || token.length > 256) {
      setStatus('error');
      setMessage('This invitation link is missing or invalid. Ask a workspace owner to send a new invitation.');
      return;
    }
    void getSession().then(async session => {
      if (!session) {
        setStatus('error');
        setMessage('Sign in or create an account using the invited email address, then reopen the original invitation email link.');
        return;
      }
      try {
        const result = await acceptWorkspaceInvitation(token);
        if (result.tenant && typeof result.tenant.id === 'string') setActiveTenant(result.tenant.id);
        setStatus('success');
        setMessage('You joined ' + (result.tenant?.name || 'the workspace') + '.');
      } catch (error) {
        setStatus('error');
        setMessage(error instanceof Error ? error.message : 'The invitation could not be accepted.');
      }
    });
  }, []);

  return (
    <div className="shell">
      <SiteHeader />
      <main id="main-content" className="container">
        <section className="auth-layout">
          <div className="auth-aside">
            <div className="eyebrow">Workspace invitation</div>
            <h1>Work together, <span>securely.</span></h1>
            <p className="lead">Workspace invitations are single-use and bound to the email address they were sent to.</p>
            <Link className="btn btn-secondary" href="/login">Go to sign in</Link>
          </div>
          <section className="form-panel auth-card" aria-labelledby="invitation-title" aria-live="polite">
            <div className="card-head"><span>Workspace access</span><span className="pill">{status === 'checking' ? 'Checking' : status === 'success' ? 'Accepted' : 'Needs attention'}</span></div>
            <h2 id="invitation-title">{status === 'checking' ? 'Checking invitation' : status === 'success' ? 'Invitation accepted' : 'Invitation not accepted'}</h2>
            <p className={status === 'error' ? 'error-message' : status === 'success' ? 'success-message' : 'muted'}>{message}</p>
            {status === 'success' && <Link className="btn btn-primary" href="/firstlight">Open workspace</Link>}
            {status === 'error' && <p className="muted">If the link has expired or was revoked, ask the workspace owner to send another invitation.</p>}
          </section>
        </section>
      </main>
    </div>
  );
}
