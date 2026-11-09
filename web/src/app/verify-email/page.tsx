'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import SiteHeader from '../site-header';
import { completeEmailVerification } from '../../lib/satark-auth';

export default function VerifyEmailPage() {
  const [status, setStatus] = useState<'checking' | 'success' | 'error'>('checking');
  const [message, setMessage] = useState('Verifying your email address…');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token') || '';
    window.history.replaceState(null, '', window.location.pathname);
    if (!token || token.length > 256) {
      setStatus('error');
      setMessage('This verification link is missing or invalid. Request a fresh link from the sign-in page.');
      return;
    }
    void completeEmailVerification(token).then(
      result => {
        setStatus('success');
        setMessage(typeof result.message === 'string' ? result.message : 'Your email address is verified. You can now sign in.');
      },
      error => {
        setStatus('error');
        setMessage(error instanceof Error ? error.message : 'Email verification failed. Request a fresh link.');
      },
    );
  }, []);

  return (
    <div className="shell">
      <SiteHeader />
      <main id="main-content" className="container">
        <section className="auth-layout">
          <div className="auth-aside">
            <div className="eyebrow">Account verification</div>
            <h1>Confirm your <span>identity.</span></h1>
            <p className="lead">Email verification helps protect SATARK workspaces from unverified account registrations.</p>
            <Link className="btn btn-secondary" href="/login">Back to sign in</Link>
          </div>
          <section className="form-panel auth-card" aria-labelledby="verify-title" aria-live="polite">
            <div className="card-head"><span>Identity</span><span className="pill">{status === 'checking' ? 'Verifying' : status === 'success' ? 'Verified' : 'Needs attention'}</span></div>
            <h2 id="verify-title">{status === 'checking' ? 'Checking your link' : status === 'success' ? 'Email verified' : 'Verification incomplete'}</h2>
            <p className={status === 'error' ? 'error-message' : status === 'success' ? 'success-message' : 'muted'}>{message}</p>
            {status !== 'checking' && <Link className="btn btn-primary" href="/login">Continue to sign in</Link>}
          </section>
        </section>
      </main>
    </div>
  );
}
