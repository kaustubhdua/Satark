'use client';

import Link from 'next/link';
import { FormEvent, useEffect, useState } from 'react';
import SiteHeader from '../site-header';
import FirstlightReadiness from '../../components/firstlight-readiness';
import { confirmMfaEnrollment, createTenant, disableMfa, getMfaStatus, getSession, listMyTenants, listWorkspaceInvitations, requestEmailVerification, requestPasswordReset, revokeWorkspaceInvitation, sendWorkspaceInvitation, setActiveTenant, signIn, signOut, signUp, startMfaEnrollment, type SatarkSession, type SatarkTenant } from '../../lib/satark-auth';

export default function LoginPage() {
  const [session, setSession] = useState<SatarkSession | null>(null);
  const [tenants, setTenants] = useState<SatarkTenant[]>([]);
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [recovering, setRecovering] = useState(false);
  const [verificationPending, setVerificationPending] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaStatus, setMfaStatus] = useState<{ enabled: boolean; required: boolean; recovery_codes_remaining: number } | null>(null);
  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaOtpUri, setMfaOtpUri] = useState('');
  const [mfaEnrollCode, setMfaEnrollCode] = useState('');
  const [mfaRecoveryCodes, setMfaRecoveryCodes] = useState<string[]>([]);
  const [mfaDisablePassword, setMfaDisablePassword] = useState('');
  const [mfaDisableCode, setMfaDisableCode] = useState('');
  const [workspaceName, setWorkspaceName] = useState('');
  const [inviteTenantId, setInviteTenantId] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'responder' | 'analyst' | 'viewer'>('analyst');
  const [pendingInvitations, setPendingInvitations] = useState<Array<{ id: string; email: string; role: string; expires_at: string }>>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function loadWorkspaces() {
    const current = await getSession();
    setSession(current);
    if (!current) { setTenants([]); setMfaStatus(null); setInviteTenantId(''); setPendingInvitations([]); return; }
    let security: { enabled: boolean; required: boolean; recovery_codes_remaining: number } | null = null;
    try { security = await getMfaStatus(); setMfaStatus(security); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not load account security settings.'); }
    if (security?.required && !security.enabled) {
      setTenants([]); setInviteTenantId(''); setPendingInvitations([]);
      return;
    }
    try {
      const available = await listMyTenants();
      setTenants(available);
      const ownerWorkspace = available.find(tenant => tenant.role === 'owner');
      if (ownerWorkspace) {
        setInviteTenantId(ownerWorkspace.id);
        setPendingInvitations(await listWorkspaceInvitations(ownerWorkspace.id));
      } else {
        setInviteTenantId('');
        setPendingInvitations([]);
      }
    } catch (e) {
      setTenants([]);
      setError(e instanceof Error ? e.message : 'Could not load workspaces.');
    }
  }

  useEffect(() => { void loadWorkspaces(); }, []);

  async function submitAuth(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      if (mode === 'signin') {
        await signIn(email.trim(), password, mfaCode);
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

  async function resendVerification() {
    setBusy(true); setError(''); setNotice('');
    try {
      await requestEmailVerification(email.trim());
      setNotice('If verification is still required for that account, a fresh link will be sent. Check your inbox.');
    } catch {
      setNotice('If verification is still required for that account, a fresh link will be sent. Check your inbox or try again later.');
    } finally { setBusy(false); }
  }

  async function submitRecovery(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      await requestPasswordReset(email.trim(), new URL('/reset-password', window.location.origin).toString());
      setNotice('If an account exists for that email, a recovery link will be sent. Check your inbox.');
    } catch {
      setNotice('If an account exists for that email, a recovery link will be sent. If it does not arrive, check the address or try again later.');
    } finally { setBusy(false); }
  }

  async function beginMfaEnrollment() {
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await startMfaEnrollment();
      setMfaSecret(result.secret);
      setMfaOtpUri(result.otpauth_uri);
      setMfaEnrollCode('');
      setMfaRecoveryCodes([]);
      setNotice('Add this account to an authenticator app, then enter the six-digit code to confirm.');
    } catch (e) { setError(e instanceof Error ? e.message : 'MFA enrollment could not start.'); }
    finally { setBusy(false); }
  }

  async function finishMfaEnrollment(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      const result = await confirmMfaEnrollment(mfaEnrollCode.trim());
      setMfaRecoveryCodes(result.recovery_codes);
      setMfaSecret('');
      setMfaOtpUri('');
      setMfaEnrollCode('');
      setMfaStatus({ enabled: true, required: mfaStatus?.required ?? false, recovery_codes_remaining: result.recovery_codes.length });
      await loadWorkspaces();
      setNotice('MFA is enabled. Save these recovery codes now; they are shown only once.');
    } catch (e) { setError(e instanceof Error ? e.message : 'The authenticator code was not accepted.'); }
    finally { setBusy(false); }
  }

  async function turnOffMfa(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      await disableMfa(mfaDisablePassword, mfaDisableCode.trim());
      setNotice('MFA disabled. Your sessions were revoked; sign in again.');
      window.location.assign('/login');
    } catch (e) { setError(e instanceof Error ? e.message : 'MFA could not be disabled.'); }
    finally { setBusy(false); }
  }

  async function submitInvitation(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      await sendWorkspaceInvitation(inviteTenantId, inviteEmail, inviteRole);
      setInviteEmail('');
      setPendingInvitations(await listWorkspaceInvitations(inviteTenantId));
      setNotice('Invitation sent. The recipient must sign in with the invited email to accept it.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Workspace invitation could not be sent.'); }
    finally { setBusy(false); }
  }

  async function changeInviteTenant(tenantId: string) {
    setInviteTenantId(tenantId);
    setBusy(true); setError('');
    try { setPendingInvitations(await listWorkspaceInvitations(tenantId)); }
    catch (e) { setError(e instanceof Error ? e.message : 'Pending invitations could not be loaded.'); }
    finally { setBusy(false); }
  }

  async function cancelInvitation(invitationId: string) {
    setBusy(true); setError(''); setNotice('');
    try {
      await revokeWorkspaceInvitation(inviteTenantId, invitationId);
      setPendingInvitations(await listWorkspaceInvitations(inviteTenantId));
      setNotice('Invitation revoked.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Invitation could not be revoked.'); }
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
      <SiteHeader />
      <main id="main-content" className="container">
        <section className="auth-layout">
          <div className="auth-aside">
            <div className="eyebrow">Secure workspace access</div>
            <h1>Investigations that <span>remember.</span></h1>
            <p className="lead">Sign in to access tenant-scoped incidents, evidence, and investigation history. Your access is enforced by SATARK-managed authentication and tenant-scoped backend authorization.</p>
            <div className="info-panel">
              <strong>Access model</strong>
              <p className="muted">Workspace membership controls access. The browser never receives a service-role credential. A newly created workspace grants owner access only to the signed-in account.</p>
            </div>
            <FirstlightReadiness />
            <Link className="btn btn-secondary" href="/investigate">Continue to public investigation tools ↗</Link>
          </div>
          <section className="form-panel auth-card" aria-labelledby="auth-title">
            {!session ? <>
              <div className="card-head"><span>Identity</span><span className="pill">{mode === 'signin' ? 'Sign in' : 'Create account'}</span></div>
              <h2 id="auth-title">{mode === 'signin' ? 'Welcome back' : 'Create your account'}</h2>
              <p className="muted">SATARK manages your password and session. Account recovery requires configured SMTP email delivery.</p>
              {recovering ? <>
                <h2 id="auth-title">Recover your account</h2>
                <p className="muted">Enter your account email. For privacy, we show the same confirmation whether or not an account exists.</p>
                <form onSubmit={submitRecovery}>
                  <label className="field-label" htmlFor="email">Email address</label>
                  <input id="email" type="email" autoComplete="email" required maxLength={254} value={email} onChange={e => setEmail(e.target.value)} />
                  <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? 'Please wait…' : 'Send recovery link'}</button>
                </form>
                <p className="muted"><button type="button" className="text-button" onClick={() => { setRecovering(false); setError(''); setNotice(''); }}>Back to sign in</button></p>
              </> : <>
                <form onSubmit={submitAuth}>
                  <label className="field-label" htmlFor="email">Email address</label>
                  <input id="email" type="email" autoComplete="email" required maxLength={254} value={email} onChange={e => setEmail(e.target.value)} />
                  <label className="field-label" htmlFor="password">Password</label>
                  <input id="password" type="password" autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} required minLength={12} maxLength={128} value={password} onChange={e => setPassword(e.target.value)} />
                  {mode === 'signin' && <>
                    <label className="field-label" htmlFor="mfa-code">Authenticator code or recovery code <span className="muted">(if enabled)</span></label>
                    <input id="mfa-code" type="text" inputMode="text" autoComplete="one-time-code" maxLength={64} value={mfaCode} onChange={e => setMfaCode(e.target.value)} />
                  </>}
                  <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? 'Please wait…' : mode === 'signin' ? 'Sign in securely' : 'Create account'}</button>
                </form>
                <p className="muted">{mode === 'signin' ? 'New to SATARK?' : 'Already have an account?'} <button type="button" className="text-button" onClick={() => { setMode(mode === 'signin' ? 'signup' : 'signin'); setError(''); setNotice(''); }}>{mode === 'signin' ? 'Create an account' : 'Sign in'}</button></p>
                {verificationPending && mode === 'signin' && <p className="muted"><button type="button" className="text-button" onClick={() => void resendVerification()} disabled={busy}>Resend verification email</button></p>}
              </>}
            </> : <>
              <div className="card-head"><span>Authenticated</span><span className="pill">Session active</span></div>
              <h2 id="auth-title">Your workspaces</h2>
              <p className="muted">Signed in as {session.user.email || session.user.id}</p>
              {mfaStatus?.required && !mfaStatus.enabled ? <p className="empty-state">Organization policy requires authenticator MFA before workspace data can be accessed. Complete setup below.</p> : <>
                {tenants.length ? <div className="workspace-list" aria-label="Available workspaces">
                  {tenants.map(tenant => <button type="button" className="workspace-choice" key={tenant.id} onClick={() => void chooseTenant(tenant)}>
                    <span><strong>{tenant.name}</strong><small>{tenant.role} · {tenant.id.slice(0, 8)}</small></span><span aria-hidden="true">→</span>
                  </button>)}
                </div> : <p className="empty-state">No workspace membership found yet. Create a workspace to begin.</p>}
                <form onSubmit={submitWorkspace} className="private-upload">
                  <label className="field-label" htmlFor="workspace">New workspace name</label>
                  <input id="workspace" required minLength={1} maxLength={160} value={workspaceName} onChange={e => setWorkspaceName(e.target.value)} placeholder="e.g. Incident Response Team" />
                  <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create workspace'}</button>
                </form>
                {tenants.some(tenant => tenant.role === 'owner') && <section className="info-panel" aria-labelledby="invite-title">
                <strong id="invite-title">Invite a teammate</strong>
                <p className="muted">Invite existing or new SATARK accounts by email. Invitations expire after seven days.</p>
                <form onSubmit={submitInvitation} className="private-upload">
                  <label className="field-label" htmlFor="invite-workspace">Workspace</label>
                  <select id="invite-workspace" value={inviteTenantId} onChange={e => void changeInviteTenant(e.target.value)}>
                    {tenants.filter(tenant => tenant.role === 'owner').map(tenant => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
                  </select>
                  <label className="field-label" htmlFor="invite-email">Email address</label>
                  <input id="invite-email" type="email" autoComplete="email" required maxLength={254} value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="teammate@example.com" />
                  <label className="field-label" htmlFor="invite-role">Workspace role</label>
                  <select id="invite-role" value={inviteRole} onChange={e => setInviteRole(e.target.value as 'responder' | 'analyst' | 'viewer')}>
                    <option value="responder">Responder</option>
                    <option value="analyst">Analyst</option>
                    <option value="viewer">Viewer</option>
                  </select>
                  <button className="btn btn-secondary" type="submit" disabled={busy || !inviteTenantId}>Send invitation</button>
                </form>
                {pendingInvitations.length > 0 && <>
                  <p><strong>Pending invitations</strong></p>
                  <ul className="workspace-list">
                    {pendingInvitations.map(invitation => <li key={invitation.id}>
                      <span><strong>{invitation.email}</strong><small>{invitation.role} · expires {new Date(invitation.expires_at).toLocaleDateString()}</small></span>
                      <button type="button" className="text-button" onClick={() => void cancelInvitation(invitation.id)} disabled={busy}>Revoke</button>
                    </li>)}
                  </ul>
                </>}
                </section>}
              </>}
              <button className="btn btn-secondary" type="button" onClick={() => void logout()} disabled={busy}>Sign out</button>

              <section className="info-panel" aria-labelledby="mfa-title">
                <strong id="mfa-title">Account security · Authenticator MFA</strong>
                {mfaStatus?.enabled ? <>
                  <p className="muted">MFA is enabled. {mfaStatus.recovery_codes_remaining} recovery codes remain.</p>
                  <form onSubmit={turnOffMfa} className="private-upload">
                    <label className="field-label" htmlFor="mfa-disable-password">Confirm your password</label>
                    <input id="mfa-disable-password" type="password" autoComplete="current-password" minLength={12} maxLength={128} required value={mfaDisablePassword} onChange={e => setMfaDisablePassword(e.target.value)} />
                    <label className="field-label" htmlFor="mfa-disable-code">Authenticator or unused recovery code</label>
                    <input id="mfa-disable-code" autoComplete="one-time-code" maxLength={64} required value={mfaDisableCode} onChange={e => setMfaDisableCode(e.target.value)} />
                    <button className="btn btn-secondary" type="submit" disabled={busy}>Disable MFA and revoke sessions</button>
                  </form>
                </> : mfaSecret ? <>
                  <p className="muted">Enter this setup key in your authenticator app. Keep it private.</p>
                  <code>{mfaSecret}</code>
                  <p className="muted">Or use this provisioning URI in an authenticator that supports manual URI import:</p>
                  <p className="muted"><code>{mfaOtpUri}</code></p>
                  <form onSubmit={finishMfaEnrollment} className="private-upload">
                    <label className="field-label" htmlFor="mfa-enroll-code">Six-digit authenticator code</label>
                    <input id="mfa-enroll-code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required value={mfaEnrollCode} onChange={e => setMfaEnrollCode(e.target.value)} />
                    <button className="btn btn-primary" type="submit" disabled={busy}>Confirm and enable MFA</button>
                  </form>
                </> : <>
                  <p className="muted">Add a time-based authenticator and save one-time recovery codes. The server encrypts the shared secret at rest.</p>
                  <button className="btn btn-secondary" type="button" onClick={() => void beginMfaEnrollment()} disabled={busy}>Set up authenticator MFA</button>
                </>}
                {mfaRecoveryCodes.length > 0 && <div role="status">
                  <p><strong>Save these recovery codes now. Each code works once.</strong></p>
                  <ul>{mfaRecoveryCodes.map(code => <li key={code}><code>{code}</code></li>)}</ul>
                </div>}
              </section>
            </>}
            {error && <p className="error-message" role="alert">{error}</p>}
            {notice && <p className="success-message" role="status">{notice}</p>}
          </section>
        </section>
      </main>
    </div>
  );
}
