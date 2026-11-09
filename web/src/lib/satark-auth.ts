const TENANT_KEY = 'satark:active-tenant:v1';

export type SatarkSession = {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  user: { id: string; email?: string };
};

export type SatarkTenant = { id: string; name: string; role: string };
let currentSession: SatarkSession | null = null;

async function api(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, headers, cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = payload && typeof payload.error === 'string' ? payload.error :
      payload && typeof payload.detail === 'string' ? payload.detail : 'The SATARK service could not complete this request.';
    throw new Error(message);
  }
  return payload;
}

function sessionFrom(value: unknown): SatarkSession {
  if (!value || typeof value !== 'object' || !('user' in value) || !value.user ||
      typeof value.user !== 'object' || !('id' in value.user) || typeof value.user.id !== 'string') {
    throw new Error('The SATARK server returned an invalid session.');
  }
  const user = value.user as SatarkSession['user'];
  const serverExpiry = 'expires_at' in value && typeof value.expires_at === 'string'
    ? Date.parse(value.expires_at)
    : Number.NaN;
  const relativeExpiry = 'expires_in' in value && typeof value.expires_in === 'number'
    ? Date.now() + Math.max(0, value.expires_in) * 1000
    : Number.NaN;
  const expiresAt = Number.isFinite(serverExpiry) ? serverExpiry
    : Number.isFinite(relativeExpiry) ? relativeExpiry : Date.now();
  return { access_token: '', refresh_token: '', expires_at: expiresAt, user };
}

export function readStoredSession(): SatarkSession | null {
  return currentSession;
}

export function clearSession() {
  currentSession = null;
  if (typeof window !== 'undefined') localStorage.removeItem(TENANT_KEY);
}

export async function signIn(email: string, password: string, mfaCode = '') {
  const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email: email.trim(), password, ...(mfaCode ? { mfa_code: mfaCode.trim() } : {}) }) });
  currentSession = sessionFrom(result);
  return currentSession;
}

export async function signUp(email: string, password: string) {
  const result = await api('/api/auth/signup', { method: 'POST', body: JSON.stringify({ email: email.trim(), password }) });
  if (result && result.verification_required === true) {
    currentSession = null;
    return { session: null, confirmationRequired: true };
  }
  currentSession = sessionFrom(result);
  return { session: currentSession, confirmationRequired: false };
}

export async function sendWorkspaceInvitation(tenantId: string, email: string, role: string) {
  return api('/api/workspaces/invitations', {
    method: 'POST', body: JSON.stringify({ tenant_id: tenantId, email: email.trim(), role }),
  });
}

export async function listWorkspaceInvitations(tenantId: string): Promise<Array<{ id: string; email: string; role: string; expires_at: string }>> {
  const result = await api('/api/workspaces/invitations?tenant_id=' + encodeURIComponent(tenantId));
  return Array.isArray(result.invitations) ? result.invitations : [];
}

export async function revokeWorkspaceInvitation(tenantId: string, invitationId: string) {
  return api('/api/workspaces/invitations?tenant_id=' + encodeURIComponent(tenantId) +
    '&invitation_id=' + encodeURIComponent(invitationId), { method: 'DELETE' });
}

export async function acceptWorkspaceInvitation(token: string) {
  return api('/api/workspaces/invitations/accept', {
    method: 'POST', body: JSON.stringify({ token }),
  });
}

export async function getMfaStatus(): Promise<{ enabled: boolean; required: boolean; recovery_codes_remaining: number }> {
  const result = await api('/api/auth/mfa/status');
  return { enabled: result.enabled === true, required: result.required === true, recovery_codes_remaining: Number(result.recovery_codes_remaining) || 0 };
}

export async function startMfaEnrollment(): Promise<{ secret: string; otpauth_uri: string }> {
  return api('/api/auth/mfa/enroll/start', { method: 'POST' });
}

export async function confirmMfaEnrollment(code: string): Promise<{ enabled: boolean; recovery_codes: string[] }> {
  return api('/api/auth/mfa/enroll/confirm', { method: 'POST', body: JSON.stringify({ code }) });
}

export async function disableMfa(password: string, code: string) {
  return api('/api/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ password, code }) });
}

export async function requestEmailVerification(email: string) {
  return api('/api/auth/email-verification/request', {
    method: 'POST', body: JSON.stringify({ email: email.trim() }),
  });
}

export async function completeEmailVerification(token: string) {
  return api('/api/auth/email-verification/complete', {
    method: 'POST', body: JSON.stringify({ token }),
  });
}

export async function requestPasswordReset(email: string, _redirectTo: string) {
  return api('/api/auth/password-reset/request', {
    method: 'POST', body: JSON.stringify({ email: email.trim() }),
  });
}

export async function completePasswordReset(token: string, password: string) {
  return api('/api/auth/password-reset/complete', {
    method: 'POST', body: JSON.stringify({ token, password }),
  });
}

export async function getSession(): Promise<SatarkSession | null> {
  try {
    let session = sessionFrom(await api('/api/auth/session'));
    // Rotate near-expiry sessions server-side. The raw cookie remains HttpOnly;
    // the browser never receives or stores a bearer/refresh token.
    if (session.expires_at - Date.now() < 24 * 60 * 60 * 1000) {
      session = sessionFrom(await api('/api/auth/refresh', { method: 'POST' }));
    }
    currentSession = session;
    return currentSession;
  } catch {
    currentSession = null;
    return null;
  }
}

export async function signOut() {
  try { await api('/api/auth/logout', { method: 'POST' }); } finally { clearSession(); }
}

export async function authenticatedFetch(path: string, init: RequestInit = {}) {
  if (!path.startsWith('/api/')) throw new Error('Use a SATARK same-origin API endpoint.');
  try { return await fetch(path, { ...init, cache: 'no-store', credentials: 'same-origin', redirect: 'error' }); }
  catch { throw new Error('The SATARK backend is unavailable.'); }
}

export async function createTenant(name: string): Promise<string> {
  const result = await api('/api/workspaces', { method: 'POST', body: JSON.stringify({ name }) });
  if (typeof result.id !== 'string') throw new Error('The workspace could not be created.');
  localStorage.setItem(TENANT_KEY, result.id);
  return result.id;
}

export function getActiveTenant() {
  return typeof window === 'undefined' ? null : localStorage.getItem(TENANT_KEY);
}

export function setActiveTenant(id: string) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('Invalid workspace identifier.');
  localStorage.setItem(TENANT_KEY, id);
}

export async function listMyTenants(): Promise<SatarkTenant[]> {
  const result = await api('/api/workspaces');
  return Array.isArray(result.workspaces) ? result.workspaces : [];
}

export async function listCases(tenantId: string) {
  const result = await api('/api/cases?tenant_id=' + encodeURIComponent(tenantId));
  return Array.isArray(result.cases) ? result.cases : [];
}

export async function createCase(tenantId: string, title: string, severity = 'unknown') {
  const result = await api('/api/cases', { method: 'POST', body: JSON.stringify({ tenant_id: tenantId, title, severity }) });
  return result.case;
}
