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
  return { access_token: '', refresh_token: '', expires_at: Date.now() + 14 * 86400_000, user };
}

export function readStoredSession(): SatarkSession | null {
  return currentSession;
}

export function clearSession() {
  currentSession = null;
  if (typeof window !== 'undefined') localStorage.removeItem(TENANT_KEY);
}

export async function signIn(email: string, password: string) {
  const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email: email.trim(), password }) });
  currentSession = sessionFrom(result);
  return currentSession;
}

export async function signUp(email: string, password: string) {
  const result = await api('/api/auth/signup', { method: 'POST', body: JSON.stringify({ email: email.trim(), password }) });
  currentSession = sessionFrom(result);
  return { session: currentSession, confirmationRequired: false };
}

export async function requestPasswordReset(_email: string, _redirectTo: string) {
  throw new Error('Password recovery is not enabled on this self-hosted deployment. Ask the workspace administrator to initiate the verified recovery procedure.');
}

export async function completePasswordReset(_accessToken: string, _password: string) {
  throw new Error('Password recovery is not enabled on this self-hosted deployment.');
}

export async function getSession(): Promise<SatarkSession | null> {
  try {
    currentSession = sessionFrom(await api('/api/auth/session'));
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
