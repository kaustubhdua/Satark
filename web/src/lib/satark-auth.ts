const SESSION_KEY = 'satark:auth-session:v1';
const TENANT_KEY = 'satark:active-tenant:v1';

export type SatarkSession = {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  user: { id: string; email?: string };
};

export type SatarkTenant = { id: string; name: string; role: string };

function config() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || '';
  if (!url || !key) throw new Error('Sign-in is not configured. Contact the SATARK administrator.');
  return { url: url.replace(/\/$/, ''), key };
}

function saveSession(value: unknown): SatarkSession {
  if (!value || typeof value !== 'object') throw new Error('Authentication returned an invalid session.');
  const raw = value as Record<string, unknown>;
  if (typeof raw.access_token !== 'string' || typeof raw.refresh_token !== 'string' ||
      !raw.user || typeof raw.user !== 'object' || typeof (raw.user as Record<string, unknown>).id !== 'string') {
    throw new Error('Authentication did not return a complete session.');
  }
  const session: SatarkSession = {
    access_token: raw.access_token,
    refresh_token: raw.refresh_token,
    expires_at: Date.now() + Math.max(0, Number(raw.expires_in || 3600)) * 1000,
    user: raw.user as SatarkSession['user'],
  };
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  return session;
}

export function readStoredSession(): SatarkSession | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw) as SatarkSession;
    if (!value.access_token || !value.refresh_token || !value.user?.id) return null;
    return value;
  } catch {
    return null;
  }
}

export function clearSession() {
  if (typeof window !== 'undefined') {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(TENANT_KEY);
  }
}

async function authRequest(path: string, body: Record<string, unknown>) {
  const { url, key } = config();
  const response = await fetch(url + '/auth/v1/' + path, {
    method: 'POST',
    headers: { apikey: key, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-store',
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof data.msg === 'string' ? data.msg : typeof data.message === 'string' ? data.message :
      typeof data.error_description === 'string' ? data.error_description : 'Authentication failed. Check your details and try again.';
    throw new Error(message);
  }
  return data;
}

export async function signIn(email: string, password: string) {
  return saveSession(await authRequest('token?grant_type=password', { email, password }));
}

export async function signUp(email: string, password: string) {
  const data = await authRequest('signup', { email, password });
  if (data.access_token && data.refresh_token) return { session: saveSession(data), confirmationRequired: false };
  return { session: null, confirmationRequired: true };
}

export async function getSession(): Promise<SatarkSession | null> {
  if (typeof window === 'undefined') return null;
  const current = readStoredSession();
  if (!current) return null;
  if (current.expires_at > Date.now() + 60_000) return current;
  try {
    const refreshed = await authRequest('token?grant_type=refresh_token', { refresh_token: current.refresh_token });
    return saveSession(refreshed);
  } catch {
    clearSession();
    return null;
  }
}

export async function signOut() {
  const session = await getSession();
  if (session) {
    const { url, key } = config();
    await fetch(url + '/auth/v1/logout', {
      method: 'POST',
      headers: { apikey: key, Authorization: 'Bearer ' + session.access_token },
      cache: 'no-store',
    }).catch(() => undefined);
  }
  clearSession();
}

export async function authenticatedFetch(path: string, init: RequestInit = {}) {
  const session = await getSession();
  if (!session) throw new Error('Your session expired. Sign in again.');
  const { url, key } = config();
  const headers = new Headers(init.headers);
  headers.set('apikey', key);
  headers.set('Authorization', 'Bearer ' + session.access_token);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(url + path, { ...init, headers, cache: 'no-store' });
  if (response.status === 401) {
    clearSession();
    throw new Error('Your session expired. Sign in again.');
  }
  return response;
}

export async function createTenant(name: string): Promise<string> {
  const response = await authenticatedFetch('/rest/v1/rpc/satark_create_tenant', {
    method: 'POST', body: JSON.stringify({ tenant_name: name }),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || typeof data !== 'string') {
    throw new Error('Workspace could not be created. Check Supabase Auth and database configuration.');
  }
  localStorage.setItem(TENANT_KEY, data);
  return data;
}

export function getActiveTenant() {
  return typeof window === 'undefined' ? null : localStorage.getItem(TENANT_KEY);
}

export function setActiveTenant(id: string) {
  localStorage.setItem(TENANT_KEY, id);
}

export async function listMyTenants(): Promise<SatarkTenant[]> {
  const membershipsResponse = await authenticatedFetch('/rest/v1/satark_memberships?select=tenant_id,role&order=created_at.asc');
  if (!membershipsResponse.ok) throw new Error('Could not load workspace memberships.');
  const memberships = await membershipsResponse.json() as { tenant_id: string; role: string }[];
  if (!memberships.length) return [];
  const ids = memberships.map(item => item.tenant_id);
  const query = new URLSearchParams({ select: 'id,name', id: 'in.(' + ids.join(',') + ')' });
  const tenantsResponse = await authenticatedFetch('/rest/v1/satark_tenants?' + query.toString());
  if (!tenantsResponse.ok) throw new Error('Could not load workspaces.');
  const tenants = await tenantsResponse.json() as { id: string; name: string }[];
  return tenants.map(tenant => ({ ...tenant, role: memberships.find(item => item.tenant_id === tenant.id)?.role || 'viewer' }));
}

export async function listCases(tenantId: string) {
  const session = await getSession();
  if (!session) throw new Error('Sign in again to load saved cases.');
  const response = await fetch('/api/cases?tenant_id=' + encodeURIComponent(tenantId), {
    headers: { Authorization: 'Bearer ' + session.access_token }, cache: 'no-store',
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Could not load cases.');
  return Array.isArray(data.cases) ? data.cases : [];
}

export async function createCase(tenantId: string, title: string, severity = 'unknown') {
  const session = await getSession();
  if (!session) throw new Error('Your session expired. Sign in again.');
  const response = await fetch('/api/cases', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant_id: tenantId, title, severity }),
    cache: 'no-store',
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Could not create case.');
  return data.case;
}
