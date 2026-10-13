import test from 'node:test';
import assert from 'node:assert/strict';

const env = process.env;
const required = [
  'SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY',
  'SATARK_TEST_USER_A_EMAIL', 'SATARK_TEST_USER_A_PASSWORD', 'SATARK_TEST_TENANT_A_ID',
  'SATARK_TEST_USER_B_EMAIL', 'SATARK_TEST_USER_B_PASSWORD', 'SATARK_TEST_TENANT_B_ID',
];
const missing = required.filter(key => !env[key]);
const configured = missing.length === 0;
const base = (env.SUPABASE_URL || '').replace(/\/$/, '');
const apiKey = env.SUPABASE_PUBLISHABLE_KEY || '';

async function login(email, password) {
  const response = await fetch(base + '/auth/v1/token?grant_type=password', {
    method: 'POST',
    headers: { apikey: apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }), cache: 'no-store',
  });
  assert.equal(response.status, 200, 'test account must be able to sign in');
  const session = await response.json();
  assert.ok(session.access_token, 'Supabase Auth must return an access token');
  return { token: session.access_token, userId: session.user.id };
}

async function rest(session, path, init = {}) {
  return fetch(base + '/rest/v1/' + path, {
    ...init,
    headers: {
      apikey: apiKey,
      Authorization: 'Bearer ' + session.token,
      Accept: 'application/json',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
    cache: 'no-store',
  });
}

test('tenant RLS blocks cross-tenant reads and writes for two distinct users', { skip: configured ? false : 'Set up two non-admin Supabase test users and separate tenant IDs; missing: ' + missing.join(', ') }, async () => {
  assert.notEqual(env.SATARK_TEST_TENANT_A_ID, env.SATARK_TEST_TENANT_B_ID, 'test tenants must be distinct');
  const [a, b] = await Promise.all([
    login(env.SATARK_TEST_USER_A_EMAIL, env.SATARK_TEST_USER_A_PASSWORD),
    login(env.SATARK_TEST_USER_B_EMAIL, env.SATARK_TEST_USER_B_PASSWORD),
  ]);
  assert.notEqual(a.userId, b.userId, 'test users must be distinct');

  for (const [session, foreignTenant] of [[a, env.SATARK_TEST_TENANT_B_ID], [b, env.SATARK_TEST_TENANT_A_ID]]) {
    const query = new URLSearchParams({ select: 'id,tenant_id,title', tenant_id: 'eq.' + foreignTenant, limit: '20' });
    const read = await rest(session, 'satark_cases?' + query);
    assert.equal(read.status, 200, 'RLS should return an empty list instead of leaking foreign rows');
    assert.deepEqual(await read.json(), [], 'a user must not read another tenant’s cases');

    const write = await rest(session, 'satark_cases', {
      method: 'POST', headers: { Prefer: 'return=representation' },
      body: JSON.stringify({
        tenant_id: foreignTenant, title: 'SATARK isolated RLS integration probe',
        status: 'open', severity: 'unknown', created_by: session.userId, metadata: { test_probe: true },
      }),
    });
    assert.ok([401, 403, 409, 422].includes(write.status), 'foreign-tenant writes must be denied');
    if (write.ok) {
      const rows = await write.json();
      assert.equal(rows.length, 0, 'foreign-tenant write must not create a visible row');
    }
  }
});
