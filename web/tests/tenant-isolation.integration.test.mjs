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

test('tenant RLS blocks cross-tenant case queries and writes for two distinct users', { skip: configured ? false : 'Set up two non-admin Supabase test users and separate tenant IDs; missing: ' + missing.join(', ') }, async () => {
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

const fixtureRequired = [
  ...required,
  'SATARK_TEST_CASE_A_ID',
  'SATARK_TEST_CASE_B_ID',
  'SATARK_TEST_EVIDENCE_B_ID',
  'SATARK_TEST_FINDING_B_ID',
  'SATARK_TEST_REPORT_B_ID',
  'SATARK_TEST_STORAGE_OBJECT_B_PATH',
];
const fixtureMissing = fixtureRequired.filter(key => !env[key]);

async function fixtureRows(session, table, id, tenantId, withCase = false) {
  const query = new URLSearchParams({
    select: withCase ? 'id,tenant_id,case_id' : 'id,tenant_id',
    id: 'eq.' + id,
    tenant_id: 'eq.' + tenantId,
    limit: '2',
  });
  const response = await rest(session, table + '?' + query);
  assert.equal(response.status, 200, table + ' fixture query must succeed');
  const rows = await response.json();
  assert.ok(Array.isArray(rows), table + ' query must return a row list');
  return rows;
}

async function storageObject(session, objectPath) {
  const encodedPath = objectPath.split('/').map(encodeURIComponent).join('/');
  return fetch(base + '/storage/v1/object/satark-evidence/' + encodedPath, {
    headers: { apikey: apiKey, Authorization: 'Bearer ' + session.token },
    cache: 'no-store',
    redirect: 'error',
  });
}

test('seeded tenant fixtures prove isolation for cases, evidence, findings, reports and private storage', {
  skip: fixtureMissing.length ? 'Seed synthetic tenant fixtures and configure dedicated non-production accounts; missing: ' + fixtureMissing.join(', ') : false,
}, async () => {
  assert.notEqual(env.SATARK_TEST_TENANT_A_ID, env.SATARK_TEST_TENANT_B_ID, 'fixture tenants must be distinct');
  assert.ok(env.SATARK_TEST_STORAGE_OBJECT_B_PATH && !env.SATARK_TEST_STORAGE_OBJECT_B_PATH.startsWith('/'), 'storage fixture path must be relative to the private bucket');
  assert.ok(!env.SATARK_TEST_STORAGE_OBJECT_B_PATH.split('/').some(part => !part || part === '.' || part === '..'), 'storage fixture path must not contain empty or traversal segments');

  const [a, b] = await Promise.all([
    login(env.SATARK_TEST_USER_A_EMAIL, env.SATARK_TEST_USER_A_PASSWORD),
    login(env.SATARK_TEST_USER_B_EMAIL, env.SATARK_TEST_USER_B_PASSWORD),
  ]);
  assert.notEqual(a.userId, b.userId, 'fixture users must be distinct');

  const ownA = await fixtureRows(a, 'satark_cases', env.SATARK_TEST_CASE_A_ID, env.SATARK_TEST_TENANT_A_ID);
  const ownB = await fixtureRows(b, 'satark_cases', env.SATARK_TEST_CASE_B_ID, env.SATARK_TEST_TENANT_B_ID);
  assert.equal(ownA.length, 1, 'user A must read its seeded case');
  assert.equal(ownB.length, 1, 'user B must read its seeded case');
  assert.equal((await fixtureRows(a, 'satark_cases', env.SATARK_TEST_CASE_B_ID, env.SATARK_TEST_TENANT_B_ID)).length, 0, 'user A must not read user B case');
  assert.equal((await fixtureRows(b, 'satark_cases', env.SATARK_TEST_CASE_A_ID, env.SATARK_TEST_TENANT_A_ID)).length, 0, 'user B must not read user A case');

  const relatedFixtures = [
    ['satark_evidence', env.SATARK_TEST_EVIDENCE_B_ID],
    ['satark_findings', env.SATARK_TEST_FINDING_B_ID],
    ['satark_reports', env.SATARK_TEST_REPORT_B_ID],
  ];
  for (const [table, id] of relatedFixtures) {
    const own = await fixtureRows(b, table, id, env.SATARK_TEST_TENANT_B_ID, true);
    assert.equal(own.length, 1, table + ' fixture must be readable by its tenant member');
    assert.equal(own[0].case_id, env.SATARK_TEST_CASE_B_ID, table + ' fixture must belong to tenant B case');
    const foreign = await fixtureRows(a, table, id, env.SATARK_TEST_TENANT_B_ID, true);
    assert.deepEqual(foreign, [], 'user A must not read tenant B ' + table);
  }

  const ownObject = await storageObject(b, env.SATARK_TEST_STORAGE_OBJECT_B_PATH);
  assert.equal(ownObject.status, 200, 'tenant B must download its seeded synthetic evidence object');
  await ownObject.arrayBuffer();
  const foreignObject = await storageObject(a, env.SATARK_TEST_STORAGE_OBJECT_B_PATH);
  assert.ok([400, 403, 404].includes(foreignObject.status), 'tenant A must not download tenant B private evidence object');
  await foreignObject.arrayBuffer();
});

const viewerRequired = ['SUPABASE_URL','SUPABASE_PUBLISHABLE_KEY','SATARK_TEST_VIEWER_EMAIL','SATARK_TEST_VIEWER_PASSWORD','SATARK_TEST_VIEWER_TENANT_ID','SATARK_TEST_VIEWER_CASE_ID'];
const viewerMissing = viewerRequired.filter(key => !env[key]);
test('viewer role cannot create or update cases', { skip: viewerMissing.length ? 'Set up a dedicated viewer test account; missing: ' + viewerMissing.join(', ') : false }, async () => {
  const viewer = await login(env.SATARK_TEST_VIEWER_EMAIL, env.SATARK_TEST_VIEWER_PASSWORD);
  const tenantId = env.SATARK_TEST_VIEWER_TENANT_ID;
  const visibleCase = await fixtureRows(viewer, 'satark_cases', env.SATARK_TEST_VIEWER_CASE_ID, tenantId);
  assert.equal(visibleCase.length, 1, 'viewer must read its seeded case');
  const create = await rest(viewer, 'satark_cases', {
    method: 'POST', headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ tenant_id: tenantId, title: 'Viewer permission integration probe', status: 'open', severity: 'unknown', created_by: viewer.userId, metadata: { test_probe: true } }),
  });
  assert.ok(!create.ok, 'viewer must not create cases');
  const listQuery = new URLSearchParams({ select:'id',tenant_id:'eq.'+tenantId,limit:'1' });
  const listed = await rest(viewer, 'satark_cases?' + listQuery);
  assert.equal(listed.status, 200);
  const rows = await listed.json();
  if (rows.length) {
    const update = await rest(viewer, 'satark_cases?id=eq.'+rows[0].id+'&tenant_id=eq.'+tenantId, {
      method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({status:'resolved'}),
    });
    assert.ok(!update.ok || (await update.json()).length===0, 'viewer must not update cases');
  }
});
