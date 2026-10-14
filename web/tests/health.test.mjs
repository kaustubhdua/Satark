import test from 'node:test';
import assert from 'node:assert/strict';

test('production readiness endpoint exposes only boolean configuration diagnostics', async () => {
  const response = await fetch((process.env.SATARK_WEB_URL || 'http://127.0.0.1:3000') + '/api/health', {
    headers: { Accept: 'application/json' },
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('cache-control') || '', /no-store/);
  const body = await response.json();
  assert.ok(['ready', 'degraded'].includes(body.status));
  for (const key of ['analysisProvider', 'sharedRateLimit', 'urlhaus', 'abuseIpDb', 'persistentStorage']) {
    assert.ok(body.checks[key], 'missing diagnostic: ' + key);
  }
  assert.equal(typeof body.checks.analysisProvider.configured, 'boolean');
  assert.equal(typeof body.checks.sharedRateLimit.configured, 'boolean');
  assert.equal(typeof body.checks.urlhaus.enabled, 'boolean');
  assert.equal(typeof body.checks.urlhaus.configured, 'boolean');
  assert.equal(typeof body.checks.abuseIpDb.enabled, 'boolean');
  assert.equal(typeof body.checks.abuseIpDb.configured, 'boolean');
  assert.equal(typeof body.checks.persistentStorage.configured, 'boolean');
  assert.equal(JSON.stringify(body).includes('GROQ_API_KEY'), false);
  assert.equal(JSON.stringify(body).includes('URLHAUS_AUTH_KEY'), false);
  assert.equal(JSON.stringify(body).includes('ABUSEIPDB_API_KEY'), false);
});
