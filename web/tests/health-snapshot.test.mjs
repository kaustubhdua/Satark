import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHealthSnapshot, describeRateLimitStatus } from '../src/lib/health-snapshot.mjs';

test('health snapshot never claims full readiness', () => {
  const snapshot = buildHealthSnapshot({});
  assert.equal(snapshot.status, 'configuration-only');
  assert.equal(snapshot.checks.analysis.mode, 'deterministic-local');
  assert.equal(snapshot.checks.analysis.configured, true);
  assert.equal(snapshot.checks.localModel.configured, false);
  assert.equal(snapshot.checks.persistentStorage.configured, false);
  assert.equal(snapshot.checks.rateLimit.mode, 'in-process');
  assert.equal(snapshot.checks.rateLimit.sharedAcrossInstances, false);
  assert.match(snapshot.note, /does not probe model, database, Redis, or FIRSTLIGHT API connectivity/i);
});

test('local self-hosted API is reported without exposing connection details', () => {
  const snapshot = buildHealthSnapshot({ SATARK_API_INTERNAL_URL: 'http://firstlight-api:8788' });
  assert.equal(snapshot.checks.persistentStorage.provider, 'self-hosted');
  assert.equal(snapshot.checks.persistentStorage.configured, true);
  assert.equal(snapshot.checks.persistentStorage.clientConfigured, false);
  assert.equal(snapshot.checks.persistentStorage.serverClientMatch, false);
  assert.doesNotMatch(JSON.stringify(snapshot), /firstlight-api|SATARK_DATABASE_URL/);
});

test('invalid or missing self-hosted API configuration is not reported as configured', () => {
  for (const url of ['', 'not-a-url', 'http://untrusted.example.com', 'https://user:password@example.com']) {
    const snapshot = buildHealthSnapshot({ SATARK_API_INTERNAL_URL: url });
    assert.equal(snapshot.checks.persistentStorage.configured, false);
  }
});

test('optional local model requires both URL and model', () => {
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: 'http://localhost:11434' }).checks.localModel.configured, false);
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_MODEL: 'local-model' }).checks.localModel.configured, false);
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: 'http://localhost:11434', SATARK_OLLAMA_MODEL: 'local-model' }).checks.localModel.configured, true);
});

test('FIRSTLIGHT integrations require safe URLs and strong server-side tokens', () => {
  const missing = buildHealthSnapshot({});
  assert.deepEqual(missing.checks.firstlight, { investigationProxyConfigured: false, wazuhProxyConfigured: false });
  const configured = buildHealthSnapshot({
    FIRSTLIGHT_API_URL: 'https://firstlight.internal.example',
    FIRSTLIGHT_API_TOKEN: 'a'.repeat(32),
    FIRSTLIGHT_WAZUH_SYNC_TOKEN: 'b'.repeat(32),
  });
  assert.deepEqual(configured.checks.firstlight, { investigationProxyConfigured: true, wazuhProxyConfigured: true });
  for (const url of ['http://firstlight.example.com', 'https://user:pass@firstlight.example.com', 'https://firstlight.example.com?token=leak']) {
    const unsafe = buildHealthSnapshot({ FIRSTLIGHT_API_URL: url, FIRSTLIGHT_API_TOKEN: 'a'.repeat(32), FIRSTLIGHT_WAZUH_SYNC_TOKEN: 'b'.repeat(32) });
    assert.equal(unsafe.checks.firstlight.investigationProxyConfigured, false);
    assert.equal(unsafe.checks.firstlight.wazuhProxyConfigured, false);
  }
});

test('production health marks shared limiting as a hard requirement', () => {
  const missing = buildHealthSnapshot({ VERCEL: '1' });
  assert.equal(missing.checks.rateLimit.mode, 'shared-required');
  assert.equal(missing.checks.rateLimit.configured, false);
  const partial = buildHealthSnapshot({ VERCEL: '1', UPSTASH_REDIS_REST_URL: 'https://redis.example.com' });
  assert.equal(partial.checks.rateLimit.mode, 'misconfigured');
  assert.equal(partial.checks.rateLimit.configured, false);
});

test('shared rate limit configuration is reported without claiming connectivity', () => {
  const configured = buildHealthSnapshot({ UPSTASH_REDIS_REST_URL: 'https://redis.example.com', UPSTASH_REDIS_REST_TOKEN: 'test-token', VERCEL: '1' });
  assert.equal(configured.checks.rateLimit.mode, 'shared-upstash');
  assert.equal(configured.checks.rateLimit.configured, true);
  assert.equal(configured.checks.rateLimit.sharedAcrossInstances, true);
  assert.equal(configured.checks.rateLimit.connectivityVerified, false);
});

test('rate-limit status copy distinguishes production and local modes', () => {
  assert.match(describeRateLimitStatus(buildHealthSnapshot({ VERCEL: '1' }).checks.rateLimit), /production analysis is disabled and fails closed/i);
  assert.match(describeRateLimitStatus(buildHealthSnapshot({}).checks.rateLimit), /process-local, not shared/i);
});
