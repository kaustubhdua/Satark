import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCapabilityRegistry } from '../src/lib/capability-registry.mjs';

const byId = (registry, id) => registry.capabilities.find(item => item.id === id);

test('missing integrations are disabled and never healthy', () => {
  const registry = buildCapabilityRegistry({});
  assert.equal(registry.productionReady, false);
  assert.equal(registry.healthProbesRun, false);
  for (const id of ['storage.self_hosted', 'ai.local_model', 'telemetry.wazuh', 'response.live']) {
    assert.equal(byId(registry, id).status, 'disabled');
  }
  assert.ok(registry.capabilities.every(item => item.status !== 'healthy'));
});

test('configured integrations remain unverified until real probes exist', () => {
  const registry = buildCapabilityRegistry({
    SATARK_API_INTERNAL_URL: 'https://satark.internal.example',
    UPSTASH_REDIS_REST_URL: 'https://redis.example.com',
    UPSTASH_REDIS_REST_TOKEN: 'private-token',
    SATARK_OLLAMA_BASE_URL: 'http://localhost:11434',
    SATARK_OLLAMA_MODEL: 'local-model',
    FIRSTLIGHT_WAZUH_INDEXER_URL: 'https://wazuh.internal.example',
    FIRSTLIGHT_WAZUH_INDEXER_USERNAME: 'readonly',
    FIRSTLIGHT_WAZUH_INDEXER_PASSWORD: 'private-token',
    FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS: '004,005',
  });
  for (const id of ['storage.self_hosted', 'rate_limit.shared', 'ai.local_model', 'firstlight.investigation', 'telemetry.wazuh']) {
    assert.equal(byId(registry, id).status, 'configured');
    assert.equal(byId(registry, id).healthVerified, false);
  }
  assert.doesNotMatch(JSON.stringify(registry), /private-token|readonly|satark\.internal|wazuh\.internal/i);
});

test('unsafe self-hosted API URLs are disabled', () => {
  const registry = buildCapabilityRegistry({ SATARK_API_INTERNAL_URL: 'http://untrusted.example' });
  assert.equal(byId(registry, 'storage.self_hosted').status, 'disabled');
  assert.equal(byId(registry, 'firstlight.investigation').status, 'disabled');
});

test('production without a shared limiter is disabled and not ready', () => {
  const registry = buildCapabilityRegistry({ VERCEL: '1' });
  assert.equal(byId(registry, 'rate_limit.shared').status, 'disabled');
  assert.equal(registry.productionReady, false);
  assert.match(byId(registry, 'rate_limit.shared').details, /fail closed/i);
});

test('rule code is explicitly unverified for live detection', () => {
  const registry = buildCapabilityRegistry({});
  assert.equal(byId(registry, 'detection.rules').status, 'unverified');
  assert.equal(byId(registry, 'detection.rules').healthVerified, false);
});
