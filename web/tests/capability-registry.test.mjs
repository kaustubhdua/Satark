import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCapabilityRegistry } from '../src/lib/capability-registry.mjs';

const byId = (registry, id) => registry.capabilities.find(item => item.id === id);

test('missing integrations are disabled and never healthy', () => {
  const registry = buildCapabilityRegistry({});
  assert.equal(registry.productionReady, false);
  assert.equal(registry.healthProbesRun, false);
  for (const id of ['storage.supabase', 'ai.local_model', 'telemetry.wazuh', 'response.live']) {
    assert.equal(byId(registry, id).status, 'disabled');
  }
  assert.ok(registry.capabilities.every(item => item.status !== 'healthy'));
});

test('configured integrations remain unverified until real probes exist', () => {
  const registry = buildCapabilityRegistry({
    SUPABASE_URL: 'https://exampleproject1234567890.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'public-key',
    NEXT_PUBLIC_SUPABASE_URL: 'https://exampleproject1234567890.supabase.co',
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: 'public-key',
    UPSTASH_REDIS_REST_URL: 'https://redis.example.com',
    UPSTASH_REDIS_REST_TOKEN: 'private-token',
    SATARK_OLLAMA_BASE_URL: 'http://localhost:11434',
    SATARK_OLLAMA_MODEL: 'local-model',
    FIRSTLIGHT_API_URL: 'https://firstlight.internal.example',
    FIRSTLIGHT_API_TOKEN: 'a'.repeat(40),
    FIRSTLIGHT_WAZUH_SYNC_TOKEN: 'b'.repeat(40),
  });
  for (const id of ['storage.supabase', 'rate_limit.shared', 'ai.local_model', 'firstlight.investigation', 'telemetry.wazuh']) {
    assert.equal(byId(registry, id).status, 'configured');
    assert.equal(byId(registry, id).healthVerified, false);
  }
  assert.doesNotMatch(JSON.stringify(registry), /private-token|aaaaaaaa|bbbbbbbb|public-key/i);
});

test('mismatched Supabase projects are degraded', () => {
  const registry = buildCapabilityRegistry({
    SUPABASE_URL: 'https://exampleproject1234567890.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'server-key',
    NEXT_PUBLIC_SUPABASE_URL: 'https://anotherproject1234567890.supabase.co',
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: 'client-key',
  });
  assert.equal(byId(registry, 'storage.supabase').status, 'degraded');
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
