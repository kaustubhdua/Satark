import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHealthSnapshot } from '../src/lib/health-snapshot.mjs';

test('health snapshot never claims full readiness and exposes non-shared rate limiting', () => {
  const snapshot = buildHealthSnapshot({});
  assert.equal(snapshot.status, 'configuration-only');
  assert.equal(snapshot.checks.analysis.mode, 'deterministic-local');
  assert.equal(snapshot.checks.analysis.configured, true);
  assert.equal(snapshot.checks.localModel.configured, false);
  assert.equal(snapshot.checks.persistentStorage.configured, false);
  assert.equal(snapshot.checks.rateLimit.sharedAcrossInstances, false);
  assert.match(snapshot.note, /does not probe model or database connectivity/i);
});

test('optional model and persistent storage require complete configuration pairs', () => {
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: 'http://localhost:11434' }).checks.localModel.configured, false);
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_MODEL: 'local-model' }).checks.localModel.configured, false);
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: 'http://localhost:11434', SATARK_OLLAMA_MODEL: 'local-model' }).checks.localModel.configured, true);
  assert.equal(buildHealthSnapshot({ SUPABASE_URL: 'https://example.supabase.co' }).checks.persistentStorage.configured, false);
  assert.equal(buildHealthSnapshot({ SUPABASE_URL: 'https://example.supabase.co', SUPABASE_PUBLISHABLE_KEY: 'public-key' }).checks.persistentStorage.configured, true);
});

test('blank environment values count as missing', () => {
  const snapshot = buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: '  ', SATARK_OLLAMA_MODEL: 'model', SUPABASE_URL: 'url', SUPABASE_PUBLISHABLE_KEY: '' });
  assert.equal(snapshot.checks.localModel.configured, false);
  assert.equal(snapshot.checks.persistentStorage.configured, false);
});
