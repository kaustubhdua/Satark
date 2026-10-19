import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHealthSnapshot, describeRateLimitStatus } from '../src/lib/health-snapshot.mjs';

test('health snapshot never claims full readiness and exposes non-shared rate limiting', () => {
  const snapshot = buildHealthSnapshot({});
  assert.equal(snapshot.status, 'configuration-only');
  assert.equal(snapshot.checks.analysis.mode, 'deterministic-local');
  assert.equal(snapshot.checks.analysis.configured, true);
  assert.equal(snapshot.checks.localModel.configured, false);
  assert.equal(snapshot.checks.persistentStorage.configured, false);
  assert.equal(snapshot.checks.rateLimit.sharedAcrossInstances, false);
  assert.equal(snapshot.checks.rateLimit.mode, 'in-process');
  assert.equal(snapshot.checks.rateLimit.configured, true);
  assert.equal(snapshot.checks.rateLimit.connectivityVerified, false);
  assert.match(snapshot.note, /does not probe model, database, or Redis connectivity/i);
});

test('production health accurately marks shared limiting as a hard requirement', () => {
  const snapshot = buildHealthSnapshot({ VERCEL: '1' });
  assert.equal(snapshot.checks.rateLimit.mode, 'shared-required');
  assert.equal(snapshot.checks.rateLimit.configured, false);
  assert.equal(snapshot.checks.rateLimit.sharedAcrossInstances, false);
  const partial = buildHealthSnapshot({ VERCEL: '1', UPSTASH_REDIS_REST_URL: 'https://redis.example.com' });
  assert.equal(partial.checks.rateLimit.mode, 'misconfigured');
  assert.equal(partial.checks.rateLimit.configured, false);
});

test('optional model and persistent storage require complete configuration pairs', () => {
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: 'http://localhost:11434' }).checks.localModel.configured, false);
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_MODEL: 'local-model' }).checks.localModel.configured, false);
  assert.equal(buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: 'http://localhost:11434', SATARK_OLLAMA_MODEL: 'local-model' }).checks.localModel.configured, true);
  assert.equal(buildHealthSnapshot({ SUPABASE_URL: 'https://example.supabase.co' }).checks.persistentStorage.configured, false);
  assert.equal(buildHealthSnapshot({ SUPABASE_URL: 'https://example.supabase.co', SUPABASE_PUBLISHABLE_KEY: 'public-key' }).checks.persistentStorage.configured, true);
});

test('Supabase mapping confirms browser/server project equality without exposing URLs or keys', () => {
  const snapshot = buildHealthSnapshot({
    SUPABASE_URL: 'https://igqgtlmnwssjaoxkkzbm.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'server-publishable-key',
    NEXT_PUBLIC_SUPABASE_URL: 'https://igqgtlmnwssjaoxkkzbm.supabase.co',
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: 'browser-publishable-key',
  });
  assert.equal(snapshot.checks.persistentStorage.configured, true);
  assert.equal(snapshot.checks.persistentStorage.clientConfigured, true);
  assert.equal(snapshot.checks.persistentStorage.serverClientMatch, true);
  assert.equal(snapshot.checks.persistentStorage.serverProjectRef, 'igqgtlmnwssjaoxkkzbm');
  assert.equal(snapshot.checks.persistentStorage.clientProjectRef, 'igqgtlmnwssjaoxkkzbm');
  const serialized = JSON.stringify(snapshot);
  assert.doesNotMatch(serialized, /https:\/\//i);
  assert.doesNotMatch(serialized, /publishable-key/i);
});

test('Supabase mapping reports mismatched browser and server projects', () => {
  const snapshot = buildHealthSnapshot({
    SUPABASE_URL: 'https://igqgtlmnwssjaoxkkzbm.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'server-publishable-key',
    NEXT_PUBLIC_SUPABASE_URL: 'https://ogbanmjokjlxfuktkicj.supabase.co',
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: 'browser-publishable-key',
  });
  assert.equal(snapshot.checks.persistentStorage.configured, true);
  assert.equal(snapshot.checks.persistentStorage.clientConfigured, true);
  assert.equal(snapshot.checks.persistentStorage.serverClientMatch, false);
  assert.equal(snapshot.checks.persistentStorage.serverProjectRef, 'igqgtlmnwssjaoxkkzbm');
  assert.equal(snapshot.checks.persistentStorage.clientProjectRef, 'ogbanmjokjlxfuktkicj');
});

test('blank environment values count as missing', () => {
  const snapshot = buildHealthSnapshot({ SATARK_OLLAMA_BASE_URL: '  ', SATARK_OLLAMA_MODEL: 'model', SUPABASE_URL: 'url', SUPABASE_PUBLISHABLE_KEY: '' });
  assert.equal(snapshot.checks.localModel.configured, false);
  assert.equal(snapshot.checks.persistentStorage.configured, false);
});

test('shared rate limit configuration is reported without claiming connectivity', () => {
  const configured = buildHealthSnapshot({ UPSTASH_REDIS_REST_URL: 'https://redis.example.com', UPSTASH_REDIS_REST_TOKEN: 'test-token', VERCEL: '1' });
  assert.equal(configured.checks.rateLimit.mode, 'shared-upstash');
  assert.equal(configured.checks.rateLimit.configured, true);
  assert.equal(configured.checks.rateLimit.sharedAcrossInstances, true);
  assert.equal(configured.checks.rateLimit.connectivityVerified, false);
});

test('unsafe or malformed dependency URLs are never reported as configured', () => {
  for (const url of ['http://redis.example.com', 'not-a-url', 'https://user:password@redis.example.com']) {
    const snapshot = buildHealthSnapshot({
      VERCEL: '1',
      UPSTASH_REDIS_REST_URL: url,
      UPSTASH_REDIS_REST_TOKEN: 'test-token',
      SUPABASE_URL: url,
      SUPABASE_PUBLISHABLE_KEY: 'public-key',
    });
    assert.equal(snapshot.checks.rateLimit.mode, 'misconfigured', 'unsafe Redis URL: ' + url);
    assert.equal(snapshot.checks.rateLimit.configured, false, 'unsafe Redis URL must fail closed: ' + url);
    assert.equal(snapshot.checks.persistentStorage.configured, false, 'unsafe Supabase URL: ' + url);
  }
});

test('rate-limit status copy distinguishes fail-closed production from local-only limiting', () => {
  const production = buildHealthSnapshot({ VERCEL: '1' });
  assert.match(describeRateLimitStatus(production.checks.rateLimit), /production analysis is disabled and fails closed/i);

  const partial = buildHealthSnapshot({ VERCEL: '1', UPSTASH_REDIS_REST_URL: 'https://redis.example.com' });
  assert.match(describeRateLimitStatus(partial.checks.rateLimit), /configuration is incomplete/i);

  const unsafe = buildHealthSnapshot({ VERCEL: '1', UPSTASH_REDIS_REST_URL: 'http://redis.example.com', UPSTASH_REDIS_REST_TOKEN: 'test-token' });
  assert.match(describeRateLimitStatus(unsafe.checks.rateLimit), /incomplete or unsafe/i);

  const local = buildHealthSnapshot({});
  assert.match(describeRateLimitStatus(local.checks.rateLimit), /process-local, not shared/i);

  const configured = buildHealthSnapshot({
    VERCEL: '1',
    UPSTASH_REDIS_REST_URL: 'https://redis.example.com',
    UPSTASH_REDIS_REST_TOKEN: 'test-token',
  });
  assert.match(describeRateLimitStatus(configured.checks.rateLimit), /live Redis connectivity is not verified/i);
});
