import assert from 'node:assert/strict';
import test from 'node:test';
import { isAcceptableRedisRestUrl } from '../src/lib/redis-rest-url.mjs';
import { buildHealthSnapshot } from '../src/lib/health-snapshot.mjs';
import { buildCapabilityRegistry } from '../src/lib/capability-registry.mjs';

test('accepts https and private single-label http, rejects everything else', () => {
  for (const ok of ['https://x.upstash.io', 'http://redis-rest:80', 'http://localhost:8079', 'http://127.0.0.1:8079']) assert.equal(isAcceptableRedisRestUrl(ok), true, ok);
  for (const bad of ['', undefined, 'http://example.com', 'http://10.0.0.5', 'ftp://redis-rest', 'https://u:p@x.io', 'not a url']) assert.equal(isAcceptableRedisRestUrl(bad), false, String(bad));
});

test('a self-hosted Redis REST proxy counts as configured shared rate limiting', () => {
  const env = { UPSTASH_REDIS_REST_URL: 'http://redis-rest:80', UPSTASH_REDIS_REST_TOKEN: 'a'.repeat(40) };
  const rateLimit = buildHealthSnapshot(env).checks.rateLimit;
  assert.equal(rateLimit.configured, true);
  assert.equal(rateLimit.connectivityVerified, false, 'configuration is never reported as verified connectivity');
  const limiter = buildCapabilityRegistry(env).capabilities.find((c) => c.id === 'rate_limit.shared');
  assert.equal(limiter.configured, true);
});

test('the production compose file wires the web service to the API, workers and self-hosted limiter', async () => {
  const { readFile } = await import('node:fs/promises');
  const compose = await readFile(new URL('../../docker-compose.production.yml', import.meta.url), 'utf8');
  const web = compose.slice(compose.indexOf('\n  web:'), compose.indexOf('\n  redis:'));
  for (const key of ['FIRSTLIGHT_API_URL', 'FIRSTLIGHT_API_TOKEN', 'FIRSTLIGHT_WAZUH_SYNC_TOKEN', 'UPSTASH_REDIS_REST_URL', 'UPSTASH_REDIS_REST_TOKEN']) {
    assert.ok(web.includes(key + ':'), `${key} missing from the production web service`);
  }
});
