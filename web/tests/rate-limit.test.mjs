import test from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiter } from '../src/lib/rate-limit.mjs';

function request(ip = '203.0.113.20') {
  return new Request('https://satark.test/api/analyze', { headers: { 'x-real-ip': ip } });
}

test('local development limiter enforces per-client window without external services', async () => {
  let now = 1000;
  const limiter = createRateLimiter({ now: () => now, env: {} });
  for (let i = 0; i < 8; i += 1) assert.deepEqual(await limiter(request()), { limited: false, unavailable: false, mode: 'local' });
  assert.deepEqual(await limiter(request()), { limited: true, unavailable: false, mode: 'local' });
  now += 60_001;
  assert.deepEqual(await limiter(request()), { limited: false, unavailable: false, mode: 'local' });
});

test('production on Vercel stays available with a per-instance fallback when no shared limiter exists', async () => {
  const limiter = createRateLimiter({ env: { VERCEL: '1' } });
  for (let i = 0; i < 8; i += 1) assert.deepEqual(await limiter(request('203.0.113.30')), { limited: false, unavailable: false, mode: 'local-fallback' });
  assert.deepEqual(await limiter(request('203.0.113.30')), { limited: true, unavailable: false, mode: 'local-fallback' });
});

test('client keys are hashed and caller-controlled forwarded-for is ignored', async () => {
  const limiter = createRateLimiter({ env: {} });
  const first = new Request('https://satark.test/api/analyze', { headers: { 'x-real-ip': '203.0.113.21', 'x-forwarded-for': '198.51.100.8' } });
  for (let i = 0; i < 8; i += 1) await limiter(first);
  assert.deepEqual(await limiter(first), { limited: true, unavailable: false, mode: 'local' });
});

test('shared limiter uses atomic Redis script and enforces the global counter', async () => {
  let captured;
  const limiter = createRateLimiter({
    env: { UPSTASH_REDIS_REST_URL: 'https://redis.example.com/', UPSTASH_REDIS_REST_TOKEN: 'test-token', VERCEL: '1' },
    fetcher: async (url, init) => {
      captured = { url, init, body: JSON.parse(init.body) };
      return new Response(JSON.stringify({ result: [9, 58_000] }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  assert.deepEqual(await limiter(request()), { limited: true, unavailable: false, mode: 'shared' });
  assert.equal(captured.url, 'https://redis.example.com');
  assert.equal(captured.init.headers.Authorization, 'Bearer test-token');
  assert.equal(captured.body[0], 'EVAL');
  assert.match(captured.body[1], /INCR/);
  assert.match(captured.body[1], /PEXPIRE/);
  assert.equal(captured.body[2], '1');
  assert.match(captured.body[3], /^satark:analysis:rate:[a-f0-9]{32}$/);
  assert.equal(captured.body[4], '60000');
});

const shared = { UPSTASH_REDIS_REST_URL: 'https://redis.example.com', UPSTASH_REDIS_REST_TOKEN: 'test-token' };
const degraded = { limited: false, unavailable: false, mode: 'shared-degraded' };

test('shared limiter degrades to the per-instance limit on oversized upstream responses', async () => {
  const limiter = createRateLimiter({ env: shared, fetcher: async () => new Response('x'.repeat(20 * 1024), { status: 200 }) });
  assert.deepEqual(await limiter(request('203.0.113.31')), degraded);
});

test('shared limiter degrades on malformed upstream JSON', async () => {
  const limiter = createRateLimiter({ env: shared, fetcher: async () => new Response('not-json', { status: 200 }) });
  assert.deepEqual(await limiter(request('203.0.113.32')), degraded);
});

test('shared limiter outage still enforces a local limit instead of opening the endpoint', async () => {
  const limiter = createRateLimiter({ env: shared, fetcher: async () => { throw new Error('network unavailable'); } });
  for (let i = 0; i < 8; i += 1) assert.deepEqual(await limiter(request('203.0.113.33')), degraded);
  assert.deepEqual(await limiter(request('203.0.113.33')), { ...degraded, limited: true });
});

test('partial or unsafe shared configuration is ignored with a per-instance limit', async () => {
  const partial = createRateLimiter({ env: { UPSTASH_REDIS_REST_URL: 'https://redis.example.com' } });
  assert.deepEqual(await partial(request('203.0.113.34')), { limited: false, unavailable: false, mode: 'misconfigured' });
  const unsafe = createRateLimiter({ env: { UPSTASH_REDIS_REST_URL: 'http://redis.example.com', UPSTASH_REDIS_REST_TOKEN: 'x' } });
  assert.deepEqual(await unsafe(request('203.0.113.35')), { limited: false, unavailable: false, mode: 'misconfigured' });
});
