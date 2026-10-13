import test from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiter } from '../src/lib/rate-limit.mjs';

function request(ip = '203.0.113.20') {
  return new Request('https://satark.test/api/analyze', { headers: { 'x-real-ip': ip } });
}

test('local fallback enforces the per-client window and keeps keys hashed', async () => {
  let now = 1000;
  const limiter = createRateLimiter({ env: {}, now: () => now });
  for (let i = 0; i < 8; i += 1) {
    assert.deepEqual(await limiter(request()), { limited: false, unavailable: false, mode: 'local' });
  }
  assert.deepEqual(await limiter(request()), { limited: true, unavailable: false, mode: 'local' });
  now += 60_001;
  assert.deepEqual(await limiter(request()), { limited: false, unavailable: false, mode: 'local' });
});

test('shared limiter sends an atomic Redis operation and blocks above the threshold', async () => {
  let command;
  const limiter = createRateLimiter({
    env: { UPSTASH_REDIS_REST_URL: 'https://redis.example.test', UPSTASH_REDIS_REST_TOKEN: 'test-token' },
    fetchImpl: async (_url, options) => {
      command = { url: _url, options, body: JSON.parse(options.body) };
      return new Response(JSON.stringify({ result: 9 }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  assert.deepEqual(await limiter(request()), { limited: true, unavailable: false, mode: 'shared' });
  assert.equal(command.url, 'https://redis.example.test');
  assert.equal(command.options.headers.Authorization, 'Bearer test-token');
  assert.equal(command.body[0], 'EVAL');
  assert.equal(command.body[2], '1');
  assert.match(command.body[3], /^satark:analysis:rate:[a-f0-9]{32}$/);
  assert.equal(command.body[3].includes('203.0.113.20'), false);
});

test('configured shared limiter fails closed when provider errors or credentials are partial', async () => {
  const failed = createRateLimiter({
    env: { UPSTASH_REDIS_REST_URL: 'https://redis.example.test', UPSTASH_REDIS_REST_TOKEN: 'token' },
    fetchImpl: async () => new Response('unavailable', { status: 503 }),
  });
  assert.deepEqual(await failed(request()), { limited: false, unavailable: true, mode: 'shared' });

  const partial = createRateLimiter({
    env: { UPSTASH_REDIS_REST_URL: 'https://redis.example.test' },
  });
  assert.deepEqual(await partial(request()), { limited: false, unavailable: true, mode: 'shared' });
});

test('shared limiter treats malformed provider responses as unavailable', async () => {
  const limiter = createRateLimiter({
    env: { UPSTASH_REDIS_REST_URL: 'https://redis.example.test', UPSTASH_REDIS_REST_TOKEN: 'token' },
    fetchImpl: async () => new Response(JSON.stringify({ result: '9' }), { status: 200 }),
  });
  assert.deepEqual(await limiter(request()), { limited: false, unavailable: true, mode: 'shared' });
});
