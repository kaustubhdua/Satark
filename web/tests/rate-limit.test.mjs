import test from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiter } from '../src/lib/rate-limit.mjs';

function request(ip = '203.0.113.20') {
  return new Request('https://satark.test/api/analyze', { headers: { 'x-real-ip': ip } });
}

test('local limiter enforces per-client window without external services', async () => {
  let now = 1000;
  const limiter = createRateLimiter({ now: () => now });
  for (let i = 0; i < 8; i += 1) {
    assert.deepEqual(await limiter(request()), { limited: false, unavailable: false, mode: 'local' });
  }
  assert.deepEqual(await limiter(request()), { limited: true, unavailable: false, mode: 'local' });
  now += 60_001;
  assert.deepEqual(await limiter(request()), { limited: false, unavailable: false, mode: 'local' });
});

test('client keys are hashed and caller-controlled forwarded-for is ignored', async () => {
  const limiter = createRateLimiter();
  const first = new Request('https://satark.test/api/analyze', {
    headers: { 'x-real-ip': '203.0.113.21', 'x-forwarded-for': '198.51.100.8' },
  });
  for (let i = 0; i < 8; i += 1) await limiter(first);
  assert.deepEqual(await limiter(first), { limited: true, unavailable: false, mode: 'local' });
});
