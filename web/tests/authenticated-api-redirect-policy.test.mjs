import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const proxy = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');

test('self-hosted API proxy bounds requests and responses', () => {
  assert.match(proxy, /MAX_REQUEST_BYTES = 8 \* 1024 \* 1024/);
  assert.match(proxy, /MAX_RESPONSE_BYTES = 16 \* 1024 \* 1024/);
  assert.match(proxy, /request\.arrayBuffer\(\)/);
  assert.match(proxy, /upstream\.arrayBuffer\(\)/);
  assert.match(proxy, /AbortSignal\.timeout\(15000\)/);
});

test('self-hosted API proxy rejects redirects and untrusted upstreams', () => {
  assert.match(proxy, /redirect: 'error'/);
  assert.match(proxy, /url\.username \|\| url\.password/);
  assert.match(proxy, /local\.has\(url\.hostname\)/);
  assert.match(proxy, /target\.origin !== base\.origin/);
  assert.match(proxy, /incoming\.pathname\.startsWith\('\/\/'\)/);
  assert.doesNotMatch(proxy, /new URL\(incoming\.pathname \+ incoming\.search, base\)/);
});

test('mutating browser requests require a same-origin boundary', () => {
  assert.match(proxy, /let sameOrigin = false/);
  assert.match(proxy, /new URL\(origin\)\.origin === incoming\.origin/);
  assert.match(proxy, /if \(unsafe && !sameOrigin\)/);
  assert.doesNotMatch(proxy, /&& !bearer/);
  assert.match(proxy, /Cross-origin API requests are not allowed/);
});

test('proxy forwards the browser scheme with the private upstream host for CSRF validation', () => {
  assert.match(proxy, /headers\.set\('origin', `\$\{incoming\.protocol\}\/\/\$\{target\.host\}`\)/);
  assert.match(proxy, /headers\.set\('x-forwarded-proto', incoming\.protocol\.slice\(0, -1\)\)/);
});
