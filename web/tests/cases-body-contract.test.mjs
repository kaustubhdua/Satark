import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const proxy = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');
const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');

test('case API proxy bounds actual request bytes before forwarding', () => {
  assert.match(proxy, /MAX_REQUEST_BYTES = 8 \* 1024 \* 1024/);
  assert.match(proxy, /request\.arrayBuffer\(\)/);
  assert.match(proxy, /body\.byteLength > MAX_REQUEST_BYTES/);
});

test('case API validates status, severity, title and metadata before persistence', () => {
  assert.match(backend, /class CaseInput/);
  assert.match(backend, /Invalid case status or severity/);
  assert.match(backend, /Case title is invalid/);
  assert.match(backend, /Case metadata is invalid or oversized/);
});
