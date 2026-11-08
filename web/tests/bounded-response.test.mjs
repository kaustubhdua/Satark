import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readBoundedResponseText } from '../src/lib/read-bounded-response.mjs';

test('accepts a response exactly at the UTF-8 byte limit', async () => {
  assert.deepEqual(await readBoundedResponseText(new Response('🛡️'), 7), { ok: true, text: '🛡️' });
});

test('rejects an oversized declared response before reading its body', async () => {
  const response = new Response('12345', { headers: { 'content-length': '5' } });
  assert.deepEqual(await readBoundedResponseText(response, 4), { ok: false, reason: 'too_large' });
});

test('enforces the streamed byte limit when content-length is absent', async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('123'));
      controller.enqueue(new TextEncoder().encode('45'));
      controller.close();
    },
  });
  assert.deepEqual(await readBoundedResponseText(new Response(stream), 4), { ok: false, reason: 'too_large' });
});

test('does not trust a falsely small content-length header', async () => {
  const response = new Response('12345', { headers: { 'content-length': '1' } });
  assert.deepEqual(await readBoundedResponseText(response, 4), { ok: false, reason: 'too_large' });
});

test('counts UTF-8 bytes rather than JavaScript characters', async () => {
  assert.deepEqual(await readBoundedResponseText(new Response('🛡️'), 6), { ok: false, reason: 'too_large' });
});

test('rejects malformed UTF-8 rather than returning corrupted text', async () => {
  const response = new Response(new Uint8Array([0xc3, 0x28]));
  assert.deepEqual(await readBoundedResponseText(response, 8), { ok: false, reason: 'unreadable' });
});

test('rejects invalid limits and malformed length headers', async () => {
  assert.deepEqual(await readBoundedResponseText(new Response('x'), 0), { ok: false, reason: 'unreadable' });
  const response = new Response('x', { headers: { 'content-length': 'unknown' } });
  assert.deepEqual(await readBoundedResponseText(response, 8), { ok: false, reason: 'unreadable' });
});

test('self-hosted API proxy bounds request and response bytes and rejects redirects', async () => {
  const source = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');
  assert.match(source, /MAX_REQUEST_BYTES = 8 \* 1024 \* 1024/);
  assert.match(source, /MAX_RESPONSE_BYTES = 16 \* 1024 \* 1024/);
  assert.match(source, /request\.arrayBuffer\(\)/);
  assert.match(source, /upstream\.arrayBuffer\(\)/);
  assert.match(source, /redirect: 'error'/);
  assert.match(source, /AbortSignal\.timeout\(15000\)/);
});

test('persistent report and investigation routes delegate to the bounded self-hosted proxy', async () => {
  for (const route of ['api/reports/[id]/route.ts', 'api/firstlight/investigate/route.ts', 'api/firstlight/jobs/route.ts']) {
    const source = await readFile(new URL('../src/app/' + route, import.meta.url), 'utf8');
    assert.match(source, /proxySatarkApi/);
    assert.doesNotMatch(source, /SUPABASE|supabase\.co|await\s+response\.(?:text|json)\(\)/i);
  }
});

test('persistent evidence upload is bounded by proxy and backend file-size limits', async () => {
  const proxy = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');
  const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
  assert.match(proxy, /MAX_REQUEST_BYTES = 8 \* 1024 \* 1024/);
  assert.match(backend, /MAX_UPLOAD = 4 \* 1024 \* 1024/);
  assert.match(backend, /read\(MAX_UPLOAD \+ 1\)/);
});

test('bounded response JSON helper enforces the shared byte cap before parsing', async () => {
  const source = await readFile(new URL('../src/lib/read-bounded-response-json.ts', import.meta.url), 'utf8');
  assert.match(source, /readBoundedResponseText\(response, maxBytes\)/);
  assert.match(source, /maxBytes = 2 \* 1024 \* 1024/);
  assert.match(source, /JSON\.parse\(bounded\.text\)/);
  assert.match(source, /bounded\.reason === 'too_large'/);
});

test('evidence multipart upload is byte-bounded before form-data parsing', async () => {
  const source = await readFile(new URL('../src/app/api/evidence/route.ts', import.meta.url), 'utf8');
  assert.match(source, /readBoundedBody\(request,\s*MAX_FILE_BYTES\s*\+\s*64\s*\*\s*1024\)/);
  assert.match(source, /new Request\(request\.url,[\s\S]*body:\s*Buffer\.from\(boundedBody\.bytes\)/);
  assert.match(source, /contentEncoding\.toLowerCase\(\)\s*!==\s*'identity'/);
  assert.doesNotMatch(source, /await\s+request\.formData\(\)/);
});

test('shared bounded request reader caps streamed bytes and parses JSON only after the cap', async () => {
  const source = await readFile(new URL('../src/lib/read-bounded-json.ts', import.meta.url), 'utf8');
  assert.match(source, /export async function readBoundedBody/);
  assert.match(source, /totalBytes > maxBytes/);
  assert.match(source, /reader\.cancel\(\)/);
  assert.match(source, /readBoundedBody\(request, maxBytes\)/);
  assert.match(source, /new TextDecoder\('utf-8', \{ fatal: true \}\)/);
});
