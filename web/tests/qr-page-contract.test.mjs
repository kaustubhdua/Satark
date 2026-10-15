import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('QR page uses bounded local decoding and never fetches decoded URLs', async () => {
  const source = await readFile(new URL('../src/app/qr/page.tsx', import.meta.url), 'utf8');
  assert.match(source, /MAX_FILE_BYTES = 10 \* 1024 \* 1024/);
  assert.match(source, /MAX_PIXELS = 40_000_000/);
  assert.match(source, /BarcodeDetector/);
  assert.match(source, /createImageBitmap/);
  assert.match(source, /detector\.detect\(bitmap\)/);
  assert.match(source, /did not open the payload|never opened automatically|never open/i);
  assert.match(source, /fetch\(['"]\/api\/analyze['"]/, 'URL text may be sent only to SATARK’s own analysis route');
  assert.doesNotMatch(source, /fetch\(\s*payload|fetch\(\s*new URL/, 'decoded destination must never be fetched');
  assert.doesNotMatch(source, /window\.open|location\.href\s*=/, 'decoded payload must not navigate the browser');
});

test('capability directory labels unported media tools honestly', async () => {
  const source = await readFile(new URL('../src/app/tools/page.tsx', import.meta.url), 'utf8');
  assert.match(source, /QR-code investigation/);
  assert.match(source, /PDF & document analysis/);
  assert.match(source, /Video & media analysis/);
  assert.match(source, /Not migrated/);
});
