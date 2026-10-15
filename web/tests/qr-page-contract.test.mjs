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
  assert.doesNotMatch(source, /fetch\s*\(/, 'QR decoding must not automatically fetch decoded destinations');
  assert.doesNotMatch(source, /window\.open|location\.href\s*=/, 'decoded payload must not navigate the browser');
});

test('capability directory labels partial local media triage honestly', async () => {
  const source = await readFile(new URL('../src/app/tools/page.tsx', import.meta.url), 'utf8');
  assert.match(source, /QR-code investigation/);
  assert.match(source, /PDF & document review/);
  assert.match(source, /Video & media review/);
  assert.match(source, /PDF structural triage/);
  assert.match(source, /Sample video frames/);
  assert.match(source, /No upload/i);
  assert.match(source, /10 MiB/);
  assert.match(source, /50 MiB/);
  assert.match(source, /not full PDF parsing or malware scanning/i);
  assert.match(source, /does not interpret scene meaning/i);
});
