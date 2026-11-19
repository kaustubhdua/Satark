import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');
const doc = read('docs/SUPPORTED_FORMATS.md');
const num = (source, name) => {
  const match = source.match(new RegExp(`${name}\\s*=\\s*([0-9_ *]+)`));
  assert.ok(match, `${name} not found`);
  return Function(`return ${match[1].replace(/_/g, '')}`)();
};
const mib = (bytes) => bytes / 1024 / 1024;
const has = (text) => assert.ok(doc.includes(text), `docs/SUPPORTED_FORMATS.md must mention "${text}"`);

test('web limits in the formats doc match the code', () => {
  const qr = read('web/src/app/qr/page.tsx');
  has(`${mib(num(qr, 'MAX_FILE_BYTES'))} MiB, ${num(qr, 'MAX_PIXELS').toLocaleString('en-US')} pixels`);
  const image = read('web/src/app/image-review/page.tsx');
  has(`${mib(num(image, 'MAX_FILE_BYTES'))} MiB, ${num(image, 'MAX_PIXELS').toLocaleString('en-US')} pixels`);
  const pdf = read('web/src/app/pdf-review/page.tsx');
  has(`PDF ${mib(num(pdf, 'MAX_PDF_BYTES'))} MiB and ${num(pdf, 'MAX_PAGES')} pages`);
  has(`text files ${mib(num(pdf, 'MAX_TEXT_BYTES'))} MiB`);
  has(`${num(pdf, 'MAX_TEXT_CHARS').toLocaleString('en-US')} extracted characters`);
  const media = read('web/src/app/media-review/page.tsx');
  has(`${mib(num(media, 'MAX_VIDEO_BYTES'))} MiB, ${num(media, 'MAX_VIDEO_SECONDS')} seconds`);
  has(`${num(media, 'MAX_SAMPLE_COUNT')} sampled frames`);
  const analyze = read('web/src/app/api/analyze/route.ts');
  has(`${num(analyze, 'MAX_INPUT_CHARS').toLocaleString('en-US')} characters per request`);
  has(`${num(analyze, 'MAX_BODY_BYTES') / 1024} KiB request body`);
  has(`${num(read('web/src/lib/firstlight-import.mjs'), 'MAX_CSV_RECORDS').toLocaleString('en-US')} event records`);
});

test('server and legacy limits in the formats doc match the code', () => {
  has(`1 byte to ${mib(num(read('satark_backend.py'), 'MAX_UPLOAD'))} MiB`);
  const legacy = read('input_processing.py');
  has(`PDF ${mib(num(legacy, 'MAX_PDF_BYTES'))} MiB; image ${mib(num(legacy, 'MAX_IMAGE_BYTES'))} MiB and ${num(legacy, 'MAX_IMAGE_PIXELS').toLocaleString('en-US')} pixels`);
  const guard = read('file_guard/engine.py');
  has(`${mib(num(guard, 'MAX_FILE_BYTES'))} MiB per file; ${num(guard, 'MAX_DIRECTORY_FILES').toLocaleString('en-US')} files, ${mib(num(guard, 'MAX_DIRECTORY_BYTES')) / 1024} GiB total, depth ${num(guard, 'MAX_DIRECTORY_DEPTH')}`);
});
