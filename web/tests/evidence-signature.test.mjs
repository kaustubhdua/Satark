import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectEvidenceFile } from '../src/lib/evidence-signature.mjs';

test('recognizes supported binary signatures independent of filename', () => {
  assert.deepEqual(inspectEvidenceFile(Uint8Array.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]), 'image/png'), { ok: true, contentType: 'image/png', signatureType: 'png', signatureVerified: true });
  assert.equal(inspectEvidenceFile(Uint8Array.from([0x25,0x50,0x44,0x46,0x2d,0x31]), '').contentType, 'application/pdf');
  assert.equal(inspectEvidenceFile(Uint8Array.from([0x50,0x4b,0x03,0x04]), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document').signatureVerified, false);
});

test('does not overstate ZIP container verification for Office document MIME types', () => {
  const docx = inspectEvidenceFile(
    Uint8Array.from([0x50,0x4b,0x03,0x04,0x00,0x00]),
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  );
  assert.equal(docx.ok, true);
  assert.equal(docx.signatureType, 'zip-container');
  assert.equal(docx.signatureVerified, false);
  assert.equal(inspectEvidenceFile(Uint8Array.from([0x50,0x4b,0x03,0x04]), 'application/zip').signatureVerified, true);
});

test('rejects a declared MIME type that conflicts with the bytes', () => {
  assert.deepEqual(inspectEvidenceFile(Uint8Array.from([0xff,0xd8,0xff,0x00]), 'image/png'), { ok: false, reason: 'mime_signature_mismatch' });
  assert.deepEqual(inspectEvidenceFile(Uint8Array.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]), 'application/pdf'), { ok: false, reason: 'mime_signature_mismatch' });
});

test('validates UTF-8 text and JSON instead of trusting a text MIME label', () => {
  assert.equal(inspectEvidenceFile(new TextEncoder().encode('line one\nline two'), 'text/plain').signatureVerified, true);
  assert.deepEqual(inspectEvidenceFile(new TextEncoder().encode('{invalid json'), 'application/json'), { ok: false, reason: 'unrecognized_or_invalid_signature' });
  assert.deepEqual(inspectEvidenceFile(Uint8Array.from([0xff,0xfe,0x00]), 'text/plain'), { ok: false, reason: 'unrecognized_or_invalid_signature' });
});

test('keeps unknown binary evidence as octet-stream but marks it unverified', () => {
  assert.deepEqual(inspectEvidenceFile(Uint8Array.from([0x00,0xff,0x81]), ''), { ok: true, contentType: 'application/octet-stream', signatureType: 'unrecognized-binary', signatureVerified: false });
  assert.deepEqual(inspectEvidenceFile(Uint8Array.from([0x00,0xff,0x81]), 'application/x-msdownload'), { ok: false, reason: 'unrecognized_or_invalid_signature' });
});

test('rejects active SVG and XML content types instead of serving untrusted markup inline', () => {
  assert.deepEqual(inspectEvidenceFile(new TextEncoder().encode('<svg><script>alert(1)</script></svg>'), 'image/svg+xml'), {
    ok: false, reason: 'unrecognized_or_invalid_signature',
  });
  assert.deepEqual(inspectEvidenceFile(new TextEncoder().encode('<root/>'), 'application/xml'), {
    ok: false, reason: 'unrecognized_or_invalid_signature',
  });
});

test('rejects empty payloads', () => {
  assert.deepEqual(inspectEvidenceFile(new Uint8Array(), 'application/octet-stream'), { ok: false, reason: 'empty_or_invalid_bytes' });
});
