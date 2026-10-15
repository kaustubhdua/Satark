import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectUrl } from '../src/lib/url-inspection.mjs';

test('rejects empty, oversized and non-web schemes without making network requests', () => {
  assert.equal(inspectUrl('').ok, false);
  assert.equal(inspectUrl('javascript:alert(1)').ok, false);
  assert.equal(inspectUrl('data:text/html,hello').ok, false);
  assert.equal(inspectUrl('x'.repeat(4097)).ok, false);
});

test('inspects a hostname without a scheme as HTTPS and never returns query values', () => {
  const result = inspectUrl('example.com/login?token=super-secret#fragment');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.protocol, 'HTTPS');
  assert.equal(result.hostname, 'example.com');
  assert.deepEqual(result.queryParameterNames, ['token']);
  assert.equal(JSON.stringify(result).includes('super-secret'), false);
  assert.equal(result.hasFragment, true);
});

test('flags credential-bearing URLs but never returns the credential values', () => {
  const result = inspectUrl('https://alice:secret@example.com/path');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.ok(result.findings.some(item => item.title === 'Credentials embedded in URL'));
  assert.equal(JSON.stringify(result).includes('alice'), false);
  assert.equal(JSON.stringify(result).includes('secret'), false);
});

test('flags HTTP, shorteners and non-standard ports', () => {
  const result = inspectUrl('http://bit.ly:8080/path');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  const titles = result.findings.map(item => item.title);
  assert.ok(titles.includes('HTTP without transport encryption'));
  assert.ok(titles.includes('URL-shortening service'));
  assert.ok(titles.includes('Non-standard port'));
});

test('marks private network targets without contacting them', () => {
  const result = inspectUrl('http://192.168.1.10/admin');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.ok(result.findings.some(item => item.title === 'Local or private-network address'));
});

test('does not label an ordinary HTTPS URL as safe or malicious', () => {
  const result = inspectUrl('https://example.com/account');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.findings.length, 0);
  assert.match(result.summary, /not a safety verdict/i);
  assert.match(result.notice, /did not visit this URL/i);
});
