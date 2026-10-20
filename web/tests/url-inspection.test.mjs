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
  assert.ok(result.findings.some(item => item.title === 'Non-public or special-use address'));
});

test('flags IPv6 local, unique-local, link-local and mapped private destinations', () => {
  for (const host of [
    '[::1]',
    '[fc00::1234]',
    '[fd12:3456:789a::1]',
    '[fe80::1]',
    '[ff02::1]',
    '[::ffff:192.168.1.10]',
    '[::ffff:10.0.0.8]',
  ]) {
    const result = inspectUrl('http://' + host + '/admin');
    assert.equal(result.ok, true, host);
    if (!result.ok) continue;
    assert.ok(result.findings.some(item => item.title === 'Non-public or special-use address'), host);
  }
});

test('does not flag a public IPv6 address as a local/private destination', () => {
  const result = inspectUrl('https://[2606:4700:4700::1111]/');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.findings.some(item => item.title === 'Non-public or special-use address'), false);
});

test('flags non-public and special-use IPv4 ranges without network access', () => {
  for (const host of [
    '0.0.0.1',
    '10.20.30.40',
    '100.64.0.1',
    '100.127.255.254',
    '127.0.0.1',
    '169.254.10.20',
    '172.16.0.1',
    '172.31.255.254',
    '192.0.0.8',
    '192.0.2.10',
    '192.88.99.1',
    '192.168.1.10',
    '198.18.0.1',
    '198.19.255.254',
    '198.51.100.20',
    '203.0.113.25',
    '224.0.0.1',
    '240.0.0.1',
    '255.255.255.255',
  ]) {
    const result = inspectUrl('http://' + host + '/');
    assert.equal(result.ok, true, host);
    if (!result.ok) continue;
    assert.ok(result.findings.some(item => item.title === 'Non-public or special-use address'), host);
  }
});

test('does not classify an ordinary public IPv4 address as non-public', () => {
  const result = inspectUrl('https://93.184.216.34/');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.findings.some(item => item.title === 'Non-public or special-use address'), false);
});

test('does not label an ordinary HTTPS URL as safe or malicious', () => {
  const result = inspectUrl('https://example.com/account');
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.findings.length, 0);
  assert.match(result.summary, /not a safety verdict/i);
  assert.match(result.notice, /did not visit this URL/i);
});
