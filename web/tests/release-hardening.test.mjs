import test from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIpAddress } from '../src/lib/public-ip.mjs';

test('AbuseIPDB lookups accept only public IP literals', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPublicIpAddress(ip), true, `${ip} should be accepted`);
  }
  for (const ip of [
    'not-an-ip', '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1',
    '169.254.1.1', '100.64.0.1', '192.0.2.1', '198.51.100.2',
    '203.0.113.9', '224.0.0.1', '255.255.255.255', '::1',
    'fc00::1', 'fe80::1', '2001:db8::1', '2001:100::1', '2001:0::1', '3fff::1', '2002:c000:0201::1',
  ]) {
    assert.equal(isPublicIpAddress(ip), false, `${ip} must not be queried`);
  }
});

import { readFileSync } from 'node:fs';

const config = readFileSync(new URL('../next.config.ts', import.meta.url), 'utf8');
const analyze = readFileSync(new URL('../src/app/api/analyze/route.ts', import.meta.url), 'utf8');
const reports = readFileSync(new URL('../src/app/reports/page.tsx', import.meta.url), 'utf8');
const firstlight = readFileSync(new URL('../src/app/firstlight/page.tsx', import.meta.url), 'utf8');

test('baseline security headers and CSP directives are configured', () => {
  for (const header of ['X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Strict-Transport-Security', 'Content-Security-Policy']) {
    assert.match(config, new RegExp(header));
  }
  assert.match(config, /base-uri 'none'/);
  assert.match(config, /object-src 'none'/);
  assert.match(config, /frame-ancestors 'none'/);
  assert.match(config, /form-action 'self'/);
});

test('independent reputation lookups execute concurrently', () => {
  assert.match(analyze, /Promise\.all\(\[/);
  assert.match(analyze, /checkUrlhaus\(input, shareWithThreatIntel\)/);
  assert.match(analyze, /checkAbuseIpDb\(input, shareIpWithThreatIntel\)/);
});

test('reports exports only user-authored notes in TXT and versioned JSON', () => {
  assert.match(reports, /satark-review-notes\.txt/);
  assert.match(reports, /satark-review-notes\.json/);
  assert.match(reports, /schema_version: 1/);
  assert.match(reports, /No analysis results or provider evidence are automatically included/);
});

test('FIRSTLIGHT explicitly marks response actions as simulation only', () => {
  assert.match(firstlight, /SYNTHETIC/);
  assert.match(firstlight, /no real system action executed/);
  assert.match(firstlight, /does not inspect the endpoint or file/);
});


test('per-instance throttling does not trust spoofable x-forwarded-for', () => {
  assert.match(analyze, /request\.headers\.get\('x-real-ip'\)/);
  assert.doesNotMatch(analyze, /request\.headers\.get\('x-forwarded-for'\)\?\.split\(', '\)\[0\]/);
  assert.match(analyze, /all requests share[\s\S]*?'unknown' bucket/);
});

test('all API responses have an explicit no-store cache policy', () => {
  assert.match(config, /source: '\/api\/:path\*'/);
  assert.match(config, /key: 'Cache-Control', value: 'no-store'/);
});

test('analysis API rejects unsupported media types before parsing bodies', () => {
  assert.match(analyze, /contentType !== 'application\/json'/);
  assert.match(analyze, /Content-Type must be application\/json/);
  assert.match(analyze, /return error\('Content-Type must be application\/json\.', 415\)/);
});

test('URLhaus consent is opt-in and query strings/fragments are stripped before sharing', () => {
  assert.match(analyze, /parsed\.search = '';/);
  assert.match(analyze, /parsed\.hash = '';/);
  assert.match(analyze, /Never forward them to an external reputation provider/);
  const investigate = readFileSync(new URL('../src/app/investigate/page.tsx', import.meta.url), 'utf8');
  assert.match(investigate, /query strings and fragments are removed first/);
  assert.match(investigate, /Paths can still contain private identifiers/);
});
