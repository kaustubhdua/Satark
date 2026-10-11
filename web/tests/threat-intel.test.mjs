import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const route = readFileSync(new URL('../src/app/api/analyze/route.ts', import.meta.url), 'utf8');
const page = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');

test('URLhaus lookup is gated by explicit user opt-in and a server-side flag', () => {
  assert.match(page, /checked=\{shareWithThreatIntel\}/);
  assert.match(page, /shareWithThreatIntel\s*\}\)/);
  assert.match(route, /parsedBody\.shareWithThreatIntel === true/);
  assert.match(route, /SATARK_ENABLE_THREAT_INTEL !== 'true'/);
});

test('URLhaus receives an extracted HTTP(S) URL, not the entire submitted message', () => {
  assert.match(route, /extractFirstHttpUrl\(input\)/);
  assert.match(route, /body: new URLSearchParams\(\{ url \}\)/);
  assert.doesNotMatch(route, /body: new URLSearchParams\(\{\s*input\s*\}\)/);
});

test('a no-match result explicitly does not mean safe', () => {
  assert.match(route, /This does not establish that the URL is safe/);
  assert.match(route, /status: 'no_match'/);
});

test('URL reputation lookup is time-bounded and server secret is not public-prefixed', () => {
  assert.match(route, /AbortController/);
  assert.match(route, /URLHAUS_AUTH_KEY/);
  assert.doesNotMatch(route, /NEXT_PUBLIC_URLHAUS_AUTH_KEY/);
});

test('UI explains optional external data sharing and displays lookup status', () => {
  assert.match(page, /full extracted URL/);
  assert.match(page, /threat_intel\.status/);
});
