import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildSecurityHeaders } from '../src/lib/security-headers.mjs';

const config = readFileSync(new URL('../next.config.ts', import.meta.url), 'utf8');
function cspFor(env) {
  return buildSecurityHeaders(env).find(header => header.key === 'Content-Security-Policy')?.value ?? '';
}

test('Next.js wires a same-origin CSP without hosted database origins', () => {
  assert.ok(config.includes("import { buildSecurityHeaders } from './src/lib/security-headers.mjs';"));
  assert.ok(config.includes('const securityHeaders = buildSecurityHeaders(process.env);'));
  const csp = cspFor({ NODE_ENV: 'production' });
  assert.match(csp, /connect-src 'self'/);
  assert.doesNotMatch(csp, /supabase|https:\/\//i);
  assert.doesNotMatch(csp, /connect-src[^;]*\*/);
});

test('untrusted backend origins cannot be added to the browser CSP', () => {
  for (const value of ['https://attacker.example', 'http://firstlight-api:8788', 'not a URL']) {
    const csp = cspFor({ NODE_ENV: 'production', SATARK_API_INTERNAL_URL: value });
    assert.match(csp, /connect-src 'self'/);
    assert.doesNotMatch(csp, /attacker\.example|firstlight-api|supabase/i);
  }
});
