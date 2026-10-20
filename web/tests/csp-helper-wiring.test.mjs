import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildSecurityHeaders } from '../src/lib/security-headers.mjs';

const config = readFileSync(new URL('../next.config.ts', import.meta.url), 'utf8');

function cspFor(env) {
  return buildSecurityHeaders(env).find((header) => header.key === 'Content-Security-Policy')?.value ?? '';
}

test('Next.js wires CSP to the validated Supabase origin helper', () => {
  assert.ok(config.includes("import { buildSecurityHeaders } from './src/lib/security-headers.mjs';"));
  assert.ok(config.includes('const securityHeaders = buildSecurityHeaders(process.env);'));
  assert.ok(!config.includes('https://*.supabase.co'));
  assert.ok(!config.includes('wss://*.supabase.co'));
});

test('production CSP allows only the configured valid Supabase HTTPS origin', () => {
  const csp = cspFor({
    NODE_ENV: 'production',
    NEXT_PUBLIC_SUPABASE_URL: 'https://project-ref.supabase.co',
  });
  assert.match(csp, /connect-src 'self' https:\/\/project-ref\.supabase\.co(?:;|$)/);
  assert.doesNotMatch(csp, /\*\.supabase\.co/);
  assert.doesNotMatch(csp, /wss:\/\//);
});

test('production CSP fails closed for malformed or non-Supabase origins', () => {
  for (const value of [
    'https://attacker.example',
    'https://project-ref.supabase.co.evil.example',
    'https://project-ref.supabase.co/path',
    'http://project-ref.supabase.co',
    'not a URL',
  ]) {
    const csp = cspFor({ NODE_ENV: 'production', NEXT_PUBLIC_SUPABASE_URL: value });
    assert.match(csp, /connect-src 'self'(?:;|$)/);
    assert.doesNotMatch(csp, /supabase\.co|attacker\.example/);
  }
});
