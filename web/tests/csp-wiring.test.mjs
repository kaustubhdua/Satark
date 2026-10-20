import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const config = readFileSync(new URL('../next.config.ts', import.meta.url), 'utf8');
test('Next.js uses exact-origin CSP helper', () => {
  assert.ok(config.includes('buildSecurityHeaders(process.env)'));
  assert.ok(!config.includes('supabase.co'));
});
