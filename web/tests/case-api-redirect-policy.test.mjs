import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../src/app/api/cases/route.ts', import.meta.url), 'utf8');

test('case API rejects redirects while validating bearer tokens with Supabase Auth', () => {
  const match = source.match(/fetch\(config\.url \+ '\/auth\/v1\/user', \{([\s\S]*?)\n    \}\);/);
  assert.ok(match, 'Supabase Auth user validation fetch must exist');
  assert.match(match[1], /\bredirect\s*:\s*['"]error['"]/, 'Auth fetch must reject redirects');
});

test('case API rejects redirects for every Supabase PostgREST operation', () => {
  const match = source.match(/return fetch\(config\.url \+ '\/rest\/v1\/' \+ path, \{([\s\S]*?)\n  \}\);/);
  assert.ok(match, 'Supabase PostgREST fetch must exist');
  assert.match(match[1], /\bredirect\s*:\s*['"]error['"]/, 'PostgREST fetch must reject redirects');
  assert.ok(match[1].indexOf('...init') < match[1].indexOf("redirect: 'error'"), 'fixed redirect policy must override caller options');
});
