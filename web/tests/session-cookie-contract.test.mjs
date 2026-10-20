import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const route = await readFile(new URL('../src/app/api/auth/session/route.ts', import.meta.url), 'utf8');

test('session-cookie endpoint rejects absent, malformed, and cross-origin Origin values', () => {
  assert.match(route, /function sameOrigin\(request: Request\)/);
  assert.match(route, /if \(!origin\) return false/);
  assert.match(route, /new URL\(origin\)\.origin === new URL\(request\.url\)\.origin/);
  assert.match(route, /if \(!sameOrigin\(request\)\) return response\(\{ error: 'Cross-origin session requests are not allowed\.' \}, 403\)/);
  assert.equal((route.match(/if \(!sameOrigin\(request\)\)/g) || []).length, 2,
    'both session creation and deletion must enforce the origin boundary');
});

test('session-cookie endpoint uses server-only Supabase configuration and bounded token validation', () => {
  assert.match(route, /process\.env\.SUPABASE_URL/);
  assert.match(route, /process\.env\.SUPABASE_PUBLISHABLE_KEY/);
  assert.doesNotMatch(route, /NEXT_PUBLIC_SUPABASE/);
  assert.match(route, /const MAX_TOKEN = 8192/);
  assert.match(route, /TOKEN_PATTERN/);
  assert.match(route, /expiresAt > Date\.now\(\) \+ 86400_000/);
  assert.match(route, /redirect: 'error'/);
  assert.match(route, /AbortSignal\.timeout\(4000\)/);
});

test('session cookies are HttpOnly, SameSite=Lax, scoped, and cleared symmetrically', () => {
  assert.match(route, /result\.cookies\.set\('satark-access', access, \{ httpOnly: true, secure, sameSite: 'lax', path: '\/', expires: new Date\(expiresAt\), priority: 'high' \}\)/);
  assert.match(route, /result\.cookies\.set\('satark-refresh', refresh, \{ httpOnly: true, secure, sameSite: 'lax', path: '\/api\/auth', maxAge: 86400 \* 30, priority: 'high' \}\)/);
  assert.match(route, /result\.cookies\.set\('satark-access', '', \{ httpOnly: true, secure, sameSite: 'lax', path: '\/', maxAge: 0 \}\)/);
  assert.match(route, /result\.cookies\.set\('satark-refresh', '', \{ httpOnly: true, secure, sameSite: 'lax', path: '\/api\/auth', maxAge: 0 \}\)/);
});

test('session responses disable caching and validate access token with Supabase Auth', () => {
  assert.match(route, /'Cache-Control': 'no-store'/);
  assert.match(route, /Pragma: 'no-cache'/);
  assert.match(route, /config\.url \+ '\/auth\/v1\/user'/);
  assert.match(route, /if \(!\(await verify\(access\)\)\) return response\(\{ error: 'The session is invalid or expired\.' \}, 401\)/);
});
