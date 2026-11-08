import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const proxy = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');

test('SATARK sessions use Argon2id password hashes and opaque revocable tokens', () => {
  assert.match(backend, /PasswordHasher/);
  assert.match(backend, /token_urlsafe\(48\)/);
  assert.match(backend, /token_digest/);
  assert.match(backend, /revoked_at/);
  assert.match(backend, /expires_at/);
});

test('session cookie is HttpOnly, SameSite=Lax, secure on HTTPS and deleted on logout', () => {
  assert.match(backend, /httponly=True/);
  assert.match(backend, /samesite="lax"/);
  assert.match(backend, /secure=request\.headers\.get\("x-forwarded-proto"/);
  assert.match(backend, /delete_cookie\("satark_session"/);
});

test('browser session mutations are protected by origin validation and proxy CSRF checks', () => {
  assert.match(backend, /Cross-origin mutation is not allowed/);
  assert.match(proxy, /Cross-origin API requests are not allowed/);
  assert.match(proxy, /redirect: 'error'/);
});

test('authentication never relies on external identity providers or browser-stored bearer tokens', () => {
  assert.doesNotMatch(backend, /SUPABASE|supabase\.co|\/auth\/v1|\/rest\/v1/i);
  assert.doesNotMatch(proxy, /SUPABASE_SERVICE_ROLE_KEY|NEXT_PUBLIC_SUPABASE/i);
});

test('near-expiry cookie sessions rotate through the self-hosted backend', async () => {
  const auth = await readFile(new URL('../src/lib/satark-auth.ts', import.meta.url), 'utf8');
  assert.match(backend, /@router\.post\("\/auth\/refresh"\)/);
  assert.match(backend, /changed\.rowcount !== 1/);
  assert.match(auth, /\/api\/auth\/refresh/);
  assert.match(auth, /session\.expires_at - Date\.now\(\) < 24 \* 60 \* 60 \* 1000/);
  assert.doesNotMatch(auth, /localStorage\.setItem\([^,]*(?:token|session)/i);
});
