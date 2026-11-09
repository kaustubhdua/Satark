import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const auth = await readFile(new URL('../src/lib/satark-auth.ts', import.meta.url), 'utf8');
const resetPage = await readFile(new URL('../src/app/reset-password/page.tsx', import.meta.url), 'utf8');

test('password reset uses expiring one-time digested tokens and invalidates prior sessions', () => {
  assert.match(backend, /class PasswordResetToken\(Base\)/);
  assert.match(backend, /timedelta\(minutes=30\)/);
  assert.match(backend, /PasswordResetToken\.token_hash == digest/);
  assert.match(backend, /SessionRecord\.user_id == user\.id, SessionRecord\.revoked_at\.is_\(None\)/);
  assert.match(backend, /SATARK_SMTP_HOST/);
  assert.match(backend, /SATARK_PUBLIC_BASE_URL/);
});

test('browser recovery sends and completes the SATARK-owned reset flow', () => {
  assert.match(auth, /\/api\/auth\/password-reset\/request/);
  assert.match(auth, /\/api\/auth\/password-reset\/complete/);
  assert.match(resetPage, /params\.get\('token'\)/);
  assert.match(resetPage, /window\.history\.replaceState/);
  assert.match(resetPage, /minLength=\{12\}/);
  assert.doesNotMatch(resetPage, /access_token/);
});


test('optional email verification uses one-time digested tokens and requires SMTP configuration', () => {
  assert.match(backend, /class EmailVerificationToken\(Base\)/);
  assert.match(backend, /SATARK_REQUIRE_EMAIL_VERIFICATION/);
  assert.match(backend, /email_verification_public_base\(\)/);
  assert.match(backend, /EmailVerificationToken\.token_hash == token_digest\(body\.token\)/);
  assert.match(backend, /Verify your email address before signing in/);
});

test('browser email verification removes the token from history and supports resend', async () => {
  const page = await readFile(new URL('../src/app/verify-email/page.tsx', import.meta.url), 'utf8');
  const login = await readFile(new URL('../src/app/login/page.tsx', import.meta.url), 'utf8');
  assert.match(auth, /\/api\/auth\/email-verification\/complete/);
  assert.match(auth, /\/api\/auth\/email-verification\/request/);
  assert.match(page, /params\.get\('token'\)/);
  assert.match(page, /window\.history\.replaceState/);
  assert.match(login, /Resend verification email/);
});
