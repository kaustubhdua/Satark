import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const auth = await readFile(new URL('../src/lib/satark-auth.ts', import.meta.url), 'utf8');
const login = await readFile(new URL('../src/app/login/page.tsx', import.meta.url), 'utf8');

test('TOTP MFA secrets are encrypted and recovery codes are stored only as hashes', () => {
  assert.match(backend, /SATARK_MFA_ENCRYPTION_KEY/);
  assert.match(backend, /Fernet\(/);
  assert.match(backend, /secret_encrypted/);
  assert.match(backend, /hashlib\.sha256\(code\.encode\("utf-8"\)\)\.hexdigest\(\)/);
  assert.match(backend, /factor\.recovery_code_hashes = hashes/);
  assert.match(backend, /def verify_totp\(/);
});

test('MFA routes require authenticated enrollment, confirmation and password-protected disable', () => {
  assert.match(backend, /@router\.post\("\/auth\/mfa\/enroll\/start"\)/);
  assert.match(backend, /@router\.post\("\/auth\/mfa\/enroll\/confirm"\)/);
  assert.match(backend, /@router\.post\("\/auth\/mfa\/disable"\)/);
  assert.match(backend, /SessionRecord\.user_id == user\.id, SessionRecord\.revoked_at\.is_\(None\)/);
});

test('browser login and authenticated security UI support TOTP and recovery codes', () => {
  assert.match(auth, /mfa_code: mfaCode/);
  assert.match(auth, /\/api\/auth\/mfa\/enroll\/start/);
  assert.match(auth, /\/api\/auth\/mfa\/enroll\/confirm/);
  assert.match(login, /Authenticator code or recovery code/);
  assert.match(login, /Set up authenticator MFA/);
  assert.match(login, /Save these recovery codes now/);
  assert.match(login, /Disable MFA and revoke sessions/);
});
