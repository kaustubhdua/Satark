import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const auth = await readFile(new URL('../src/lib/satark-auth.ts', import.meta.url), 'utf8');
const login = await readFile(new URL('../src/app/login/page.tsx', import.meta.url), 'utf8');
const acceptPage = await readFile(new URL('../src/app/accept-invitation/page.tsx', import.meta.url), 'utf8');

test('workspace invitations are expiring, digested, role-bounded and single-use', () => {
  assert.match(backend, /class WorkspaceInvitation\(Base\)/);
  assert.match(backend, /timedelta\(days=7\)/);
  assert.match(backend, /WorkspaceInvitation\.token_hash == digest/);
  assert.match(backend, /row\.accepted_at = now/);
  assert.match(backend, /Sign in using the email address that received this invitation/);
  assert.match(backend, /body\.role not in \{"responder", "analyst", "viewer"\}/);
});

test('owners can send, list and revoke workspace invitations from the browser', () => {
  assert.match(auth, /\/api\/workspaces\/invitations/);
  assert.match(login, /Invite a teammate/);
  assert.match(login, /Pending invitations/);
  assert.match(login, /Revoke/);
});

test('invitation acceptance requires a signed-in matching account and removes token from URL', () => {
  assert.match(auth, /\/api\/workspaces\/invitations\/accept/);
  assert.match(acceptPage, /getSession\(\)/);
  assert.match(acceptPage, /window\.history\.replaceState/);
  assert.match(acceptPage, /reopen the original invitation email link/);
});
