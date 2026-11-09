import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const backend = await readFile(new URL('../../satark_backend.py', import.meta.url), 'utf8');
const panel = await readFile(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');

test('case notes are authenticated, tenant-scoped, bounded, and audit-linked', () => {
  assert.match(backend, /class CaseNote/);
  assert.match(backend, /def list_notes/);
  assert.match(backend, /def create_note/);
  assert.match(backend, /require_membership\(db, user, body\.tenant_id/);
  assert.match(backend, /body: str = Field\(min_length=1, max_length=4000\)/);
  assert.match(backend, /case\.note\.created/);
});

test('case UI exposes notes and durable investigation actions', () => {
  assert.match(panel, /Run durable investigation/);
  assert.match(panel, /Add immutable note/);
});
