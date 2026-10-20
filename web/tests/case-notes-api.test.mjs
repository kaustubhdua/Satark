import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const notesRoute = await readFile(new URL('../src/app/api/cases/notes/route.ts', import.meta.url), 'utf8');
const casesRoute = await readFile(new URL('../src/app/api/cases/route.ts', import.meta.url), 'utf8');
const panel = await readFile(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');
const migration = await readFile(new URL('../../supabase/migrations/20261020032710_satark_case_assignment_notes.sql', import.meta.url), 'utf8');
const assignmentRpc = await readFile(new URL('../../supabase/migrations/20261020033104_satark_assignable_members_rpc.sql', import.meta.url), 'utf8');

test('case assignment requires owner/responder and verifies assignee tenant membership', () => {
  assert.match(casesRoute, /rpc\/satark_list_assignable_members/);
  assert.match(casesRoute, /Only owners or responders may assign cases/);
  assert.match(casesRoute, /row\.user_id === input\.assigned_to/);
  assert.match(casesRoute, /assigned_to/);
  assert.match(migration, /satark_validate_case_assignee/);
  assert.match(migration, /m\.tenant_id=new\.tenant_id and m\.user_id=new\.assigned_to/);
});

test('analyst notes are authenticated, bounded, immutable and audit-linked', () => {
  assert.match(notesRoute, /\/auth\/v1\/user/);
  assert.match(notesRoute, /readBoundedJson\(request, 8192\)/);
  assert.match(notesRoute, /note\.length > 4000/);
  assert.doesNotMatch(notesRoute, /export async function (PATCH|DELETE)/);
  assert.match(migration, /force row level security/i);
  assert.match(migration, /case\.note_added/);
  assert.match(migration, /body_sha256/);
  assert.doesNotMatch(migration, /grant .*update.*public\.satark_case_notes/i);
  assert.match(panel, /Run durable investigation/);
  assert.match(panel, /Add immutable note/);
  assert.match(panel, /Save assignment/);
});

test('assignable member discovery is limited to owners/responders and omits profile data', () => {
  assert.match(assignmentRpc, /satark_list_assignable_members/);
  assert.match(assignmentRpc, /array\['owner','responder'\]::text\[\]/);
  assert.match(assignmentRpc, /returns table\(user_id uuid, role text\)/);
  assert.match(assignmentRpc, /revoke all on function public\.satark_list_assignable_members\(uuid\) from public,anon/i);
  assert.doesNotMatch(assignmentRpc, /email|phone|profile_name/i);
});
