import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const page = await readFile(new URL('../src/app/firstlight/page.tsx', import.meta.url), 'utf8');
const panel = await readFile(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');
const liveResponse = await readFile(new URL('../src/app/firstlight/live-response-panel.tsx', import.meta.url), 'utf8');

test('FIRSTLIGHT response review points operators to the saved-case guarded workflow', () => {
  assert.match(page, /id="persistent-workspace"/);
  assert.match(page, /href="#persistent-workspace"/);
  assert.match(page, /Real endpoint response is available from a saved case/);
  assert.match(page, /configured private Wazuh Manager/);
  assert.match(page, /Training-only decision examples/);
  assert.match(page, /They do not approve, execute, or record a real endpoint action/);
});

test('the persistent case workspace mounts the real Wazuh response panel only for a saved case', () => {
  assert.match(panel, /import LiveResponsePanel from '\.\/live-response-panel'/);
  assert.match(panel, /<LiveResponsePanel tenantId={tenant\.id} caseId={currentCaseId} userId={session\.user\.id} role={tenant\.role} \/>/);
  assert.match(panel, /cases\.some\(c => c\.id === currentCaseId\)/);
});

test('live response retains separate approval, execution and independent verification controls', () => {
  assert.match(liveResponse, /Refresh response status/);
  assert.match(liveResponse, /run\(refresh, false\)/);
  assert.match(liveResponse, /Request live-response approval/);
  assert.match(liveResponse, /Execute approved action once/);
  assert.match(liveResponse, /Record independent verification/);
  assert.match(liveResponse, /No provider action has run/);
});
