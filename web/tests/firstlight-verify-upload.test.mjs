import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const panel = readFileSync(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');

test('verifying an uploaded original sends the workspace id the API requires', () => {
  const start = panel.indexOf('async function verifyOriginal');
  const body = panel.slice(start, panel.indexOf('return <section', start));
  assert.match(body, /\/verify\?' \+ new URLSearchParams\(\{ tenant_id: tenant\.id \}\)/);
  assert.match(body, /result\.detail/, 'FastAPI validation detail must reach the user instead of a generic message');
});

test('upload confirmation reads the digest from the evidence object the API returns', () => {
  assert.match(panel, /result\.evidence\.source_sha256/);
  assert.doesNotMatch(panel, /result\.integrity\.source_sha256/);
});

test('audit-chain message uses the fields the API actually returns', () => {
  assert.match(panel, /result\.events_checked/);
  assert.match(panel, /result\.failed_event_id/);
  assert.doesNotMatch(panel, /result\.event_count|result\.first_invalid_event_id/);
});
