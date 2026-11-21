import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  RULE_VERSION, investigateCase, prioritizeEvidence, ruleMetadata, ruleTitles, sealEvidence, timestampMs, verifyEvidence,
} from '../src/lib/firstlight-engine.mjs';

const fixture = JSON.parse(await readFile(new URL('./fixtures/firstlight-parity.json', import.meta.url), 'utf8'));

test('rule metadata matches the Python registry', () => {
  for (const [title, expected] of Object.entries(fixture.rules)) {
    assert.deepEqual(ruleMetadata(title === '__unmapped__' ? 'not a registered rule' : title), expected, title);
  }
  assert.equal(RULE_VERSION, fixture.rules['Unfamiliar successful login'].rule_version);
  assert.equal(ruleTitles().length, 10);
});

for (const c of fixture.cases) {
  test(`investigation matches Python: ${c.name}`, async () => {
    assert.deepEqual(await investigateCase(c.case, c.evidence), c.expected);
  });
  test(`integrity verdicts match Python: ${c.name}`, async () => {
    for (let i = 0; i < c.evidence.length; i++) assert.deepEqual(await verifyEvidence(c.evidence[i]), c.expected_verdicts[i], `${c.name}[${i}]`);
  });
}

for (const c of fixture.priority_cases) {
  test(`prioritization matches Python: ${c.name}`, async () => {
    assert.deepEqual(await prioritizeEvidence(c.evidence, new Date(c.now)), c.expected);
  });
}

test('sealed evidence verifies and any edit is detected', async () => {
  const sealed = await sealEvidence({ event_id: 'X1', kind: 'file', summary: 'a', timestamp: '2026-01-01T00:00:00Z' });
  assert.equal((await verifyEvidence(sealed)).valid, true);
  sealed.record.summary = 'b';
  assert.equal((await verifyEvidence(sealed)).valid, false);
  await assert.rejects(() => sealEvidence({ summary: 'no id' }), /event_id/);
});

test('timestamps: naive values are UTC, offsets honoured, impossible dates rejected', () => {
  assert.equal(timestampMs('2025-05-01T10:00:00'), timestampMs('2025-05-01T10:00:00Z'));
  assert.equal(timestampMs('2025-05-01T12:00:00+02:00'), timestampMs('2025-05-01T10:00:00Z'));
  assert.equal(timestampMs('2025-02-30T00:00:00Z'), Infinity);
  assert.equal(timestampMs('2024-02-29T00:00:00Z') < Infinity, true);
  assert.equal(timestampMs(null), Infinity);
});
