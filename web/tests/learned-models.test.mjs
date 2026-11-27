import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MODELS, scoreHost, scoreMessage } from '../src/lib/learned-models.mjs';
import { analyzeLocally } from '../src/lib/local-analysis.mjs';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/model-parity.json', import.meta.url), 'utf8'));

test('JS URL-host scores match the Python reference', () => {
  for (const item of fixture.hosts) {
    const got = scoreHost(item.host);
    if (!/^[a-z0-9._-]+$/.test(item.host.toLowerCase())) { assert.equal(got, null); continue; }
    assert.ok(got, item.host);
    assert.ok(Math.abs(got.score - item.score) < 1e-9, `${item.host}: ${got.score} vs ${item.score}`);
    assert.equal(got.band, item.band, item.host);
  }
});

test('JS message scores match the Python reference, including unicode and empty input', () => {
  for (const item of fixture.messages) {
    const got = scoreMessage(item.text);
    if (!item.text.trim()) { assert.equal(got, null); continue; }
    assert.ok(Math.abs(got.score - item.score) < 1e-9, `${JSON.stringify(item.text.slice(0, 30))}: ${got.score} vs ${item.score}`);
    assert.equal(got.band, item.band);
  }
});

test('shipped model files record their training data and held-out metrics', () => {
  for (const m of Object.values(MODELS)) {
    assert.ok(m.metrics.test_roc_auc > 0.9);
    assert.ok(m.metrics.at_high_threshold.false_positive_rate < 0.02);
    assert.match(JSON.stringify(m.training), /sha256/);
  }
});

test('analysis adds learned-model signals as advisory evidence and still works for benign text', () => {
  const bad = analyzeLocally('WINNER! You have won a £1000 prize. Claim at http://secure-update-account.xyz/now');
  assert.ok(bad.evidence.some((e) => e.category === 'learned-model'));
  assert.ok(bad.limitations.some((l) => /learned models/i.test(l)));
  const good = analyzeLocally('Lunch at noon? Menu is at https://github.com/');
  assert.ok(!good.evidence.some((e) => e.category === 'learned-model'));
  assert.equal(good.learned_models.length, 2);
});
