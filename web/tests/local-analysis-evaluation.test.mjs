import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { evaluateLocalAnalysis } from '../src/lib/local-analysis-evaluation.mjs';

const corpus = JSON.parse(await readFile(new URL('../evaluation/local-analysis-cases.json', import.meta.url), 'utf8'));

test('synthetic local-analysis evaluation corpus is versioned and balanced', () => {
  assert.equal(corpus.version, 1);
  assert.equal(corpus.cases.length, 12);
  assert.equal(corpus.cases.filter(item => item.label === 'suspicious').length, 6);
  assert.equal(corpus.cases.filter(item => item.label === 'benign').length, 6);
  assert.equal(new Set(corpus.cases.map(item => item.id)).size, corpus.cases.length);
});

test('local-analysis evaluation reports confusion matrix, latency and evidence grounding', () => {
  const report = evaluateLocalAnalysis(corpus.cases);
  assert.equal(report.sample_count, 12);
  assert.deepEqual(report.confusion_matrix, {
    true_positive: 6,
    false_positive: 2,
    true_negative: 4,
    false_negative: 0,
  });
  assert.equal(report.metrics.precision, 0.75);
  assert.equal(report.metrics.recall, 1);
  assert.equal(report.metrics.f1, 0.8571);
  assert.ok(report.metrics.median_latency_ms >= 0);
  assert.ok(report.metrics.p95_latency_ms >= report.metrics.median_latency_ms);
  assert.equal(report.metrics.evidence_grounding_ratio, 1);
  assert.deepEqual(report.false_positives, ['password-training', 'verification-documentation']);
  assert.deepEqual(report.false_negatives, []);
  assert.match(report.corpus_scope, /not representative of real-world prevalence/);
  assert.ok(report.limitations.some(value => value.includes('must not be represented as production detection rates')));
});

test('evaluation rejects malformed or duplicate case definitions', () => {
  assert.throws(() => evaluateLocalAnalysis([]), /At least one evaluation case/);
  assert.throws(() => evaluateLocalAnalysis([{ id: 'x', label: 'unknown', input: 'sample' }]), /unique id/);
  assert.throws(() => evaluateLocalAnalysis([
    { id: 'duplicate', label: 'benign', input: 'first' },
    { id: 'duplicate', label: 'benign', input: 'second' },
  ]), /unique/);
});
