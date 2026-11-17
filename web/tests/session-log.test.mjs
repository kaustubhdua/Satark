import assert from 'node:assert/strict';
import test from 'node:test';
import { MAX_ENTRIES, appendEntry, parseLog, summarize, summaryText } from '../src/lib/session-log.mjs';

const at = new Date('2026-11-17T08:00:00Z');

test('an empty session summarises to zeros, not NaN', () => {
  assert.deepEqual(summarize([]), { total: 0, average: 0, highPriority: 0, patterns: [] });
});

test('summary counts, averages and ranks patterns', () => {
  let log = [];
  for (const [category, score] of [['Phishing', 90], ['Phishing', 70], ['Safe', 10], ['OTP Scam', 85]]) {
    log = appendEntry(log, { category, score, now: at });
  }
  const summary = summarize(log);
  assert.equal(summary.total, 4);
  assert.equal(summary.average, 64);
  assert.equal(summary.highPriority, 3, 'the >= 70 boundary is inclusive');
  assert.deepEqual(summary.patterns, [
    { category: 'Phishing', count: 2 }, { category: 'OTP Scam', count: 1 }, { category: 'Safe', count: 1 },
  ]);
});

test('entries never carry analysed content and clamp hostile values', () => {
  const log = appendEntry([], { category: 'x'.repeat(500), score: 9999, now: at });
  assert.deepEqual(Object.keys(log[0]).sort(), ['at', 'category', 'score']);
  assert.equal(log[0].score, 100);
  assert.equal(log[0].category.length, 80);
  assert.equal(appendEntry([], { category: 'a', score: Number.NaN, now: at })[0].score, 0);
  assert.equal(appendEntry([], { category: '   ', score: 5, now: at })[0].category, 'Needs review');
});

test('the log is capped and keeps the newest entries', () => {
  let log = [];
  for (let i = 0; i < MAX_ENTRIES + 25; i += 1) log = appendEntry(log, { category: `c${i}`, score: 1, now: at });
  assert.equal(log.length, MAX_ENTRIES);
  assert.equal(log.at(-1).category, `c${MAX_ENTRIES + 24}`);
  assert.equal(log[0].category, 'c25');
});

test('parseLog tolerates corrupt or tampered storage', () => {
  for (const bad of [null, undefined, '', 'not json', '{}', '"x"', '5', 'null']) assert.deepEqual(parseLog(bad), [], String(bad));
  const mixed = JSON.stringify([{ at: at.toISOString(), category: 'Phishing', score: 50 }, { at: 'nope', score: 1 }, null, 7, { category: 'x' }]);
  assert.equal(parseLog(mixed).length, 1);
});

test('the exported summary is plain text with a limitations note and no content', () => {
  const text = summaryText(appendEntry([], { category: 'Phishing', score: 88, now: at }), at);
  assert.match(text, /Analyses: 1/);
  assert.match(text, /- Phishing: 1/);
  assert.match(text, /not a student record/);
  assert.match(summaryText([], at), /- none/);
});
