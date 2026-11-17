import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  MAX_POINTS, LEVELS, canStartLevel, computePoints, emptyProgress, finishLevel, levelsMissingPerfect,
  normalizeProgress, rankForLevel, tierForLevel,
} from '../src/lib/scam-challenge.mjs';

const read = (name) => JSON.parse(readFileSync(new URL(`../src/data/learning/${name}`, import.meta.url), 'utf8'));
const ranks = read('ranks.json');
const constants = read('constants.json');
const parity = read('points-parity.json');

const play = (progress, level, correct, seconds = 2) => finishLevel(progress, ranks, level, {
  correct, times: Array(10).fill(seconds), points: correct * computePoints(true, seconds),
});

test('scoring matches the Python implementation exactly (parity vectors exported from Python)', () => {
  for (const [t, expected] of parity.correct) assert.equal(computePoints(true, t), expected, `correct @ ${t}s`);
  for (const [t, expected] of parity.incorrect) assert.equal(computePoints(false, t), expected, `incorrect @ ${t}s`);
  assert.equal(computePoints(true, parity.negativeElapsed[0]), parity.negativeElapsed[1]);
  assert.equal(constants.maxPoints, MAX_POINTS);
  assert.equal(computePoints(true, Number.NaN), MAX_POINTS);
});

test('tiers and ranks match the exported Python constants', () => {
  for (const [tier, upper] of Object.entries(constants.tierBoundaries)) {
    assert.equal(tierForLevel(upper), Number(tier));
    if (upper < LEVELS) assert.equal(tierForLevel(upper + 1), Number(tier) + 1);
  }
  assert.equal(tierForLevel(1), 1);
  assert.equal(tierForLevel(100), 7);
  const covered = ranks.flatMap((rank) => Array.from({ length: rank.hi - rank.lo + 1 }, (_, i) => rank.lo + i));
  assert.deepEqual(covered, Array.from({ length: 100 }, (_, i) => i + 1));
  assert.equal(rankForLevel(1, ranks).name, 'DIGITAL ROOKIE');
  assert.equal(rankForLevel(100, ranks).name, 'SATARK LEGEND');
  assert.equal(rankForLevel(0, ranks).name, 'DIGITAL ROOKIE');
  assert.equal(rankForLevel(999, ranks).name, 'SATARK LEGEND');
});

test('a fresh game only unlocks level 1', () => {
  const progress = emptyProgress();
  assert.equal(canStartLevel(progress, 1), true);
  assert.equal(canStartLevel(progress, 2), false);
  assert.equal(canStartLevel(progress, 0), false);
  assert.equal(canStartLevel(progress, 101), false);
  assert.equal(canStartLevel(progress, 1.5), false);
});

test('passing at 50% advances only the frontier level', () => {
  let outcome = play(emptyProgress(), 1, 4);
  assert.equal(outcome.result.passed, false);
  assert.equal(outcome.progress.highestUnlocked, 1);
  outcome = play(outcome.progress, 1, 5);
  assert.equal(outcome.result.passed, true);
  assert.equal(outcome.progress.highestUnlocked, 2);
  // Replaying an earlier cleared level never moves the frontier.
  const replay = play(outcome.progress, 1, 10);
  assert.equal(replay.progress.highestUnlocked, 2);
  // Replaying the frontier-1 level with a pass keeps it at 2; clearing level 2 moves to 3.
  assert.equal(play(replay.progress, 2, 7).progress.highestUnlocked, 3);
});

test('best score and best correct-count survive worse replays', () => {
  let outcome = play(emptyProgress(), 1, 9, 1);
  const best = outcome.progress.scores[1];
  outcome = play(outcome.progress, 1, 5, 30);
  assert.equal(outcome.progress.scores[1], best);
  assert.equal(outcome.progress.bestCorrect[1], 9);
  assert.equal(outcome.progress.stats[1].correct, 5, 'latest stats reflect the latest run');
  assert.equal(outcome.progress.totalScore, best);
  assert.deepEqual(outcome.progress.completed, [1]);
});

test('a rank boundary stays locked until every level in the rank has been aced', () => {
  const rank = ranks[0]; // levels 1..10
  let progress = emptyProgress();
  for (let level = 1; level <= 9; level += 1) progress = play(progress, level, 6).progress;
  assert.equal(progress.highestUnlocked, 10);
  const blocked = play(progress, 10, 10);
  assert.equal(blocked.progress.highestUnlocked, 10, 'level 10 passes but the next rank stays locked');
  assert.equal(blocked.rankUp, null);
  assert.deepEqual(blocked.blockedByRank.missing, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(blocked.progress.perfect.includes(10), true);

  // Ace every remaining level, then level 10 opens rank II.
  progress = blocked.progress;
  for (let level = 1; level <= 9; level += 1) progress = play(progress, level, 10).progress;
  assert.deepEqual(levelsMissingPerfect(progress, rank), []);
  const rankUp = play(progress, 10, 5);
  assert.equal(rankUp.progress.highestUnlocked, 11);
  assert.equal(rankUp.rankUp.name, 'SCAM SCOUT');
  assert.equal(rankUp.blockedByRank, null);
});

test('level 100 can be completed but never advances past the cap', () => {
  const progress = { ...emptyProgress(), highestUnlocked: 100 };
  const outcome = play(progress, 100, 10);
  assert.equal(outcome.progress.highestUnlocked, 100);
  assert.equal(outcome.result.isLegend, true);
  assert.equal(play(progress, 100, 3).result.isLegend, false);
});

test('finishLevel never mutates its input and validates arguments', () => {
  const progress = emptyProgress();
  const frozen = JSON.stringify(progress);
  play(progress, 1, 7);
  assert.equal(JSON.stringify(progress), frozen);
  assert.throws(() => finishLevel(progress, ranks, 0, { correct: 5, times: [], points: 0 }), RangeError);
  assert.throws(() => finishLevel(progress, ranks, 1, { correct: 11, times: [], points: 0 }), RangeError);
  assert.throws(() => finishLevel(progress, ranks, 1, { correct: -1, times: [], points: 0 }), RangeError);
});

test('stored progress survives a JSON round trip and rejects tampering', () => {
  let progress = emptyProgress();
  for (let level = 1; level <= 4; level += 1) progress = play(progress, level, 10).progress;
  const restored = normalizeProgress(JSON.parse(JSON.stringify(progress)));
  assert.deepEqual(restored, progress);

  for (const garbage of [null, undefined, 5, 'x', [], {}, { version: 99 }, { version: 1, highestUnlocked: 'a' }]) {
    assert.deepEqual(normalizeProgress(garbage), emptyProgress(), JSON.stringify(garbage));
  }
  const tampered = normalizeProgress({
    version: 1, highestUnlocked: 500, completed: [1, 1, 2, 'x', 999], perfect: [1, 2, 3],
    scores: { 1: 99999999, 2: 1500, 3: -1, abc: 5 }, bestCorrect: { 1: 10, 2: 4, 3: 99 }, stats: { 1: { correct: 99 } },
  });
  assert.equal(tampered.highestUnlocked, 1, 'out-of-range frontier is discarded');
  assert.deepEqual(tampered.completed, [1, 2]);
  assert.deepEqual(tampered.perfect, [1], 'perfect requires a recorded 10/10');
  assert.deepEqual(tampered.scores, { 2: 1500 });
  assert.deepEqual(tampered.bestCorrect, { 1: 10, 2: 4 });
  assert.deepEqual(tampered.stats, {});
  assert.equal(tampered.totalScore, 1500);
});

test('normalizeProgress clamps a forged frontier to cleared levels', async () => {
  const { normalizeProgress } = await import('../src/lib/scam-challenge.mjs');
  const forged = normalizeProgress({ version: 1, highestUnlocked: 99, completed: [1], perfect: [], scores: {}, bestCorrect: {} });
  assert.equal(forged.highestUnlocked, 2);
});
