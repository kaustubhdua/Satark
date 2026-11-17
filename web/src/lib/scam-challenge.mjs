// Scam Challenge engine: pure, immutable game rules.
//
// A faithful port of the rules in the repository's Python implementation
// (scam_challenge.py). Question content is exported from that file by
// scripts/export_learning_content.py; tests assert parity for scoring, ranks
// and tiers so the two implementations cannot silently diverge.
//
// This is a training game. Progress is stored per browser (localStorage) and
// is a convenience, not a record or a credential.

export const MAX_POINTS = 2000;
export const QUESTIONS_PER_LEVEL = 10;
export const LEVELS = 100;
export const PASS_CORRECT = QUESTIONS_PER_LEVEL / 2;
export const PROGRESS_VERSION = 1;
export const STORAGE_KEY = 'satark:challenge:v1';

const TIER_UPPER_BOUNDS = [10, 20, 40, 60, 80, 90, 100];

export function tierForLevel(level) {
  const index = TIER_UPPER_BOUNDS.findIndex((upper) => level <= upper);
  return index === -1 ? TIER_UPPER_BOUNDS.length : index + 1;
}

export function rankForLevel(level, ranks) {
  const clamped = Math.max(1, Math.min(LEVELS, level));
  return ranks.find((rank) => rank.lo <= clamped && clamped <= rank.hi) ?? ranks[ranks.length - 1];
}

// Python's round() rounds halves to even; Math.round rounds halves up.
function roundHalfEven(value) {
  const floor = Math.floor(value);
  const diff = value - floor;
  if (diff < 0.5) return floor;
  if (diff > 0.5) return floor + 1;
  return floor % 2 === 0 ? floor : floor + 1;
}

/** Points for one answer: exponential decay with answer time, floored at 8% of max. */
export function computePoints(correct, elapsedSeconds) {
  if (!correct) return 0;
  const t = Math.max(0, Number.isFinite(elapsedSeconds) ? elapsedSeconds : 0);
  const raw = MAX_POINTS * Math.exp(-t / 18);
  const floorPoints = Math.trunc(MAX_POINTS * 0.08);
  return Math.max(floorPoints, Math.min(MAX_POINTS, roundHalfEven(raw)));
}

export function emptyProgress() {
  return {
    version: PROGRESS_VERSION,
    highestUnlocked: 1,
    completed: [],
    perfect: [],
    scores: {},
    bestCorrect: {},
    stats: {},
    totalScore: 0,
  };
}

const isLevel = (value) => Number.isInteger(value) && value >= 1 && value <= LEVELS;
const clean = (levels) => [...new Set((Array.isArray(levels) ? levels : []).filter(isLevel))].sort((a, b) => a - b);

/** Defensive restore from untrusted storage; anything malformed becomes a fresh game. */
export function normalizeProgress(raw) {
  try {
    if (!raw || typeof raw !== 'object' || raw.version !== PROGRESS_VERSION) return emptyProgress();
    const scores = {};
    for (const [key, value] of Object.entries(raw.scores ?? {})) {
      const level = Number(key);
      if (isLevel(level) && Number.isFinite(value) && value >= 0 && value <= MAX_POINTS * QUESTIONS_PER_LEVEL) scores[level] = Math.round(value);
    }
    const bestCorrect = {};
    for (const [key, value] of Object.entries(raw.bestCorrect ?? {})) {
      const level = Number(key);
      if (isLevel(level) && Number.isInteger(value) && value >= 0 && value <= QUESTIONS_PER_LEVEL) bestCorrect[level] = value;
    }
    const stats = {};
    for (const [key, value] of Object.entries(raw.stats ?? {})) {
      const level = Number(key);
      if (isLevel(level) && value && Number.isInteger(value.correct) && value.correct >= 0 && value.correct <= QUESTIONS_PER_LEVEL
        && Number.isFinite(value.avgTime) && value.avgTime >= 0 && Number.isFinite(value.score) && value.score >= 0) {
        stats[level] = { correct: value.correct, incorrect: QUESTIONS_PER_LEVEL - value.correct, avgTime: value.avgTime, score: Math.round(value.score) };
      }
    }
    const completed = clean(raw.completed);
    // A level can only be "perfect" if its best result really was 10/10.
    const perfect = clean(raw.perfect).filter((level) => bestCorrect[level] === QUESTIONS_PER_LEVEL);
    // The frontier can never run ahead of the levels actually cleared.
    const ceiling = Math.min(100, (completed.length ? Math.max(...completed) : 0) + 1);
    const highest = isLevel(raw.highestUnlocked) ? Math.min(raw.highestUnlocked, ceiling) : 1;
    return {
      version: PROGRESS_VERSION,
      highestUnlocked: highest,
      completed,
      perfect,
      scores,
      bestCorrect,
      stats,
      totalScore: Object.values(scores).reduce((sum, value) => sum + value, 0),
    };
  } catch {
    return emptyProgress();
  }
}

export function canStartLevel(progress, level) {
  return isLevel(level) && level <= progress.highestUnlocked;
}

/** Levels in a rank that still need a 10/10 before the rank boundary opens. */
export function levelsMissingPerfect(progress, rank) {
  const missing = [];
  for (let level = rank.lo; level <= rank.hi; level += 1) if (!progress.perfect.includes(level)) missing.push(level);
  return missing;
}

/**
 * Record a finished level.
 *
 * Rules (identical to the Python game):
 *  - best score and best correct-count per level are kept across replays;
 *  - a level passes with at least 50% correct;
 *  - only the frontier level (the highest unlocked) advances progress;
 *  - a rank's last level only opens the next rank once every level in that
 *    rank has been aced (10/10) at least once.
 */
export function finishLevel(progress, ranks, level, { correct, times, points }) {
  if (!isLevel(level)) throw new RangeError('level out of range');
  if (!Number.isInteger(correct) || correct < 0 || correct > QUESTIONS_PER_LEVEL) throw new RangeError('correct out of range');
  const avgTime = times.length ? times.reduce((sum, value) => sum + value, 0) / times.length : 0;
  const next = {
    ...progress,
    completed: [...progress.completed],
    perfect: [...progress.perfect],
    scores: { ...progress.scores },
    bestCorrect: { ...progress.bestCorrect },
    stats: { ...progress.stats },
  };
  next.scores[level] = Math.max(next.scores[level] ?? 0, points);
  next.bestCorrect[level] = Math.max(next.bestCorrect[level] ?? 0, correct);
  if (next.bestCorrect[level] >= QUESTIONS_PER_LEVEL && !next.perfect.includes(level)) next.perfect.push(level);
  next.stats[level] = { correct, incorrect: QUESTIONS_PER_LEVEL - correct, avgTime, score: points };
  if (!next.completed.includes(level)) next.completed.push(level);
  next.completed.sort((a, b) => a - b);
  next.perfect.sort((a, b) => a - b);
  next.totalScore = Object.values(next.scores).reduce((sum, value) => sum + value, 0);

  const passed = correct >= PASS_CORRECT;
  let rankUp = null;
  let blockedByRank = null;
  if (passed && level === next.highestUnlocked && level < LEVELS) {
    const rank = rankForLevel(level, ranks);
    if (level === rank.hi) {
      const missing = levelsMissingPerfect(next, rank);
      if (missing.length === 0) {
        next.highestUnlocked = level + 1;
        rankUp = rankForLevel(level + 1, ranks);
      } else {
        blockedByRank = { rank, missing };
      }
    } else {
      next.highestUnlocked = level + 1;
    }
  }
  return {
    progress: next,
    rankUp,
    blockedByRank,
    result: { level, score: points, correct, incorrect: QUESTIONS_PER_LEVEL - correct, avgTime, passed, isLegend: level === LEVELS && passed },
  };
}
