// Per-tab record of the analyses a person ran in this browser session.
//
// Privacy by design: only the threat category, the heuristic priority score and
// a timestamp are kept. The analysed text, URLs and results are never stored
// here. The log lives in sessionStorage, so it disappears when the tab closes,
// and the Classroom page is a teaching aid, not a student record.

export const SESSION_LOG_KEY = 'satark:session-analyses:v1';
export const MAX_ENTRIES = 200;
export const HIGH_PRIORITY_THRESHOLD = 70;

const clampScore = (value) => {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, Math.round(number))) : 0;
};

function normalizeEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const at = typeof raw.at === 'string' && !Number.isNaN(Date.parse(raw.at)) ? new Date(raw.at).toISOString() : null;
  if (!at) return null;
  const category = typeof raw.category === 'string' && raw.category.trim() ? raw.category.trim().slice(0, 80) : 'Needs review';
  return { at, category, score: clampScore(raw.score) };
}

export function parseLog(serialized) {
  try {
    const parsed = JSON.parse(serialized ?? '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.map(normalizeEntry).filter(Boolean).slice(-MAX_ENTRIES);
  } catch {
    return [];
  }
}

export function appendEntry(entries, { category, score, now = new Date() }) {
  const entry = normalizeEntry({ at: now.toISOString(), category, score });
  return entry ? [...entries, entry].slice(-MAX_ENTRIES) : entries;
}

export function summarize(entries) {
  const total = entries.length;
  const average = total ? Math.round(entries.reduce((sum, entry) => sum + entry.score, 0) / total) : 0;
  const highPriority = entries.filter((entry) => entry.score >= HIGH_PRIORITY_THRESHOLD).length;
  const counts = new Map();
  for (const entry of entries) counts.set(entry.category, (counts.get(entry.category) ?? 0) + 1);
  const patterns = [...counts.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
  return { total, average, highPriority, patterns };
}

export function summaryText(entries, now = new Date()) {
  const { total, average, highPriority, patterns } = summarize(entries);
  return [
    'SATARK Classroom Session Summary',
    `Generated: ${now.toISOString()}`,
    '',
    `Analyses: ${total}`,
    `Average heuristic priority: ${average}/100`,
    `High-priority results (>= ${HIGH_PRIORITY_THRESHOLD}): ${highPriority}`,
    '',
    'Patterns:',
    ...(patterns.length ? patterns.map(({ category, count }) => `- ${category}: ${count}`) : ['- none']),
    '',
    'Priority scores are triage signals, not verdicts. This summary contains no analysed content and is not a student record.',
    '',
  ].join('\n');
}
