import { createHash } from 'node:crypto';

const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 8;
const MAX_TRACKED_CLIENTS = 2_000;
const localCounts = new Map();

function getClientKey(request) {
  const client = request.headers.get('x-real-ip')?.trim() || 'unknown';
  return createHash('sha256').update(client).digest('hex').slice(0, 32);
}

function localLimit(key, now) {
  if (localCounts.size >= MAX_TRACKED_CLIENTS) {
    for (const [trackedKey, entry] of localCounts) {
      if (now - entry.start >= WINDOW_MS) localCounts.delete(trackedKey);
    }
    if (localCounts.size >= MAX_TRACKED_CLIENTS && !localCounts.has(key)) return true;
  }
  const entry = localCounts.get(key);
  if (!entry || now - entry.start >= WINDOW_MS) {
    localCounts.set(key, { start: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_REQUESTS_PER_WINDOW;
}

/**
 * Bounded in-process throttle for the inexpensive local-only analysis endpoint.
 * It is not a globally shared limiter across serverless instances; deploy behind
 * a host-level rate limit if exposed publicly. Self-hosted single-instance mode
 * needs no Redis credentials or external rate-limit service.
 */
export function createRateLimiter({ now = Date.now } = {}) {
  return async function checkRateLimit(request) {
    return {
      limited: localLimit(getClientKey(request), now()),
      unavailable: false,
      mode: 'local',
    };
  };
}

export const checkAnalysisRateLimit = createRateLimiter();
