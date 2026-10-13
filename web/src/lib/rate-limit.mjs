import { createHash } from 'node:crypto';

const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 8;
const MAX_TRACKED_CLIENTS = 2_000;
const localCounts = new Map();

function getClientKey(request) {
  // Trust only the single-hop header supplied by the hosting platform. Never
  // use the caller-controlled first value in x-forwarded-for.
  const client = request.headers.get('x-real-ip')?.trim() || 'unknown';
  return createHash('sha256').update(client).digest('hex').slice(0, 32);
}

function localLimit(key, now) {
  if (localCounts.size >= MAX_TRACKED_CLIENTS) {
    for (const [trackedKey, entry] of localCounts) {
      if (now - entry.start >= WINDOW_MS) localCounts.delete(trackedKey);
    }
    if (localCounts.size >= MAX_TRACKED_CLIENTS && !localCounts.has(key)) {
      return true;
    }
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
 * Create a bounded analysis endpoint limiter.
 *
 * When Upstash REST credentials are configured, the atomic Redis script is
 * shared across serverless instances. If that configured backend fails, callers
 * receive an unavailable result instead of silently falling back to a weaker
 * per-instance limit. Without credentials, retain the explicitly best-effort
 * in-process fallback for local development.
 */
export function createRateLimiter({
  env = process.env,
  fetchImpl = fetch,
  now = Date.now,
} = {}) {
  return async function checkRateLimit(request) {
    const key = getClientKey(request);
    const redisUrl = env.UPSTASH_REDIS_REST_URL;
    const redisToken = env.UPSTASH_REDIS_REST_TOKEN;

    if (Boolean(redisUrl) !== Boolean(redisToken)) {
      return { limited: false, unavailable: true, mode: 'shared' };
    }

    if (!redisUrl || !redisToken) {
      return { limited: localLimit(key, now()), unavailable: false, mode: 'local' };
    }

    const script = "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); end; return count";
    const redisKey = 'satark:analysis:rate:' + key;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1800);

    try {
      const response = await fetchImpl(redisUrl, {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + redisToken,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(['EVAL', script, '1', redisKey, String(WINDOW_MS)]),
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!response.ok) return { limited: false, unavailable: true, mode: 'shared' };
      const payload = await response.json();
      if (payload?.error || !Number.isInteger(payload?.result) || payload.result < 1) {
        return { limited: false, unavailable: true, mode: 'shared' };
      }
      return { limited: payload.result > MAX_REQUESTS_PER_WINDOW, unavailable: false, mode: 'shared' };
    } catch {
      return { limited: false, unavailable: true, mode: 'shared' };
    } finally {
      clearTimeout(timeout);
    }
  };
}

export const checkAnalysisRateLimit = createRateLimiter();
