import { createHash } from 'node:crypto';

const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 8;
const MAX_TRACKED_CLIENTS = 2_000;
const localCounts = new Map();

const SHARED_LIMIT_SCRIPT = [
  "local count = redis.call('INCR', KEYS[1])",
  "if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end",
  "local ttl = redis.call('PTTL', KEYS[1])",
  "return { count, ttl }",
].join('\n');

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

function sharedConfig(env) {
  const url = env.UPSTASH_REDIS_REST_URL?.trim();
  const token = env.UPSTASH_REDIS_REST_TOKEN?.trim();
  if (!url && !token) return { mode: 'local' };
  if (!url || !token) return { mode: 'misconfigured' };
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || !parsed.hostname) return { mode: 'misconfigured' };
  } catch {
    return { mode: 'misconfigured' };
  }
  return { mode: 'shared', url: url.replace(/\/$/, ''), token };
}

async function sharedLimit(key, config, fetcher) {
  try {
    const response = await fetcher(config.url, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + config.token,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify([
        'EVAL', SHARED_LIMIT_SCRIPT, '1',
        'satark:analysis:rate:' + key,
        String(WINDOW_MS),
      ]),
      cache: 'no-store',
      signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok) return { limited: false, unavailable: true, mode: 'shared' };
    const payload = await response.json();
    const result = payload?.result;
    if (!Array.isArray(result) || !Number.isInteger(Number(result[0])) || Number(result[0]) < 1) {
      return { limited: false, unavailable: true, mode: 'shared' };
    }
    return {
      limited: Number(result[0]) > MAX_REQUESTS_PER_WINDOW,
      unavailable: false,
      mode: 'shared',
    };
  } catch {
    // Do not silently downgrade to per-instance throttling when shared limiting
    // was explicitly configured: a provider outage must fail closed.
    return { limited: false, unavailable: true, mode: 'shared' };
  }
}

/**
 * Uses an atomic Upstash Redis REST/Lua counter when configured. If shared
 * limiting was requested but is misconfigured or unavailable, fails closed.
 * Without shared credentials, uses a bounded in-process fallback suitable only
 * for local development or a single trusted instance—not a distributed quota.
 */
export function createRateLimiter({ now = Date.now, env = process.env, fetcher = fetch } = {}) {
  const config = sharedConfig(env);
  return async function checkRateLimit(request) {
    const key = getClientKey(request);
    if (config.mode === 'misconfigured') {
      return { limited: false, unavailable: true, mode: 'misconfigured' };
    }
    if (config.mode === 'shared') return sharedLimit(key, config, fetcher);
    return {
      limited: localLimit(key, now()),
      unavailable: false,
      mode: 'local',
    };
  };
}

export const checkAnalysisRateLimit = createRateLimiter();
