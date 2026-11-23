import { isAcceptableRedisRestUrl } from './redis-rest-url.mjs';
import { createHash } from 'node:crypto';
import { readBoundedResponseText } from './read-bounded-response.mjs';

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
  if (!url && !token) return { mode: env.VERCEL === '1' ? 'local-fallback' : 'local' };
  if (!url || !token) return { mode: 'misconfigured' };
  try {
    const parsed = new URL(url);
    if (!isAcceptableRedisRestUrl(url) || !parsed.hostname) return { mode: 'misconfigured' };
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
    const bounded = await readBoundedResponseText(response, 16 * 1024);
    if (!bounded.ok) return { limited: false, unavailable: true, mode: 'shared' };
    let payload;
    try { payload = JSON.parse(bounded.text); }
    catch { return { limited: false, unavailable: true, mode: 'shared' }; }
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
    // Never downgrade a configured distributed limiter to process-local behavior.
    return { limited: false, unavailable: true, mode: 'shared' };
  }
}

/**
 * Uses atomic shared Redis counters when configured. Public analysis is deterministic,
 * local and bounded (48 KiB bodies), so it stays available when no shared limiter is
 * configured, the configuration is unusable, or the shared store is unreachable: the
 * request is then limited by a best-effort per-instance counter. That is weaker than a
 * shared limit on serverless platforms (each instance counts separately) and is reported
 * honestly by /api/health as `local-fallback` rather than presented as distributed.
 */
export function createRateLimiter({ now = Date.now, env = process.env, fetcher = fetch } = {}) {
  const config = sharedConfig(env);
  return async function checkRateLimit(request) {
    const key = getClientKey(request);
    if (config.mode === 'shared') {
      const shared = await sharedLimit(key, config, fetcher);
      if (!shared.unavailable) return shared;
      return { limited: localLimit(key, now()), unavailable: false, mode: 'shared-degraded' };
    }
    return { limited: localLimit(key, now()), unavailable: false, mode: config.mode };
  };
}

export const checkAnalysisRateLimit = createRateLimiter();
