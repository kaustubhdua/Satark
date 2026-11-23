import { isAcceptableRedisRestUrl } from './redis-rest-url.mjs';
/**
 * Reports configuration only. It is not a dependency or security readiness
 * probe: model/database connectivity and actual limiter behavior are not tested.
 */
const hasValue = value => typeof value === 'string' && value.trim().length > 0;

function isFirstlightBackendUrl(value, allowLocalHttp = true) {
  if (!hasValue(value)) return false;
  try {
    const url = new URL(value.trim());
    const localHosts = new Set(['localhost', '127.0.0.1', '::1', 'firstlight-api']);
    const allowedProtocol = url.protocol === 'https:' || (allowLocalHttp && url.protocol === 'http:' && localHosts.has(url.hostname));
    return allowedProtocol && Boolean(url.hostname) && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    return false;
  }
}

/** @param {Record<string, string | undefined>} [env={}] */
export function buildHealthSnapshot(env = {}) {
  const localModelConfigured = hasValue(env.SATARK_OLLAMA_BASE_URL) && hasValue(env.SATARK_OLLAMA_MODEL);
  const firstlightApiUrlValid = isFirstlightBackendUrl(env.FIRSTLIGHT_API_URL, env.VERCEL !== '1');
  const firstlightApiTokenConfigured = hasValue(env.FIRSTLIGHT_API_TOKEN) && env.FIRSTLIGHT_API_TOKEN.trim().length >= 32;
  const firstlightWazuhSyncTokenConfigured = hasValue(env.FIRSTLIGHT_WAZUH_SYNC_TOKEN) && env.FIRSTLIGHT_WAZUH_SYNC_TOKEN.trim().length >= 32;
  const persistentStorageConfigured = isFirstlightBackendUrl(env.SATARK_API_INTERNAL_URL, env.VERCEL !== '1');
  const redisUrlPresent = hasValue(env.UPSTASH_REDIS_REST_URL);
  const redisTokenPresent = hasValue(env.UPSTASH_REDIS_REST_TOKEN);
  const redisUrlValid = isAcceptableRedisRestUrl(env.UPSTASH_REDIS_REST_URL);
  const sharedLimiterConfigured = redisUrlValid && redisTokenPresent;
  const limiterMisconfigured = redisUrlPresent !== redisTokenPresent || (redisUrlPresent && !redisUrlValid);
  const sharedLimiterRequired = env.VERCEL === '1' && !sharedLimiterConfigured && !limiterMisconfigured;

  return {
    status: 'configuration-only',
    checks: {
      analysis: { mode: 'deterministic-local', configured: true },
      localModel: { configured: localModelConfigured },
      firstlight: {
        investigationProxyConfigured: firstlightApiUrlValid && firstlightApiTokenConfigured,
        wazuhProxyConfigured: firstlightApiUrlValid && firstlightWazuhSyncTokenConfigured,
      },
      rateLimit: {
        mode: sharedLimiterConfigured ? 'shared-upstash' : limiterMisconfigured ? 'misconfigured' : sharedLimiterRequired ? 'local-fallback' : 'in-process',
        configured: sharedLimiterConfigured || !limiterMisconfigured,
        sharedAcrossInstances: sharedLimiterConfigured,
        connectivityVerified: false,
      },
      persistentStorage: {
        configured: persistentStorageConfigured,
        provider: 'self-hosted',
        clientConfigured: false,
        serverClientMatch: false,
      },
    },
    note: 'Configuration snapshot only. This endpoint does not probe model, database, Redis, or FIRSTLIGHT API connectivity, prove tenant isolation, or validate rate-limit behavior. It reports whether the self-hosted database URL is configured without exposing connection details. Analysis works without any external service; without a shared limiter it is limited per server instance, which is weaker than a shared limit. Deterministic analysis requires no third-party AI API key.',
  };
}

/** Describe the rate-limit configuration without implying that a missing shared limiter is active locally. */
export function describeRateLimitStatus(rateLimit) {
  switch (rateLimit?.mode) {
    case 'shared-upstash':
      return 'Shared rate limiting is configured; live Redis connectivity is not verified by this configuration snapshot.';
    case 'local-fallback':
      return 'No shared rate limiter is configured; analysis stays available and is limited per server instance (best effort, not shared across instances).';
    case 'misconfigured':
      return 'Shared rate limiting configuration is incomplete or unsafe and is being ignored; analysis stays available with a per-instance limit until it is corrected.';
    case 'in-process':
      return 'Rate limiting is process-local, not shared across instances; configure shared limiting before public exposure.';
    default:
      return 'Rate-limit status is unknown; verify shared limiting before relying on this service.';
  }
}
