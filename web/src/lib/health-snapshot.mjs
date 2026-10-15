/**
 * Reports configuration only. It is not a dependency or security readiness
 * probe: model/database connectivity and actual limiter behavior are not tested.
 */
const hasValue = value => typeof value === 'string' && value.trim().length > 0;

function isHttpsUrl(value) {
  if (!hasValue(value)) return false;
  try {
    const url = new URL(value.trim());
    return url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password;
  } catch {
    return false;
  }
}

/** @param {Record<string, string | undefined>} [env={}] */
export function buildHealthSnapshot(env = {}) {
  const localModelConfigured = hasValue(env.SATARK_OLLAMA_BASE_URL) && hasValue(env.SATARK_OLLAMA_MODEL);
  const persistentStorageConfigured = isHttpsUrl(env.SUPABASE_URL) && hasValue(env.SUPABASE_PUBLISHABLE_KEY);
  const redisUrlPresent = hasValue(env.UPSTASH_REDIS_REST_URL);
  const redisTokenPresent = hasValue(env.UPSTASH_REDIS_REST_TOKEN);
  const redisUrlValid = isHttpsUrl(env.UPSTASH_REDIS_REST_URL);
  const sharedLimiterConfigured = redisUrlValid && redisTokenPresent;
  const limiterMisconfigured = redisUrlPresent !== redisTokenPresent || (redisUrlPresent && !redisUrlValid);
  const sharedLimiterRequired = env.VERCEL === '1' && !sharedLimiterConfigured && !limiterMisconfigured;

  return {
    status: 'configuration-only',
    checks: {
      analysis: { mode: 'deterministic-local', configured: true },
      localModel: { configured: localModelConfigured },
      rateLimit: {
        mode: sharedLimiterConfigured ? 'shared-upstash' : limiterMisconfigured ? 'misconfigured' : sharedLimiterRequired ? 'shared-required' : 'in-process',
        configured: sharedLimiterConfigured || (!limiterMisconfigured && !sharedLimiterRequired),
        sharedAcrossInstances: sharedLimiterConfigured,
        connectivityVerified: false,
      },
      persistentStorage: { configured: persistentStorageConfigured },
    },
    note: 'Configuration snapshot only. This endpoint does not probe model, database, or Redis connectivity, prove tenant isolation, or validate rate-limit behavior. On Vercel, analysis requires a configured shared limiter; process-local limits are for local development only. Deterministic analysis requires no third-party AI API key.',
  };
}

/** Describe the rate-limit configuration without implying that a missing shared limiter is active locally. */
export function describeRateLimitStatus(rateLimit) {
  switch (rateLimit?.mode) {
    case 'shared-upstash':
      return 'Shared rate limiting is configured; live Redis connectivity is not verified by this configuration snapshot.';
    case 'shared-required':
      return 'Shared rate limiting is not configured; production analysis is disabled and fails closed until it is.';
    case 'misconfigured':
      return 'Shared rate limiting configuration is incomplete or unsafe; production analysis is disabled and fails closed until it is corrected.';
    case 'in-process':
      return 'Rate limiting is process-local, not shared across instances; configure shared limiting before public exposure.';
    default:
      return 'Rate-limit status is unknown; verify shared limiting before relying on this service.';
  }
}
