/**
 * Reports configuration only. It is not a dependency or security readiness
 * probe: model/database connectivity and actual limiter behavior are not tested.
 */
const hasValue = value => typeof value === 'string' && value.trim().length > 0;

/** @param {Record<string, string | undefined>} [env={}] */
export function buildHealthSnapshot(env = {}) {
  const localModelConfigured = hasValue(env.SATARK_OLLAMA_BASE_URL) && hasValue(env.SATARK_OLLAMA_MODEL);
  const persistentStorageConfigured = hasValue(env.SUPABASE_URL) && hasValue(env.SUPABASE_PUBLISHABLE_KEY);
  const redisUrl = hasValue(env.UPSTASH_REDIS_REST_URL);
  const redisToken = hasValue(env.UPSTASH_REDIS_REST_TOKEN);
  const sharedLimiterConfigured = redisUrl && redisToken;
  const limiterMisconfigured = redisUrl !== redisToken;
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
