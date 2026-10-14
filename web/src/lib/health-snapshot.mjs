/**
 * Reports configuration only. Do not interpret this as a dependency or security
 * readiness probe: the serverless limiter is per-instance and storage/model
 * connectivity is not checked here.
 * @param {Record<string, string | undefined>} [env={}]
 */
const hasValue = value => typeof value === 'string' && value.trim().length > 0;

/** @param {Record<string, string | undefined>} [env={}] */
export function buildHealthSnapshot(env = {}) {
  const localModelConfigured = hasValue(env.SATARK_OLLAMA_BASE_URL) && hasValue(env.SATARK_OLLAMA_MODEL);
  const persistentStorageConfigured = hasValue(env.SUPABASE_URL) && hasValue(env.SUPABASE_PUBLISHABLE_KEY);

  return {
    status: 'configuration-only',
    checks: {
      analysis: { mode: 'deterministic-local', configured: true },
      localModel: { configured: localModelConfigured },
      rateLimit: { mode: 'in-process', configured: true, sharedAcrossInstances: false },
      persistentStorage: { configured: persistentStorageConfigured },
    },
    note: 'Configuration snapshot only. This endpoint does not probe model or database connectivity, prove tenant isolation, or validate shared rate limiting. Deterministic analysis requires no third-party API key.',
  };
}
