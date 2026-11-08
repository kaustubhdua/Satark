/**
 * Configuration-aware capability registry.
 * Configured dependencies are not healthy until a real runtime probe proves it.
 * Never include secret values in this response.
 */
const hasValue = value => typeof value === 'string' && value.trim().length > 0;
function isSelfHostedApiUrl(value, allowLocalHttp = true) {
  if (!hasValue(value)) return false;
  try {
    const url = new URL(value.trim());
    const localHosts = new Set(['localhost', '127.0.0.1', '::1', 'firstlight-api']);
    const allowed = url.protocol === 'https:' || (allowLocalHttp && url.protocol === 'http:' && localHosts.has(url.hostname));
    return allowed && !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}

function capability(id, name, configured, details, configuredStatus = 'configured') {
  return { id, name, status: configured ? configuredStatus : 'disabled', configured: Boolean(configured), healthVerified: false, details };
}

/** @param {Record<string, string | undefined>} [env={}] */
export function buildCapabilityRegistry(env = {}) {
  const storageConfigured = isSelfHostedApiUrl(env.SATARK_API_INTERNAL_URL, env.VERCEL !== '1');
  const firstlightConfigured = storageConfigured;
  const wazuhConfigured = hasValue(env.FIRSTLIGHT_WAZUH_INDEXER_URL) &&
    hasValue(env.FIRSTLIGHT_WAZUH_INDEXER_USERNAME) &&
    hasValue(env.FIRSTLIGHT_WAZUH_INDEXER_PASSWORD) &&
    hasValue(env.FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS);
  const redisConfigured = hasValue(env.UPSTASH_REDIS_REST_URL) &&
    /^https:\/\//i.test(env.UPSTASH_REDIS_REST_URL.trim()) && hasValue(env.UPSTASH_REDIS_REST_TOKEN);
  const modelConfigured = hasValue(env.SATARK_OLLAMA_BASE_URL) && hasValue(env.SATARK_OLLAMA_MODEL);
  const firstlightConfigured = hasValue(env.FIRSTLIGHT_API_URL) &&
    hasValue(env.FIRSTLIGHT_API_TOKEN) && env.FIRSTLIGHT_API_TOKEN.trim().length >= 32;
  const wazuhConfigured = firstlightConfigured && hasValue(env.FIRSTLIGHT_WAZUH_SYNC_TOKEN) &&
    env.FIRSTLIGHT_WAZUH_SYNC_TOKEN.trim().length >= 32;
  const capabilities = [
    capability('analysis.deterministic', 'Deterministic analysis', true, 'Analysis code is present; this endpoint does not execute analysis requests.'),
    capability('storage.self_hosted', 'Self-hosted persistent storage', storageConfigured,
      'Private SATARK FastAPI and database URL are configured; database connectivity, schema compatibility and tenant isolation are not probed.'),
    capability('rate_limit.shared', 'Shared rate limiting', redisConfigured,
      redisConfigured ? 'Upstash settings are present; connectivity and enforcement are not probed.'
        : env.VERCEL === '1' ? 'Required in production; analysis must fail closed until configured.'
          : 'Not configured; process-local limiting is not shared across instances.'),
    capability('ai.local_model', 'Local model inference', modelConfigured,
      modelConfigured ? 'Endpoint and model are configured; reachability and invocation are unverified.'
        : 'No local model endpoint/model pair is configured; do not substitute canned AI output.'),
    capability('firstlight.investigation', 'FIRSTLIGHT investigation API', firstlightConfigured,
      firstlightConfigured ? 'SATARK-owned investigation API is configured; reachability and execution are unverified.'
        : 'Private SATARK_API_INTERNAL_URL is not configured or is unsafe.'),
    capability('telemetry.wazuh', 'Wazuh telemetry connector', wazuhConfigured,
      wazuhConfigured ? 'Read-only Indexer settings and agent allowlist are present; connectivity, event freshness and durable ingestion are unverified.'
        : 'Wazuh Indexer URL, credentials, and allowed agent IDs are not all configured.'),
    capability('detection.rules', 'Deterministic detection rules', true,
      'Rule code exists; live coverage, regression corpus and alert delivery are unverified.', 'unverified'),
    capability('response.live', 'Live response / containment', false,
      'Disabled until a provider-specific executor, exact-action approval binding and independent lab verification pass.'),
    capability('notifications.delivery', 'Alert notification delivery', false,
      'No verified notification-provider delivery acknowledgement is represented.'),
  ];
  return {
    schemaVersion: 1,
    status: capabilities.some(item => item.status === 'degraded') ? 'degraded' : 'configuration-only',
    generatedAt: new Date().toISOString(),
    healthProbesRun: false,
    productionReady: false,
    capabilities,
    note: 'Configuration is not health. This endpoint performs no network probes, tenant-isolation tests, provider actions or production-readiness checks. "disabled" means not configured or intentionally disabled; "unverified" means implementation exists but end-to-end operation has not been proven.',
  };
}
