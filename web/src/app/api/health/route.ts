import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const present = (...values: Array<string | undefined>) =>
  values.some(value => typeof value === 'string' && value.trim().length > 0);

/** Configuration-only diagnostics; never disclose secret values or user data. */
export async function GET() {
  const mode = process.env.SATARK_ANALYSIS_MODE || 'local';
  const localModelConfigured = present(process.env.SATARK_OLLAMA_BASE_URL, process.env.SATARK_OLLAMA_MODEL);
  const checks = {
    analysis: {
      mode: mode === 'local' ? 'local-only' : mode === 'groq' ? 'legacy-provider' : 'unsupported',
      configured: mode === 'local' || (mode === 'groq' && present(process.env.GROQ_API_KEY)),
    },
    localModel: { configured: localModelConfigured },
    sharedRateLimit: {
      configured: present(process.env.UPSTASH_REDIS_REST_URL) && present(process.env.UPSTASH_REDIS_REST_TOKEN),
      requiredForLocalMode: false,
    },
    externalThreatIntel: {
      enabled: mode === 'groq' && (process.env.SATARK_ENABLE_THREAT_INTEL === 'true' || process.env.SATARK_ENABLE_ABUSEIPDB === 'true'),
      configured: mode === 'groq'
        && (process.env.SATARK_ENABLE_THREAT_INTEL !== 'true' || present(process.env.URLHAUS_AUTH_KEY))
        && (process.env.SATARK_ENABLE_ABUSEIPDB !== 'true' || present(process.env.ABUSEIPDB_API_KEY)),
    },
    persistentStorage: {
      configured: present(process.env.SUPABASE_URL) && present(process.env.SUPABASE_PUBLISHABLE_KEY),
    },
  };
  const ready = checks.analysis.configured && checks.analysis.mode !== 'unsupported';
  return NextResponse.json({
    status: ready ? 'ready' : 'degraded',
    checks,
    note: 'Configuration presence only. Local analysis uses deterministic rules; an Ollama model is optional. Storage and model availability are not validated by this endpoint.',
  }, { headers: { 'Cache-Control': 'no-store' } });
}
