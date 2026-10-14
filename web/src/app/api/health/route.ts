import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function present(...values: Array<string | undefined>) {
  return values.some(value => typeof value === 'string' && value.trim().length > 0);
}

/**
 * Public, non-secret configuration diagnostics. Never return credential values,
 * provider responses, project identifiers, or user data from this endpoint.
 */
export async function GET() {
  const sharedRateLimitConfigured = present(
    process.env.UPSTASH_REDIS_REST_URL,
    process.env.UPSTASH_REDIS_REST_TOKEN,
  ) && Boolean(process.env.UPSTASH_REDIS_REST_URL?.trim())
    && Boolean(process.env.UPSTASH_REDIS_REST_TOKEN?.trim());
  const checks = {
    analysisProvider: { configured: Boolean(process.env.GROQ_API_KEY?.trim()) },
    sharedRateLimit: { configured: sharedRateLimitConfigured },
    urlhaus: {
      enabled: process.env.SATARK_ENABLE_THREAT_INTEL === 'true',
      configured: Boolean(process.env.URLHAUS_AUTH_KEY?.trim()),
    },
    abuseIpDb: {
      enabled: process.env.SATARK_ENABLE_ABUSEIPDB === 'true',
      configured: Boolean(process.env.ABUSEIPDB_API_KEY?.trim()),
    },
    persistentStorage: {
      configured: Boolean(
        process.env.SUPABASE_URL?.trim()
        && process.env.SUPABASE_PUBLISHABLE_KEY?.trim(),
      ),
    },
  };
  const requiredReady = checks.analysisProvider.configured && checks.sharedRateLimit.configured;
  return NextResponse.json(
    {
      status: requiredReady ? 'ready' : 'degraded',
      checks,
      note: 'Configuration presence only; this endpoint does not validate credentials or contact external providers.',
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
