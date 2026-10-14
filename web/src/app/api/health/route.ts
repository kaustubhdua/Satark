import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const present = (...values: Array<string | undefined>) =>
  values.some(value => typeof value === 'string' && value.trim().length > 0);

/** Public-safe local readiness; never disclose secrets or user data. */
export async function GET() {
  const checks = {
    analysis: { mode: 'local-only', configured: true },
    localModel: {
      configured: present(process.env.SATARK_OLLAMA_BASE_URL, process.env.SATARK_OLLAMA_MODEL),
    },
    rateLimit: { mode: 'in-process', configured: true, sharedAcrossInstances: false },
    persistentStorage: {
      configured: present(process.env.SUPABASE_URL) && present(process.env.SUPABASE_PUBLISHABLE_KEY),
    },
  };
  return NextResponse.json({
    status: 'ready',
    checks,
    note: 'Local deterministic analysis is available without API keys. This endpoint reports configuration only; it does not validate model availability or persistent storage connectivity.',
  }, { headers: { 'Cache-Control': 'no-store' } });
}
