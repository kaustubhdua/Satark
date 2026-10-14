import { NextResponse } from 'next/server';
import { buildHealthSnapshot } from '@/lib/health-snapshot.mjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Public-safe configuration snapshot; never disclose secrets or user data. */
export async function GET() {
  return NextResponse.json(buildHealthSnapshot(process.env), {
    headers: { 'Cache-Control': 'no-store' },
  });
}
