import { NextResponse } from 'next/server';
import { buildCapabilityRegistry } from '@/lib/capability-registry.mjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Safe configuration snapshot; intentionally does not claim runtime health. */
export async function GET() {
  return NextResponse.json(buildCapabilityRegistry(process.env), {
    headers: { 'Cache-Control': 'no-store' },
  });
}
