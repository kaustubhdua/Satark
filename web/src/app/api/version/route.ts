import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  const commit = process.env.VERCEL_GIT_COMMIT_SHA;
  if (!commit || !/^[0-9a-f]{40}$/i.test(commit)) {
    return NextResponse.json(
      { error: 'Build revision unavailable.' },
      { status: 503, headers: { 'Cache-Control': 'no-store' } },
    );
  }

  return NextResponse.json(
    { commit: commit.toLowerCase() },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
