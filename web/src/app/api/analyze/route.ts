import { NextResponse } from 'next/server';
export async function POST() { return NextResponse.json({ error: 'Analysis endpoint is being configured.' }, { status: 503 }); }
