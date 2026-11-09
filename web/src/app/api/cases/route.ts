import { proxySatarkApi } from '@/lib/satark-api-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const GET = proxySatarkApi;
export const POST = proxySatarkApi;
export const PATCH = proxySatarkApi;
