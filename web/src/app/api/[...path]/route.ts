import { proxySatarkApi } from '@/lib/satark-api-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Covers self-hosted API endpoints that do not need a specialized Next handler
// (including auth signup/login/logout and workspace membership routes).
export const GET = proxySatarkApi;
export const POST = proxySatarkApi;
export const PUT = proxySatarkApi;
export const PATCH = proxySatarkApi;
export const DELETE = proxySatarkApi;
export const HEAD = proxySatarkApi;
export const OPTIONS = proxySatarkApi;
