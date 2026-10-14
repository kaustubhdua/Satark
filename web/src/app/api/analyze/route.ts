import { NextResponse } from 'next/server';
import { checkAnalysisRateLimit } from '@/lib/rate-limit.mjs';
import { analyzeLocally, analyzeWithLocalModel } from '@/lib/local-analysis.mjs';

export const runtime = 'nodejs';

const MAX_BODY_BYTES = 48 * 1024;
const MAX_INPUT_CHARS = 12_000;

function error(message: string, status: number, extraHeaders: Record<string, string> = {}) {
  return NextResponse.json({ error: message }, {
    status,
    headers: { 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

export async function POST(request: Request) {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    return error('Content-Type must be application/json.', 415);
  }

  const contentLengthHeader = request.headers.get('content-length');
  if (contentLengthHeader !== null) {
    const contentLength = Number(contentLengthHeader);
    if (!Number.isFinite(contentLength) || contentLength < 0) {
      return error('Invalid Content-Length.', 400);
    }
    if (contentLength > MAX_BODY_BYTES) return error('Request body is too large.', 413);
  }

  let bodyText = '';
  try {
    if (!request.body) return error('Send a valid JSON request.', 400);
    const reader = request.body.getReader();
    const decoder = new TextDecoder();
    let totalBytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        await reader.cancel();
        return error('Request body is too large.', 413);
      }
      bodyText += decoder.decode(value, { stream: true });
    }
    bodyText += decoder.decode();
  } catch {
    return error('Send a valid JSON request.', 400);
  }

  let input: unknown;
  try {
    const body: unknown = JSON.parse(bodyText);
    input = body && typeof body === 'object' && !Array.isArray(body)
      ? (body as Record<string, unknown>).input
      : undefined;
  } catch {
    return error('Send a valid JSON request.', 400);
  }

  if (typeof input !== 'string' || !input.trim()) return error('Enter a URL or suspicious message.', 400);
  if (input.length > MAX_INPUT_CHARS) return error('Input must be 12,000 characters or fewer.', 413);

  const rateLimit = await checkAnalysisRateLimit(request);
  if (rateLimit.unavailable) {
    return error('Local analysis protection could not be verified. Retry shortly.', 503, { 'Retry-After': '10' });
  }
  if (rateLimit.limited) return error('Too many requests. Wait a minute and retry.', 429, { 'Retry-After': '60' });

  try {
    // This route has no third-party provider path. The optional Ollama endpoint
    // must be configured to a self-hosted instance; deterministic rules always work.
    const result = await analyzeWithLocalModel(input.trim());
    return NextResponse.json(result, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    // Defensive fallback should remain usable even if an unexpected adapter error occurs.
    const result = analyzeLocally(input.trim());
    return NextResponse.json(result, { headers: { 'Cache-Control': 'no-store' } });
  }
}
