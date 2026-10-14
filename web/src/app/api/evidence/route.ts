import { createHash, randomUUID } from 'node:crypto';
import { inspectEvidenceFile } from '@/lib/evidence-signature.mjs';
import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_FILE_BYTES = 4 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function error(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: { 'Cache-Control': 'no-store' } });
}

function configuration() {
  const rawUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!rawUrl || !publishableKey) return null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:' || !url.hostname.endsWith('.supabase.co')) return null;
    return { url: url.origin, publishableKey };
  } catch { return null; }
}

function bearer(request: Request) {
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(request.headers.get('authorization') || '');
  return match?.[1] || null;
}

async function authenticate(token: string, config: NonNullable<ReturnType<typeof configuration>>) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(config.url + '/auth/v1/user', {
      headers: { apikey: config.publishableKey, Authorization: 'Bearer ' + token, Accept: 'application/json' },
      cache: 'no-store', signal: controller.signal,
    });
    if (!response.ok) return null;
    const user: unknown = await response.json();
    if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string' || !UUID.test(user.id)) return null;
    return { id: user.id };
  } catch { return null; }
  finally { clearTimeout(timer); }
}

export async function POST(request: Request) {
  const config = configuration();
  if (!config) return error('Evidence storage is not configured.', 503);
  const token = bearer(request);
  if (!token) return error('Sign in is required.', 401);
  const user = await authenticate(token, config);
  if (!user) return error('Your session is invalid or expired.', 401);

  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > MAX_FILE_BYTES + 64 * 1024) return error('File exceeds the 4 MiB upload limit.', 413);

  let form: FormData;
  try { form = await request.formData(); }
  catch { return error('A multipart file upload is required.', 400); }

  const file = form.get('file');
  const tenantId = String(form.get('tenant_id') || '');
  const caseId = String(form.get('case_id') || '');
  const sourceLabel = String(form.get('source_label') || 'Uploaded evidence').trim();
  const eventKind = String(form.get('event_kind') || 'file').trim();
  const observedAt = String(form.get('observed_at') || new Date().toISOString());
  const summary = String(form.get('summary') || 'Evidence file uploaded.').trim();

  if (!(file instanceof File)) return error('A file is required.', 400);
  if (file.size < 1) return error('Empty evidence files are not accepted.', 400);
  if (file.size > MAX_FILE_BYTES) return error('File exceeds the 4 MiB upload limit.', 413);
  if (!UUID.test(tenantId) || !UUID.test(caseId)) return error('Valid tenant_id and case_id are required.', 400);
  if (!sourceLabel || sourceLabel.length > 160 || !eventKind || eventKind.length > 100 || !summary || summary.length > 8192) {
    return error('Evidence metadata contains invalid or oversized fields.', 400);
  }
  if (!Number.isFinite(Date.parse(observedAt)) || !/(Z|[+-]\d{2}:?\d{2})$/i.test(observedAt)) {
    return error('observed_at must be an ISO timestamp with an explicit timezone.', 400);
  }

  const bytes = Buffer.from(await file.arrayBuffer());
  if (bytes.byteLength !== file.size) return error('File bytes could not be verified.', 400);
  const inspection = inspectEvidenceFile(bytes, file.type);
  if (!inspection.ok) return error('File content does not match its declared type or the supported evidence format.', 415);

  const sourceSha256 = createHash('sha256').update(bytes).digest('hex');
  const evidenceId = randomUUID();
  const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(-100) || 'evidence.bin';
  const objectKey = tenantId + '/' + caseId + '/' + evidenceId + '_' + safeName;
  const contentType = inspection.contentType;
  const record = {
    id: evidenceId, tenant_id: tenantId, case_id: caseId,
    source_label: sourceLabel, event_kind: eventKind, observed_at: new Date(observedAt).toISOString(),
    summary, source_sha256: sourceSha256, created_by: user.id,
    metadata: { object_key: objectKey, original_filename: safeName, content_type: contentType, size_bytes: bytes.byteLength, signature_type: inspection.signatureType, signature_verified: inspection.signatureVerified },
  };
  const recordSha256 = createHash('sha256').update(JSON.stringify(record)).digest('hex');
  const headers = {
    apikey: config.publishableKey,
    Authorization: 'Bearer ' + token,
    Accept: 'application/json',
  };

  try {
    const upload = await fetch(config.url + '/storage/v1/object/satark-evidence/' + objectKey.split('/').map(encodeURIComponent).join('/'), {
      method: 'POST',
      headers: { ...headers, 'Content-Type': contentType, 'x-upsert': 'false' },
      body: bytes,
      cache: 'no-store',
      signal: AbortSignal.timeout(8_000),
    });
    if (!upload.ok) {
      if (upload.status === 401 || upload.status === 403) return error('You do not have permission to upload evidence to this case.', 403);
      if (upload.status === 413) return error('Storage rejected this file because it exceeds its upload limit.', 413);
      return error('Evidence upload failed. Verify workspace membership and case access, then retry.', 422);
    }

    const row = { ...record, record_sha256: recordSha256 };
    const saved = await fetch(config.url + '/rest/v1/satark_evidence', {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify(row),
      cache: 'no-store',
      signal: AbortSignal.timeout(8_000),
    });
    if (!saved.ok) {
      // Keep the object private. Do not expose a delete path to the browser; an administrator
      // can reconcile orphaned uploads through the documented retention process.
      return error('The private file was uploaded but its evidence record could not be saved. Contact an administrator with request time.', 503);
    }
    const rows: unknown = await saved.json();
    if (!Array.isArray(rows) || !rows[0]) return error('Evidence storage returned an invalid response.', 502);
    return NextResponse.json({ evidence: rows[0], integrity: { algorithm: 'SHA-256', source_sha256: sourceSha256, record_sha256: recordSha256 } }, {
      status: 201, headers: { 'Cache-Control': 'no-store' },
    });
  } catch {
    return error('Evidence storage is temporarily unavailable.', 503);
  }
}
