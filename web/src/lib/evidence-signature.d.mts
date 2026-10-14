export type EvidenceFileInspection =
  | { ok: true; contentType: string; signatureType: string; signatureVerified: boolean }
  | { ok: false; reason: 'empty_or_invalid_bytes' | 'mime_signature_mismatch' | 'unrecognized_or_invalid_signature' };

export function inspectEvidenceFile(bytes: Uint8Array, declaredMime?: string): EvidenceFileInspection;
