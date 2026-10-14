const OCTET_STREAM = 'application/octet-stream';
const TEXT_TYPES = new Set([
  'application/json', 'application/ld+json', 'application/x-ndjson',
  'text/csv', 'text/plain', 'text/tab-separated-values',
]);

const startsWith = (bytes, signature) => signature.every((value, index) => bytes[index] === value);
const ascii = (bytes, start, end) => String.fromCharCode(...bytes.slice(start, end));

function detectBinary(bytes) {
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) return { type: 'application/pdf', signature: 'pdf' };
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return { type: 'image/png', signature: 'png' };
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return { type: 'image/jpeg', signature: 'jpeg' };
  if (['GIF87a', 'GIF89a'].includes(ascii(bytes, 0, 6))) return { type: 'image/gif', signature: 'gif' };
  if (ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 12) === 'WEBP') return { type: 'image/webp', signature: 'webp' };
  if (ascii(bytes, 0, 2) === 'BM') return { type: 'image/bmp', signature: 'bmp' };
  if (startsWith(bytes, [0x49, 0x49, 0x2a, 0x00]) || startsWith(bytes, [0x4d, 0x4d, 0x00, 0x2a])) return { type: 'image/tiff', signature: 'tiff' };
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06]) || startsWith(bytes, [0x50, 0x4b, 0x07, 0x08])) return { type: 'application/zip', signature: 'zip-container' };
  if (startsWith(bytes, [0x1f, 0x8b])) return { type: 'application/gzip', signature: 'gzip' };
  if (startsWith(bytes, [0x1a, 0x45, 0xdf, 0xa3])) return { type: 'video/webm', signature: 'webm-ebml' };
  if (ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 12) === 'WAVE') return { type: 'audio/wav', signature: 'wav' };
  if (ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 11) === 'AVI') return { type: 'video/x-msvideo', signature: 'avi' };
  if (ascii(bytes, 0, 4) === 'OggS') return { type: 'application/ogg', signature: 'ogg' };
  if (ascii(bytes, 0, 4) === 'fLaC') return { type: 'audio/flac', signature: 'flac' };
  if (ascii(bytes, 0, 3) === 'ID3' || (bytes.length >= 4 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0 && (bytes[1] & 0x06) !== 0)) return { type: 'audio/mpeg', signature: 'mpeg-audio' };
  if (bytes.length >= 12 && ascii(bytes, 4, 8) === 'ftyp') {
    const brand = ascii(bytes, 8, 12);
    return brand === 'qt  ' ? { type: 'video/quicktime', signature: 'quicktime-ftyp' } : { type: 'video/mp4', signature: 'mp4-ftyp' };
  }
  return null;
}

function isTextLike(bytes, declaredType) {
  if (!TEXT_TYPES.has(declaredType)) return null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text)) return null;
    if (declaredType === 'application/json' || declaredType === 'application/ld+json') JSON.parse(text);
    if (declaredType === 'image/svg+xml' && !/<svg[\s>]/i.test(text) && !/<\?xml[\s>]/i.test(text)) return null;
    return { type: declaredType, signature: 'utf8-text' };
  } catch {
    return null;
  }
}

function isCompatible(declaredType, detected) {
  if (!declaredType || declaredType === OCTET_STREAM || declaredType === detected.type) return true;
  if (detected.signature === 'zip-container') return declaredType === 'application/x-zip-compressed' || declaredType.startsWith('application/vnd.openxmlformats-officedocument.');
  if (detected.signature === 'mp4-ftyp') return ['video/mp4', 'audio/mp4', 'application/mp4'].includes(declaredType);
  if (detected.signature === 'webm-ebml') return ['video/webm', 'audio/webm'].includes(declaredType);
  if (detected.signature === 'ogg') return ['application/ogg', 'audio/ogg', 'video/ogg'].includes(declaredType);
  if (detected.signature === 'wav') return declaredType === 'audio/x-wav';
  return false;
}

/**
 * Compares the browser-declared MIME type with recognizable file signatures.
 * Unknown binary evidence is retained only as application/octet-stream and is
 * explicitly marked unverified; submitted bytes are never executed.
 * @param {Uint8Array} bytes
 * @param {string} [declaredMime]
 */
export function inspectEvidenceFile(bytes, declaredMime = '') {
  const declaredType = typeof declaredMime === 'string' && /^[\w.+-]+\/[\w.+-]+$/.test(declaredMime.trim())
    ? declaredMime.trim().toLowerCase()
    : '';
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) return { ok: false, reason: 'empty_or_invalid_bytes' };

  const detected = detectBinary(bytes);
  if (detected) {
    if (!isCompatible(declaredType, detected)) return { ok: false, reason: 'mime_signature_mismatch' };
    return {
      ok: true,
      contentType: declaredType && declaredType !== OCTET_STREAM ? declaredType : detected.type,
      signatureType: detected.signature,
      signatureVerified: true,
    };
  }

  const text = isTextLike(bytes, declaredType);
  if (text) return { ok: true, contentType: text.type, signatureType: text.signature, signatureVerified: true };
  if (!declaredType || declaredType === OCTET_STREAM) return { ok: true, contentType: OCTET_STREAM, signatureType: 'unrecognized-binary', signatureVerified: false };
  return { ok: false, reason: 'unrecognized_or_invalid_signature' };
}
