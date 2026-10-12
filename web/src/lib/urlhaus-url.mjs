/**
 * Extract a URL for an explicitly consented URLhaus lookup.
 *
 * Privacy boundary: never forward URL query strings or fragments to the provider,
 * because they can contain session IDs, signed tokens, email addresses, or trackers.
 * Paths may still contain identifiers, so the UI must warn users before opting in.
 *
 * @param {string} input Untrusted user-submitted text.
 * @returns {string | null} Sanitized HTTP(S) URL, or null when none is usable.
 */
export function extractFirstHttpUrl(input) {
  const candidate = input.match(/https?:\/\/[^\s<>\"']{1,2048}/i)?.[0];
  if (!candidate) return null;
  try {
    const parsed = new URL(candidate.replace(/[),.;!?]+$/, ''));
    if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.username || parsed.password) return null;
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString().slice(0, 2048);
  } catch {
    return null;
  }
}
