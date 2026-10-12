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

/**
 * Accept only canonical HTTPS references on URLhaus itself.
 * Provider responses are external data; never pass an arbitrary provider-supplied
 * URL into a browser link.
 *
 * @param {unknown} value Untrusted provider-supplied reference.
 * @returns {string | undefined} Safe URLhaus reference, if valid.
 */
export function safeUrlhausReference(value) {
  if (typeof value !== 'string' || value.length > 500) return undefined;
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' ||
      parsed.hostname !== 'urlhaus.abuse.ch' ||
      parsed.username ||
      parsed.password ||
      !parsed.pathname.startsWith('/url/')
    ) return undefined;
    return parsed.toString();
  } catch {
    return undefined;
  }
}
