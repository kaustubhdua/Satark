/**
 * Accept a Redis-over-REST endpoint (Upstash, or a self-hosted Upstash-compatible
 * proxy such as hiett/serverless-redis-http) only when the transport is safe:
 * https anywhere, or plain http for loopback and single-label private hostnames
 * (a Docker/Kubernetes service name). No embedded credentials, ever.
 * @param {string | undefined} value
 */
export function isAcceptableRedisRestUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  try {
    const url = new URL(value.trim());
    if (!url.hostname || url.username || url.password) return false;
    if (url.protocol === 'https:') return true;
    if (url.protocol !== 'http:') return false;
    const host = url.hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || /^[a-z0-9][a-z0-9-]*$/.test(host);
  } catch {
    return false;
  }
}
