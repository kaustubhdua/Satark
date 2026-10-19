const baseHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'X-DNS-Prefetch-Control', value: 'off' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
];

export function supabaseConnectOrigin(value, nodeEnv = 'production') {
  if (typeof value !== 'string' || !value.trim()) return '';
  try {
    const url = new URL(value.trim());
    if (url.username || url.password || url.search || url.hash) return '';
    if (url.protocol === 'https:' && /^[a-z0-9-]+\.supabase\.co$/i.test(url.hostname) && !url.port) {
      return url.origin;
    }
    if (nodeEnv !== 'production' && url.protocol === 'http:'
      && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
      return url.origin;
    }
    return '';
  } catch {
    return '';
  }
}

export function buildSecurityHeaders(env = process.env) {
  const supabaseOrigin = supabaseConnectOrigin(env.NEXT_PUBLIC_SUPABASE_URL, env.NODE_ENV);
  const connectSources = ["'self'", supabaseOrigin].filter(Boolean).join(' ');
  const csp = [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${connectSources}`,
    "media-src 'self' data: blob:",
    "worker-src 'self' blob:",
  ].join('; ');

  return [
    ...baseHeaders,
    { key: 'Content-Security-Policy', value: csp },
  ];
}
