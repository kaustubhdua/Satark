import type { NextConfig } from 'next';
import { buildSecurityHeaders } from './src/lib/security-headers.mjs';

// The helper validates and scopes connect-src to this deployment's Supabase URL.
const securityHeaders = buildSecurityHeaders();

const nextConfig: NextConfig = {
  output: 'standalone',
  async headers() {
    return [
      { source: '/:path*', headers: securityHeaders },
      {
        // API errors, including framework-generated 405 responses, must not
        // inherit cacheable defaults even when a handler returns no body data.
        source: '/api/:path*',
        headers: [{ key: 'Cache-Control', value: 'no-store' }],
      },
    ];
  },
};

export default nextConfig;
