import type { NextConfig } from 'next';
import { buildSecurityHeaders } from './src/lib/security-headers.mjs';

const securityHeaders = buildSecurityHeaders(process.env);

const satarkApi = (process.env.SATARK_API_INTERNAL_URL || 'http://firstlight-api:8788').replace(/\/$/, '');

const nextConfig: NextConfig = {
  async rewrites() {
    // Keep scanner analysis, capability discovery, health snapshot, and version
    // handlers in Next.js. Proxy only persistent application APIs to FastAPI.
    return { beforeFiles: [
      { source: '/api/auth/:path*', destination: satarkApi + '/api/auth/:path*' },
      { source: '/api/workspaces/:path*', destination: satarkApi + '/api/workspaces/:path*' },
      { source: '/api/cases/:path*', destination: satarkApi + '/api/cases/:path*' },
      { source: '/api/evidence/:path*', destination: satarkApi + '/api/evidence/:path*' },
      { source: '/api/findings/:path*', destination: satarkApi + '/api/findings/:path*' },
      { source: '/api/reports/:path*', destination: satarkApi + '/api/reports/:path*' },
      { source: '/api/audit/:path*', destination: satarkApi + '/api/audit/:path*' },
      { source: '/api/firstlight/:path*', destination: satarkApi + '/api/firstlight/:path*' },
    ] };
  },
  output: 'standalone',
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
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
