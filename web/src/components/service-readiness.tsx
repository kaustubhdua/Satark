'use client';

import { useEffect, useState } from 'react';

type Health = {
  status: 'ready' | 'degraded';
  checks: {
    analysisProvider: { configured: boolean };
    sharedRateLimit: { configured: boolean };
    urlhaus: { enabled: boolean; configured: boolean };
    abuseIpDb: { enabled: boolean; configured: boolean };
    persistentStorage: { configured: boolean };
  };
};

export default function ServiceReadiness() {
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/health', { cache: 'no-store', signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Health check unavailable');
        return response.json() as Promise<Health>;
      })
      .then(setHealth)
      .catch(() => {
        if (!controller.signal.aborted) setHealth(null);
      });
    return () => controller.abort();
  }, []);

  if (!health) return null;

  const missing: string[] = [];
  if (!health.checks.analysisProvider.configured) missing.push('AI analysis provider');
  if (!health.checks.sharedRateLimit.configured) missing.push('shared rate limiting');
  const optionalMissing: string[] = [];
  if (health.checks.urlhaus.enabled && !health.checks.urlhaus.configured) optionalMissing.push('URLhaus');
  if (health.checks.abuseIpDb.enabled && !health.checks.abuseIpDb.configured) optionalMissing.push('AbuseIPDB');

  if (!missing.length && !optionalMissing.length) {
    return <div className="readiness-banner readiness-ready" role="status">
      <span className="readiness-dot" aria-hidden="true" />
      <span><strong>Service configuration present</strong><small>Credential presence is checked, not provider health.</small></span>
    </div>;
  }

  return <div className="readiness-banner readiness-degraded" role="status">
    <span className="readiness-dot" aria-hidden="true" />
    <span>
      <strong>{missing.length ? 'Some core services need configuration' : 'Optional integrations need configuration'}</strong>
      <small>
        {missing.length ? 'Core: ' + missing.join(' and ') + '. ' : ''}
        {optionalMissing.length ? 'Optional: ' + optionalMissing.join(' and ') + '. ' : ''}
        Add credentials in Vercel Project Settings → Environment Variables, then redeploy. Do not put secrets in browser code.
      </small>
    </span>
  </div>;
}
