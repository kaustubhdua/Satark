'use client';

import { useEffect, useState } from 'react';

type Health = {
  status: 'configuration-only';
  checks: {
    analysis: { mode: string; configured: boolean };
    localModel: { configured: boolean };
    rateLimit: { mode: string; configured: boolean; sharedAcrossInstances: boolean };
    persistentStorage: { configured: boolean };
  };
  note?: string;
};

export default function ServiceReadiness() {
  const [health, setHealth] = useState<Health | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);
    fetch('/api/health', { cache: 'no-store', signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Health endpoint unavailable');
        const value: unknown = await response.json();
        if (!value || typeof value !== 'object' || !('checks' in value) || !('status' in value) || value.status !== 'configuration-only') {
          throw new Error('Unexpected health response');
        }
        return value as Health;
      })
      .then(value => { setHealth(value); setUnavailable(false); })
      .catch(() => {
        if (!controller.signal.aborted) setUnavailable(true);
        else setUnavailable(true);
      })
      .finally(() => clearTimeout(timeout));
    return () => { clearTimeout(timeout); controller.abort(); };
  }, []);

  if (unavailable) {
    return <div className="readiness-banner readiness-degraded" role="status">
      <span className="readiness-dot" aria-hidden="true" />
      <span>
        <strong>Service status unavailable</strong>
        <small>The health endpoint could not be verified. Analysis may still work, but this banner cannot confirm it. Retry the page or check deployment logs before relying on this service.</small>
      </span>
    </div>;
  }
  if (!health) return <div className="readiness-banner" role="status" aria-live="polite">
    <span className="readiness-dot" aria-hidden="true" />
    <span><strong>Checking service configuration…</strong><small>This check reports configuration only, not live dependency health.</small></span>
  </div>;

  return <div className="readiness-banner readiness-ready" role="status">
    <span className="readiness-dot" aria-hidden="true" />
    <span>
      <strong>Local-first analysis · configuration snapshot</strong>
      <small>
        {health.checks.analysis.configured
          ? 'Deterministic local checks are the baseline; no third-party AI key is required.'
          : 'Analysis configuration needs review.'}
        {health.checks.localModel.configured
          ? ' Both the self-hosted model URL and model name are configured; model availability is not verified.'
          : ' A self-hosted model is not fully configured; local-language model summaries may be unavailable.'}
        {health.checks.persistentStorage.configured
          ? ' Storage credentials are configured, but database connectivity and tenant authorization are not verified.'
          : ' Persistent case/evidence storage is not configured in this deployment.'}
        {!health.checks.rateLimit.sharedAcrossInstances
          ? ' Rate limiting is per instance, not shared; apply host-level abuse controls before public exposure.'
          : ''}
      </small>
    </span>
  </div>;
}
