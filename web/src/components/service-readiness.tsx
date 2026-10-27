'use client';

import { useEffect, useState } from 'react';
import { describeRateLimitStatus } from '../lib/health-snapshot.mjs';

type Health = {
  status: 'configuration-only';
  checks: {
    analysis: { mode: string; configured: boolean };
    localModel: { configured: boolean };
    rateLimit: { mode: string; configured: boolean; sharedAcrossInstances: boolean };
    persistentStorage: { configured: boolean; clientConfigured: boolean; serverClientMatch: boolean };
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
      <div className="readiness-body">
        <strong>Service status unavailable</strong>
        <small>The health endpoint could not be verified. Analysis may still work, but this banner cannot confirm it. Retry the page or check deployment logs before relying on this service.</small>
      </div>
    </div>;
  }
  if (!health) return <div className="readiness-banner" role="status" aria-live="polite">
    <span className="readiness-dot" aria-hidden="true" />
    <div className="readiness-body"><strong>Checking service configuration…</strong><small>This check reports configuration only, not live dependency health.</small></div>
  </div>;

  const needsAttention = !health.checks.persistentStorage.configured ||
    !health.checks.persistentStorage.clientConfigured || health.checks.persistentStorage.serverClientMatch !== true ||
    !health.checks.rateLimit.configured || !health.checks.rateLimit.sharedAcrossInstances;
  const chips: Array<[string, string]> = [
    ['Analysis', health.checks.analysis.configured ? 'local rules available' : 'needs review'],
    ['Self-hosted model', health.checks.localModel.configured ? 'configured · unverified' : 'not configured'],
    ['Storage', health.checks.persistentStorage.serverClientMatch !== true ? 'project mismatch' : health.checks.persistentStorage.configured && health.checks.persistentStorage.clientConfigured ? 'configured · unverified' : 'not configured'],
    ['Rate limit', health.checks.rateLimit.sharedAcrossInstances ? 'shared · unverified' : 'shared limiter missing'],
  ];

  return <div className={'readiness-banner ' + (needsAttention ? 'readiness-degraded' : 'readiness-ready')} role="status">
    <span className="readiness-dot" aria-hidden="true" />
    <div className="readiness-body">
      <strong>{needsAttention ? 'Configuration needs attention' : 'Configuration snapshot · not live health'}</strong>
      <div className="readiness-chips">{chips.map(([label, value]) => <span key={label}>{label}: <b>{value}</b></span>)}</div>
      <details className="readiness-details">
        <summary>What this does and does not check</summary>
        <p>
          {health.checks.analysis.configured
            ? 'Deterministic local checks are the baseline; no third-party AI key is required.'
            : 'Analysis configuration needs review.'}
          {health.checks.localModel.configured
            ? ' Both the self-hosted model URL and model name are configured; model availability is not verified.'
            : ' A self-hosted model is not fully configured; local-language model summaries may be unavailable.'}
          {health.checks.persistentStorage.configured
            ? ' Storage credentials are configured, but database connectivity and tenant authorization are not verified.'
            : ' Persistent case/evidence storage is not configured in this deployment.'}
          {' '}{describeRateLimitStatus(health.checks.rateLimit)}
        </p>
      </details>
    </div>
  </div>;
}
