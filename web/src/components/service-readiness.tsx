'use client';

import { useEffect, useState } from 'react';

type Health = {
  status: 'ready';
  checks: {
    analysis: { mode: string; configured: boolean };
    localModel: { configured: boolean };
    rateLimit: { mode: string; configured: boolean; sharedAcrossInstances: boolean };
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
      .catch(() => { if (!controller.signal.aborted) setHealth(null); });
    return () => controller.abort();
  }, []);
  if (!health) return null;

  return <div className="readiness-banner readiness-ready" role="status">
    <span className="readiness-dot" aria-hidden="true" />
    <span>
      <strong>Local analysis available</strong>
      <small>
        {health.checks.localModel.configured
          ? 'Self-hosted model is configured; deterministic checks remain the fallback.'
          : 'No third-party AI key is required. Deterministic local rules are active; configure your own Ollama model for local-language summaries.'}
        {health.checks.persistentStorage.configured ? ' Persistent-storage configuration is present, but this status does not verify database connectivity or tenant authorization.' : ' Persistent case/evidence storage is not configured in this deployment.'}
        {!health.checks.rateLimit.sharedAcrossInstances ? ' Rate limiting is per instance; use host-level controls before exposing publicly.' : ''}
      </small>
    </span>
  </div>;
}
