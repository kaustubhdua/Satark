'use client';

import { useEffect, useState } from 'react';

type Health = {
  status: 'ready' | 'degraded';
  checks: {
    analysis: { mode: string; configured: boolean };
    localModel: { configured: boolean };
    sharedRateLimit: { configured: boolean; requiredForLocalMode: boolean };
    externalThreatIntel: { enabled: boolean; configured: boolean };
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
  const notes: string[] = [];
  if (!health.checks.localModel.configured) notes.push('Ollama model is optional; deterministic local rules are active.');
  if (!health.checks.persistentStorage.configured) notes.push('Persistent case storage is not configured.');
  if (health.checks.externalThreatIntel.enabled && !health.checks.externalThreatIntel.configured) {
    notes.push('A legacy external intelligence connector is enabled but not configured.');
  }

  return <div className={health.status === 'ready' ? 'readiness-banner readiness-ready' : 'readiness-banner readiness-degraded'} role="status">
    <span className="readiness-dot" aria-hidden="true" />
    <span>
      <strong>{health.status === 'ready' ? 'Local analysis available' : 'Analysis configuration needs attention'}</strong>
      <small>{notes.length ? notes.join(' ') : 'Local-only mode is enabled. No third-party AI API key is required.'}</small>
    </span>
  </div>;
}
