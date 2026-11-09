'use client';

import { useEffect, useState } from 'react';

type Capability = {
  id: string;
  name: string;
  status: string;
  configured: boolean;
  healthVerified: boolean;
  details: string;
};
type Snapshot = {
  generatedAt: string;
  healthProbesRun: boolean;
  productionReady: boolean;
  capabilities: Capability[];
  note: string;
};

const priority = [
  'telemetry.wazuh',
  'firstlight.investigation',
  'storage.supabase',
  'detection.rules',
  'response.live',
];

function label(status: string) {
  if (status === 'configured') return 'Configured · unverified';
  if (status === 'unverified') return 'Implemented · unverified';
  if (status === 'degraded') return 'Configuration mismatch';
  return 'Not configured / disabled';
}

export default function FirstlightReadiness() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5000);
    fetch('/api/capabilities', { cache: 'no-store', signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Capability endpoint unavailable');
        const value = await response.json();
        if (!value || !Array.isArray(value.capabilities) || typeof value.productionReady !== 'boolean') {
          throw new Error('Unexpected capability response');
        }
        return value as Snapshot;
      })
      .then(value => { setSnapshot(value); setUnavailable(false); })
      .catch(() => setUnavailable(true))
      .finally(() => window.clearTimeout(timeout));
    return () => { window.clearTimeout(timeout); controller.abort(); };
  }, []);

  const capabilities = snapshot?.capabilities ?? [];
  const healthProbeLabel = snapshot?.healthProbesRun ? 'Probe reported' : 'No live probe';
  const ordered = priority.map(id => capabilities.find(item => item.id === id)).filter((item): item is Capability => Boolean(item));

  return (
    <section className="fl-readiness" aria-labelledby="fl-readiness-title">
      <div className="fl-readiness-heading">
        <div>
          <div className="panel-kicker">Integration readiness snapshot</div>
          <h2 id="fl-readiness-title">Configuration is not proof of operation.</h2>
        </div>
        <span className="fl-readiness-state">{unavailable ? 'STATUS UNAVAILABLE' : !snapshot ? 'CHECKING…' : snapshot.healthProbesRun ? 'PROBE REPORTED · VERIFY RESULT' : 'CONFIGURATION ONLY'}</span>
      </div>
      {unavailable ? (
        <p className="fl-readiness-note" role="status">The capability endpoint could not be verified. Do not assume telemetry, storage, or response services are available.</p>
      ) : !snapshot ? (
        <p className="fl-readiness-note" role="status">Reading the server-side configuration snapshot. No credentials or secret values are displayed.</p>
      ) : (
        <>
          <div className="fl-capability-grid">
            {ordered.map(item => (
              <article className="fl-capability" key={item.id}>
                <div className="fl-capability-top">
                  <strong>{item.name}</strong>
                  <span className={'fl-capability-status ' + item.status}>{label(item.status)}</span>
                </div>
                <p>{item.details}</p>
              </article>
            ))}
          </div>
          <p className="fl-readiness-note">
            Snapshot {new Date(snapshot.generatedAt).toLocaleString('en-IN')}. {healthProbeLabel}. {snapshot.healthProbesRun
              ? 'A health probe was reported by the server; provider-side action is still not implied.'
              : 'No live health probes were run.'} {snapshot.productionReady
              ? 'The server reports production readiness; verify the linked acceptance evidence before release.'
              : 'This deployment is not marked production-ready.'}
          </p>
        </>
      )}
    </section>
  );
}
