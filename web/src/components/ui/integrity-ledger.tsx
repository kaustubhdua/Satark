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

const featured = [
  'storage.supabase',
  'rate_limit.shared',
  'firstlight.investigation',
  'telemetry.wazuh',
];

function statusLabel(item: Capability) {
  if (item.status === 'degraded') return 'Configuration mismatch';
  if (item.healthVerified) return 'Health verified';
  if (item.configured) return 'Configured · unverified';
  return 'Not configured';
}

/** Homepage status panel backed by the server's capability registry, never sample evidence. */
export default function IntegrityLedger() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 4500);
    fetch('/api/capabilities', { cache: 'no-store', signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Capability endpoint unavailable');
        const value: unknown = await response.json();
        if (!value || typeof value !== 'object' || !('capabilities' in value) ||
            !Array.isArray(value.capabilities) || typeof (value as Snapshot).productionReady !== 'boolean') {
          throw new Error('Invalid capability snapshot');
        }
        return value as Snapshot;
      })
      .then(value => { setSnapshot(value); setUnavailable(false); })
      .catch(() => setUnavailable(true))
      .finally(() => window.clearTimeout(timeout));
    return () => { window.clearTimeout(timeout); controller.abort(); };
  }, []);

  const items = snapshot
    ? featured.map(id => snapshot.capabilities.find(item => item.id === id)).filter((item): item is Capability => Boolean(item))
    : [];

  return (
    <section className="ledger border-beam" aria-labelledby="ledger-title">
      <div className="ledger-head">
        <div>
          <strong id="ledger-title">Integration readiness</strong>
          <small>Server-reported configuration · not a live health check</small>
        </div>
        <span className={unavailable || !snapshot?.productionReady ? 'risk-chip' : 'review-chip'}>
          {unavailable ? 'Status unavailable' : !snapshot ? 'Checking…' : snapshot.productionReady ? 'Ready reported' : 'Not release-verified'}
        </span>
      </div>
      {unavailable ? (
        <div className="ledger-foot" role="status">
          <p><b className="bad">Could not load capability status.</b> No integration is assumed healthy.</p>
        </div>
      ) : !snapshot ? (
        <div className="ledger-foot" role="status"><p>Reading the server configuration snapshot…</p></div>
      ) : (
        <>
          <ul className="ledger-rows">
            {items.map((item, index) => (
              <li key={item.id} className="ledger-row">
                <span className="ledger-id">{String(index + 1).padStart(2, '0')}</span>
                <span className="ledger-text">{item.name}</span>
                <span className="ledger-hash">{item.details}</span>
                <span className="ledger-state">
                  <span className={item.status === 'degraded' || !item.configured ? 'risk-chip' : 'review-chip'}>
                    {statusLabel(item)}
                  </span>
                </span>
              </li>
            ))}
          </ul>
          <div className="ledger-foot">
            <p aria-live="polite"><b className="bad">Production readiness is not verified.</b> {snapshot.healthProbesRun ? 'A health probe was reported; provider actions remain unproven.' : 'No live health probes, tenant tests, or provider actions were run.'}</p>
          </div>
        </>
      )}
    </section>
  );
}
