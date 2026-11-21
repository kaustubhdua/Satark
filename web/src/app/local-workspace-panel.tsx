'use client';

import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { installLocalMode, getLocalModeStatus, exportLocalWorkspace, importLocalWorkspace, eraseLocalWorkspace, requestPersistentStorage, type LocalModeStatus } from '../lib/local-mode';

installLocalMode();

const SERVER_STATUS: LocalModeStatus = { active: false, durable: false };
function subscribe(callback: () => void) {
  window.addEventListener('satark-local-mode', callback);
  return () => window.removeEventListener('satark-local-mode', callback);
}

export function useLocalMode(): LocalModeStatus {
  // useSyncExternalStore keeps hydration consistent (server snapshot = inactive)
  // and hands components mounted later the real value on their first render.
  return useSyncExternalStore(subscribe, getLocalModeStatus, () => SERVER_STATUS);
}

/** Thin notice shown on every page while the browser-only workspace is in use. */
export function LocalModeNotice() {
  const { active, durable } = useLocalMode();
  if (!active) return null;
  return (
    <div className="local-mode-bar" role="status">
      <strong>Browser-only workspace</strong>
      <span>{durable ? 'Your cases and evidence stay in this browser; nothing is uploaded.' : 'Storage is blocked here, so work is kept for this tab only.'}</span>
      <span>Back up from “This device” in the menu.</span>
    </div>
  );
}

export function DeviceWorkspacePanel() {
  const { active, durable } = useLocalMode();
  const fileInput = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [persisted, setPersisted] = useState<boolean | null>(null);
  useEffect(() => { void navigator.storage?.persisted?.().then(setPersisted).catch(() => setPersisted(null)); }, [active]);
  if (!active) return null;

  async function run(task: () => Promise<string>) {
    setBusy(true); setError(''); setMessage('');
    try { setMessage(await task()); } catch (cause) { setError(cause instanceof Error ? cause.message : 'That did not work.'); } finally { setBusy(false); }
  }

  const exportBackup = () => run(async () => {
    const backup = await exportLocalWorkspace();
    const url = URL.createObjectURL(new Blob([JSON.stringify(backup, null, 2) + '\n'], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url; link.download = 'satark-workspace-' + new Date().toISOString().slice(0, 10) + '.json';
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    return 'Backup saved. It is sealed with a SHA-256 digest, so any later edit is detected when you import it.';
  });
  const importBackup = (file: File) => run(async () => {
    const summary = await importLocalWorkspace(file);
    window.setTimeout(() => window.location.reload(), 900);
    return 'Imported ' + summary.cases + ' case(s), ' + summary.evidence + ' evidence item(s) and ' + summary.audit_events + ' verified audit events. Reloading…';
  });
  const erase = () => {
    if (!window.confirm('Erase every case, note, evidence item and report stored in this browser? Export a backup first if you need them.')) return;
    void run(async () => { await eraseLocalWorkspace(); window.setTimeout(() => window.location.reload(), 700); return 'Workspace erased from this browser. Reloading…'; });
  };
  const keep = () => run(async () => {
    const granted = await requestPersistentStorage();
    setPersisted(granted);
    return granted ? 'Your browser agreed to keep this data unless you clear it yourself.' : 'The browser did not grant protected storage. Keep a backup.';
  });

  return (
    <section className="form-panel device-workspace" id="device-workspace" aria-labelledby="device-workspace-title">
      <div className="card-head"><span>Browser-only workspace</span><span className={durable ? 'safe-chip' : 'review-chip'}>{durable ? 'Saved in this browser' : 'This tab only'}</span></div>
      <h2 id="device-workspace-title">Your workspace lives on this device</h2>
      <p className="muted">
        No account or server is needed. Cases, notes, findings, evidence files, sealed reports and the hash-chained audit trail are stored in this browser
        and never uploaded. Clearing site data erases them, so export a backup. Sharing with teammates, e-mail invitations, sign-in security and live
        endpoint response need the hosted SATARK service and are not available here.
      </p>
      {persisted === false && <p className="hint">This browser has not promised to keep the data. <button className="mini-btn" type="button" onClick={() => void keep()} disabled={busy}>Ask it to keep it</button></p>}
      <div className="actions">
        <button className="btn btn-primary" type="button" onClick={() => void exportBackup()} disabled={busy}>Export backup</button>
        <button className="btn btn-secondary" type="button" onClick={() => fileInput.current?.click()} disabled={busy}>Import backup</button>
        <button className="btn btn-secondary" type="button" onClick={erase} disabled={busy}>Erase this workspace</button>
        <input ref={fileInput} type="file" accept="application/json,.json" hidden aria-label="Choose a SATARK workspace backup"
          onChange={event => { const file = event.target.files?.[0]; event.target.value = ''; if (file) void importBackup(file); }} />
      </div>
      {error && <p className="error-message" role="alert">{error}</p>}
      {message && <p className="success-message" role="status">{message}</p>}
    </section>
  );
}
