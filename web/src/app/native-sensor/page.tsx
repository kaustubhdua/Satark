'use client';

import SiteHeader from '../site-header';
import { useState } from 'react';
import { scoreHost } from '../../lib/learned-models.mjs';

const MAX_LOG_BYTES = 2 * 1024 * 1024;
const MAX_GUARD_BYTES = 25 * 1024 * 1024;

const DANGEROUS_PERMISSIONS = [
  'READ_SMS',
  'RECEIVE_SMS',
  'SEND_SMS',
  'BIND_ACCESSIBILITY_SERVICE',
  'SYSTEM_ALERT_WINDOW',
  'REQUEST_INSTALL_PACKAGES',
  'READ_CALL_LOG',
  'RECORD_AUDIO',
  'READ_CONTACTS',
  'GET_ACCOUNTS',
  'ACCESS_FINE_LOCATION',
];

const steps = [
  { title: 'Collect local authentication signals', text: 'Read a bounded portion of an operator-selected Linux auth log. The sensor classifies failed and successful logins, privilege use and session changes.' },
  { title: 'Watch important files', text: 'Create a bounded file manifest for paths you explicitly select. Later scans identify additions, modifications and missing files.' },
  { title: 'Preserve traceable observations', text: 'Each event records its source, SHA-256 digest and stable identifier. A local JSONL hash chain detects ordinary journal edits.' },
  { title: 'Verify before investigating', text: 'Check the journal chain and use the records as evidence for a human-led investigation. These observations are signals, not a verdict.' },
];

const commands = [
  { label: 'Collect authentication events', command: 'python satark_native_sensor.py auth-log --path /var/log/auth.log --journal ./state/native-events.jsonl' },
  { label: 'Scan explicitly selected paths', command: 'python satark_native_sensor.py file-scan --paths /etc/ssh /etc/sudoers.d --state ./state/file-manifest.json --journal ./state/native-events.jsonl' },
  { label: 'Verify the journal', command: 'python satark_native_sensor.py verify-journal --journal ./state/native-events.jsonl' },
  { label: 'Run the sensor tests', command: 'python -m unittest -v tests.test_satark_native_sensor' },
];

type ParsedSensorEvent = {
  id: string;
  timestamp: string;
  source: string;
  kind: string;
  summary: string;
};

type FileGuardReport = {
  name: string;
  bytes: number;
  sha256: string;
  magic: string;
  isApk: boolean;
  zipEntries: string[];
  permissions: string[];
  embeddedUrls: Array<{ url: string; hostBand: string }>;
  findings: string[];
};

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseZipEntries(bytes: Uint8Array): string[] {
  // Scan End of Central Directory (EOCD) backwards within last 64 KiB
  const start = Math.max(0, bytes.length - 65557);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= start; i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const cdSize = view.getUint32(eocd + 12, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  if (cdOffset + cdSize > bytes.length) return [];

  const entries: string[] = [];
  let pos = cdOffset;
  const decoder = new TextDecoder('utf-8', { fatal: false });
  while (pos + 46 <= cdOffset + cdSize && entries.length < 250) {
    if (view.getUint32(pos, true) !== 0x02014b50) break;
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const nameStart = pos + 46;
    if (nameStart + nameLen > bytes.length) break;
    entries.push(decoder.decode(bytes.subarray(nameStart, nameStart + nameLen)));
    pos = nameStart + nameLen + extraLen + commentLen;
  }
  return entries;
}

function detectMagic(bytes: Uint8Array): string {
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) return 'ZIP / APK / JAR archive (PK)';
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return 'Linux ELF executable / shared object';
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) return 'Windows PE executable / DLL (MZ)';
  if (bytes.length >= 4 && bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0a) return 'Android Dalvik Executable (DEX)';
  if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'PDF document (%PDF)';
  return 'Unknown / raw binary';
}

function parseSensorText(raw: string): ParsedSensorEvent[] {
  const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(0, 2000);
  const events: ParsedSensorEvent[] = [];
  const nowYear = new Date().getUTCFullYear();

  lines.forEach((line, idx) => {
    if (line.startsWith('{')) {
      try {
        const obj = JSON.parse(line) as Record<string, unknown>;
        events.push({
          id: String(obj.event_id || obj.id || `SENSOR-${idx + 1}`),
          timestamp: String(obj.timestamp || obj.time || new Date().toISOString()),
          source: String(obj.source || 'satark_native_sensor'),
          kind: String(obj.kind || obj.event_type || 'sensor_event'),
          summary: String(obj.summary || obj.message || line.slice(0, 240)),
        });
        return;
      } catch {
        // fall through to syslog parsing
      }
    }
    let kind = '';
    if (/Failed password|authentication failure|Invalid user/i.test(line)) kind = 'auth_failure';
    else if (/Accepted (?:password|publickey)/i.test(line)) kind = 'auth_success';
    else if (/\bsudo\b.*COMMAND=/i.test(line)) kind = 'privilege_escalation';
    else if (/useradd|usermod|groupadd/i.test(line)) kind = 'account_change';
    if (!kind) return;

    const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))/);
    const syslogMatch = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
    let timestamp = new Date().toISOString();
    if (isoMatch) {
      timestamp = isoMatch[1];
    } else if (syslogMatch) {
      const parsed = Date.parse(`${syslogMatch[1]} ${nowYear} UTC`);
      if (Number.isFinite(parsed)) timestamp = new Date(parsed).toISOString();
    }
    events.push({
      id: `LOG-${String(idx + 1).padStart(5, '0')}`,
      timestamp,
      source: 'linux-auth-log',
      kind,
      summary: line.slice(0, 400),
    });
  });
  return events;
}

export default function NativeSensorPage() {
  const [logText, setLogText] = useState('');
  const [parsedEvents, setParsedEvents] = useState<ParsedSensorEvent[]>([]);
  const [logError, setLogError] = useState('');

  const [guardReport, setGuardReport] = useState<FileGuardReport | null>(null);
  const [guardBusy, setGuardBusy] = useState(false);
  const [guardError, setGuardError] = useState('');

  function analyzeLog(text: string) {
    setLogError('');
    if (!text.trim()) {
      setLogError('Paste auth.log lines or upload a native sensor JSONL journal first.');
      setParsedEvents([]);
      return;
    }
    const events = parseSensorText(text);
    setParsedEvents(events);
    if (!events.length) {
      setLogError('No recognized auth.log or JSONL sensor events were found in the input.');
    }
  }

  async function handleLogUpload(file?: File) {
    if (!file) return;
    setLogError('');
    if (file.size > MAX_LOG_BYTES) {
      setLogError('Log file exceeds the 2 MiB browser limit.');
      return;
    }
    const text = await file.text();
    setLogText(text.slice(0, 100_000));
    analyzeLog(text);
  }

  function exportFirstlightJson() {
    if (!parsedEvents.length) return;
    const blob = new Blob([JSON.stringify(parsedEvents, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'firstlight-sensor-events.json';
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function inspectBinaryFile(file?: File) {
    setGuardError('');
    setGuardReport(null);
    if (!file) return;
    if (file.size === 0 || file.size > MAX_GUARD_BYTES) {
      setGuardError('File must be between 1 byte and 25 MiB.');
      return;
    }
    setGuardBusy(true);
    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      const hash = await sha256Hex(buf);
      const magic = detectMagic(bytes);
      const zipEntries = magic.startsWith('ZIP') ? parseZipEntries(bytes) : [];
      const isApk = zipEntries.includes('AndroidManifest.xml') || file.name.toLowerCase().endsWith('.apk');

      // Bounded ASCII string scan over up to first 4 MiB for permissions & URLs
      const scanText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 4 * 1024 * 1024)));
      const permissions = DANGEROUS_PERMISSIONS.filter(p => scanText.includes(p));
      const rawUrls = Array.from(new Set(scanText.match(/https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s"'<>\\]{0,80})?/g) || [])).slice(0, 12);
      const embeddedUrls = rawUrls.map(u => {
        try {
          const scored = scoreHost(new URL(u).hostname);
          return { url: u, hostBand: scored ? scored.band : 'low' };
        } catch {
          return { url: u, hostBand: 'low' };
        }
      });

      const findings: string[] = [];
      if (isApk && permissions.length >= 3) {
        findings.push(`High-privilege Android permissions detected (${permissions.join(', ')}). Verify why this app needs them.`);
      } else if (permissions.length > 0) {
        findings.push(`Sensitive Android permissions found: ${permissions.join(', ')}.`);
      }
      if (isApk && zipEntries.some(e => e.endsWith('.so'))) {
        findings.push('Contains native ARM/x86 shared libraries (.so).');
      }
      if (embeddedUrls.some(u => u.hostBand !== 'low')) {
        findings.push('Embedded URL(s) scored elevated or high risk by satark-url-host-v1.');
      }
      if (magic.startsWith('Windows PE') || magic.startsWith('Linux ELF')) {
        findings.push('Executable binary detected; verify its SHA-256 against trusted release checksums before running.');
      }

      setGuardReport({
        name: file.name,
        bytes: file.size,
        sha256: hash,
        magic,
        isApk,
        zipEntries: zipEntries.slice(0, 40),
        permissions,
        embeddedUrls,
        findings,
      });
    } catch (e) {
      setGuardError(e instanceof Error ? e.message : 'Could not inspect this file locally.');
    } finally {
      setGuardBusy(false);
    }
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">Endpoint sensor &amp; File Guard</div>
        <h1>Inspect endpoint logs &amp; binaries locally.</h1>
        <p className="lead">Analyze Linux auth logs or sensor JSONL journals right in your browser, inspect APK/EXE/ELF files with File Guard, or run SATARK’s first-party Python collector on your host.</p>
        <div className="actions">
          <a className="btn btn-primary" href="https://github.com/kaustubhdua/Satark/blob/main/satark_native_sensor.py">View sensor source <span aria-hidden="true">↗</span></a>
          <a className="btn btn-secondary" href="https://github.com/kaustubhdua/Satark/blob/main/docs/NATIVE_ENDPOINT_SENSOR.md">Read operator guide <span aria-hidden="true">↗</span></a>
        </div>

        <section className="form-panel" aria-labelledby="browser-sensor-title">
          <div className="panel-kicker">Works in-browser</div>
          <h2 id="browser-sensor-title">Linux Auth-Log &amp; Sensor Journal Analyzer</h2>
          <p className="muted">Upload or paste `/var/log/auth.log` or `native-events.jsonl`. SATARK extracts failed logins, `sudo` escalations, and account changes locally, then exports a FIRSTLIGHT-ready JSON file.</p>
          <label className="field-label" htmlFor="sensor-log-file">Upload log or JSONL file (max 2 MiB)</label>
          <input id="sensor-log-file" type="file" accept=".log,.txt,.jsonl,.json" onChange={e => { void handleLogUpload(e.currentTarget.files?.[0]); e.currentTarget.value = ''; }} />
          <label className="field-label" htmlFor="sensor-log-text" style={{ marginTop: '12px' }}>Or paste log lines</label>
          <textarea id="sensor-log-text" rows={5} value={logText} onChange={e => setLogText(e.target.value)} placeholder="Nov 28 10:14:02 host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51234 ssh2" />
          <div className="actions">
            <button type="button" className="btn btn-primary" onClick={() => analyzeLog(logText)}>Parse events locally</button>
            {parsedEvents.length > 0 && (
              <button type="button" className="btn btn-secondary" onClick={exportFirstlightJson}>Export for FIRSTLIGHT ({parsedEvents.length})</button>
            )}
          </div>
          {logError && <p className="error-message" role="alert">{logError}</p>}
          {parsedEvents.length > 0 && (
            <div className="table-wrap" style={{ marginTop: '14px' }}>
              <table className="evidence-table">
                <thead><tr><th>ID</th><th>Kind</th><th>Timestamp</th><th>Summary</th></tr></thead>
                <tbody>
                  {parsedEvents.slice(0, 50).map(ev => (
                    <tr key={ev.id}><td><strong>{ev.id}</strong></td><td>{ev.kind}</td><td><small>{ev.timestamp}</small></td><td>{ev.summary}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="form-panel" aria-labelledby="file-guard-title">
          <div className="panel-kicker">Browser File Guard</div>
          <h2 id="file-guard-title">APK, Executable &amp; Archive Inspector</h2>
          <p className="muted">Drop an `.apk`, `.exe`, `.dll`, `.elf`, or `.zip` (up to 25 MiB). Computes SHA-256, checks file magic, lists APK/ZIP entries, flags sensitive Android permissions, and scores embedded URLs with `satark-url-host-v1`—with zero upload.</p>
          <label className="field-label" htmlFor="file-guard-input">Select APK or binary file</label>
          <input id="file-guard-input" type="file" accept=".apk,.exe,.dll,.elf,.zip,.jar,.dex,.bin" disabled={guardBusy} onChange={e => { void inspectBinaryFile(e.currentTarget.files?.[0]); e.currentTarget.value = ''; }} />
          {guardBusy && <p className="hint" role="status">Hashing and inspecting binary structure locally…</p>}
          {guardError && <p className="error-message" role="alert">{guardError}</p>}
          {guardReport && (
            <div className="info-panel" style={{ marginTop: '14px' }}>
              <p><strong>File:</strong> {guardReport.name} ({(guardReport.bytes / 1024).toFixed(1)} KiB)</p>
              <p><strong>Detected type:</strong> {guardReport.magic}{guardReport.isApk ? ' (Android APK)' : ''}</p>
              <p><strong>SHA-256:</strong> <code>{guardReport.sha256}</code></p>
              {guardReport.findings.length > 0 && (
                <>
                  <p><strong>File Guard findings:</strong></p>
                  <ul>{guardReport.findings.map(f => <li key={f}>{f}</li>)}</ul>
                </>
              )}
              {guardReport.embeddedUrls.length > 0 && (
                <>
                  <p><strong>Embedded URLs ({guardReport.embeddedUrls.length}):</strong></p>
                  <ul>{guardReport.embeddedUrls.map(u => <li key={u.url}><code>{u.url}</code> · host risk: <strong>{u.hostBand.toUpperCase()}</strong></li>)}</ul>
                </>
              )}
              {guardReport.zipEntries.length > 0 && (
                <details style={{ marginTop: '8px' }}>
                  <summary>Archive entries ({guardReport.zipEntries.length}{guardReport.zipEntries.length === 250 ? '+' : ''})</summary>
                  <ul>{guardReport.zipEntries.map(e => <li key={e}><code>{e}</code></li>)}</ul>
                </details>
              )}
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="pipeline-title">
          <h2 id="pipeline-title">How the host sensor works</h2>
          <p>A small, auditable collection path with explicit limits.</p>
          <ol className="sensor-steps">
            {steps.map((step) => <li key={step.title}><h3>{step.title}</h3><p>{step.text}</p></li>)}
          </ol>
        </section>

        <section className="panel" aria-labelledby="commands-title">
          <h2 id="commands-title">Operator commands</h2>
          <p>Run from a local checkout with Python 3.12 or later.</p>
          <div className="sensor-commands">
            {commands.map(item => <div key={item.label}><h3>{item.label}</h3><pre><code>{item.command}</code></pre></div>)}
          </div>
        </section>

        <div className="workspace-grid">
          <section className="workspace-card" aria-labelledby="safety-title">
            <h2 id="safety-title">Safety boundaries</h2>
            <ul><li>Reads only local paths the operator selects; symlinks and non-regular files are skipped.</li><li>Bounded log, file and scan sizes reduce accidental resource exhaustion.</li><li>Does not execute commands, contact providers, elevate privileges or isolate hosts.</li><li>Use least privilege and protect the journal and manifest.</li></ul>
          </section>
          <section className="workspace-card" aria-labelledby="limits-title">
            <h2 id="limits-title">Limitations</h2>
            <ul><li>This is a pull-based Linux sensor, not a resident daemon or a full EDR.</li><li>A local hash chain can be recomputed by a privileged attacker who rewrites the whole journal; external anchoring is needed for stronger assurance.</li><li>Local unit tests do not prove live host coverage or production readiness.</li><li>Central ingestion and automated response remain separate acceptance gates.</li></ul>
          </section>
        </div>

        <section className="panel" aria-labelledby="next-title">
          <h2 id="next-title">Next: investigate what it found</h2>
          <p>Import the exported JSON journal as evidence in FIRSTLIGHT. Treat sensor events as signals that need context, not as a verdict.</p>
          <a className="btn btn-secondary" href="/firstlight">Open FIRSTLIGHT <span aria-hidden="true">→</span></a>
        </section>
      </div>
    </main>
  );
}
