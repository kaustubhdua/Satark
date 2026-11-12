'use client';

import SiteHeader from '../site-header';
import FirstlightReadiness from '../../components/firstlight-readiness';
import dynamic from 'next/dynamic';
import { useEffect, useMemo, useRef, useState } from 'react';
import { authenticatedFetch, getActiveTenant, getSession, type SatarkSession } from '../../lib/satark-auth';
import { parseCsv, parseIsoTimestamp } from '../../lib/firstlight-import.mjs';
import { buildFirstlightFindings, getTrustedFirstlightEvidence } from '../../lib/firstlight-investigation.mjs';

// Large workspace and insight views are loaded only when their section/tab is needed.
const PersistentCasePanel = dynamic(() => import('./persistent-case-panel'), {
  ssr: false,
  loading: () => <div className="panel" role="status">Loading persistent case workspace…</div>,
});
const FindingsInsights = dynamic(() => import('./insights').then(module => module.FindingsInsights), {
  ssr: false,
  loading: () => <p className="hint" role="status">Loading findings summary…</p>,
});
const EventTracker = dynamic(() => import('./insights').then(module => module.EventTracker), {
  ssr: false,
  loading: () => <p className="hint" role="status">Loading event timeline…</p>,
});
// The fallback reads only supplied summaries; it does not inspect the endpoint or file.

type Evidence = { id: string; time: string; source: string; kind: string; summary: string; digest: string; tampered?: boolean; details?: Record<string, unknown>; metadata?: Record<string, unknown> };
type Audit = { time: string; action: string; detail: string };
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const source = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(source).sort().map(key => [key, canonicalize(source[key])]));
  }
  return value;
}

function toHex(hash: ArrayBuffer) {
  return Array.from(new Uint8Array(hash)).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function digest(text: string) {
  const bytes = new TextEncoder().encode(text);
  return toHex(await crypto.subtle.digest('SHA-256', bytes));
}

async function boundedDetails(value: unknown): Promise<Record<string, unknown>> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const canonical = JSON.stringify(canonicalize(value));
  const bytes = new TextEncoder().encode(canonical);
  if (bytes.byteLength <= 16 * 1024) return value as Record<string, unknown>;
  return { truncated: true, original_bytes: bytes.byteLength, sha256: await digest(canonical) };
}

// Keep the browser's evidence envelope byte-for-byte compatible with Python's
// sorted-key canonical JSON in firstlight_engine.sha256_record.
async function digestEvidence(item: { id: string; time: string; source: string; kind: string; summary: string; details?: Record<string, unknown> }) {
  const canonicalRecord = {
    details: item.details || {},
    event_id: item.id,
    kind: item.kind,
    source: item.source,
    summary: item.summary,
    timestamp: item.time,
  };
  return digest(JSON.stringify(canonicalize(canonicalRecord)));
}

async function digestBytes(bytes: ArrayBuffer) {
  return toHex(await crypto.subtle.digest('SHA-256', bytes));
}
export default function FirstlightPage() {
  const [authChecked, setAuthChecked] = useState(false);
  const persistentPanelRef = useRef<HTMLDivElement | null>(null);
  const [persistentPanelVisible, setPersistentPanelVisible] = useState(false);
  const [session, setSession] = useState<SatarkSession | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [selected, setSelected] = useState('overview');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [caseOpen, setCaseOpen] = useState(false);
  const [importName, setImportName] = useState('');
  const [sourceFileSha256, setSourceFileSha256] = useState('');
  const [persistentCaseId, setPersistentCaseId] = useState('');
  const [serverInvestigation, setServerInvestigation] = useState<any>(null);
  const [serverBusy, setServerBusy] = useState(false);
  useEffect(() => {
    if (!authChecked) return;
    const target = persistentPanelRef.current;
    if (!target) return;
    if (!('IntersectionObserver' in window)) {
      setPersistentPanelVisible(true);
      return;
    }
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) {
        setPersistentPanelVisible(true);
        observer.disconnect();
      }
    }, { rootMargin: '320px 0px' });
    observer.observe(target);
    return () => observer.disconnect();
  }, [authChecked]);

  useEffect(() => {
    let active = true;
    void getSession().then(current => {
      if (!active) return;
      if (!current) { window.location.replace('/login'); return; }
      setSession(current);
      setAuthChecked(true);
    }).catch(() => { if (active) window.location.replace('/login'); });
    return () => { active = false; };
  }, []);

  const trustedEvidence = useMemo(() => getTrustedFirstlightEvidence(evidence), [evidence]);
  const quarantinedEvidenceCount = evidence.length - trustedEvidence.length;
  const timeline = useMemo(() => [...evidence].sort((a,b)=>Date.parse(a.time)-Date.parse(b.time)), [evidence]);
  const findings = useMemo(() => buildFirstlightFindings(evidence), [evidence]);
  async function runSharedInvestigation() {
    if (!caseOpen || serverBusy || evidence.length === 0) return;
    setServerBusy(true);
    setServerInvestigation(null);
    setNotice('');
    try {
      const previewFingerprint = await digest(evidence.map(item => item.id + ':' + item.digest).sort().join('\n'));
      const caseId = persistentCaseId || 'FL-PREVIEW-' + previewFingerprint.slice(0, 16);
      const title = persistentCaseId
        ? 'Saved case investigation'
        : importName === 'Wazuh alerts' ? 'Read-only Wazuh alert preview' : 'Imported evidence preview';
      const response = await authenticatedFetch('/api/firstlight/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          title,
          evidence: evidence.map(({ id, time, source, kind, summary, digest, details }) => ({ id, time, source, kind, summary, digest, details: details || {} })),
        }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(typeof payload?.error === 'string' ? payload.error : 'Shared investigation could not be completed.');
      setServerInvestigation(payload);
      log('SHARED_INVESTIGATION_COMPLETED', 'Python engine reviewed ' + payload.integrity_summary.verified + ' verified and ' + payload.integrity_summary.mismatched + ' mismatched evidence record(s).');
      setNotice('Shared Python investigation completed. Review the stage trace and integrity results below.');
    } catch (error) {
      setNotice((error instanceof Error ? error.message : 'Shared investigation is unavailable.') + ' The local deterministic view remains available; it is not a substitute for a successful shared-engine run.');
    } finally {
      setServerBusy(false);
    }
  }

  async function loadWazuhAlerts() {
    if (!session || busy) return;
    if (evidence.length > 0 && !window.confirm('Replace the current in-memory evidence with the next Wazuh alert page? Export or save your current case first if you need it.')) return;
    const tenantId = getActiveTenant();
    if (!tenantId) { setNotice('Select a workspace before loading real Wazuh alerts.'); return; }
    setBusy(true);
    setNotice('');
    try {
      const response = await authenticatedFetch('/api/firstlight/wazuh/alerts?limit=100&tenant_id=' + encodeURIComponent(tenantId));
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof payload?.error === 'string' ? payload.error : 'Wazuh alerts could not be loaded.');
      if (!Array.isArray(payload?.events)) throw new Error('Wazuh connector returned an invalid event list.');
      if (payload.events.length === 0) throw new Error('Wazuh returned no alerts in this page. Check the index pattern and time window.');
      const next: Evidence[] = [];
      for (const [index, event] of payload.events.entries()) {
        if (!event || typeof event !== 'object' || typeof event.event_id !== 'string' ||
            typeof event.timestamp !== 'string' || typeof event.summary !== 'string') {
          throw new Error('Wazuh event ' + (index + 1) + ' is missing required identity, timestamp or summary fields.');
        }
        const parsedTime = parseIsoTimestamp(event.timestamp);
        if (!parsedTime) throw new Error('Wazuh event ' + event.event_id + ' has an invalid source timestamp.');
        const rawDetails = event.details && typeof event.details === 'object' && !Array.isArray(event.details)
          ? event.details as Record<string, unknown> : {};
        const details = await boundedDetails(rawDetails);
        const provenance = event.provenance && typeof event.provenance === 'object' && !Array.isArray(event.provenance)
          ? event.provenance as Record<string, unknown> : {};
        const item = {
          id: event.event_id.slice(0, 100),
          time: parsedTime,
          source: 'Wazuh',
          kind: typeof event.kind === 'string' ? event.kind.slice(0, 100) : 'security_alert',
          summary: event.summary.slice(0, 4096),
          details,
          metadata: {
            ...details,
            source_provider: 'wazuh-indexer',
            source_index: typeof provenance.index === 'string' ? provenance.index : '',
            source_document_id: typeof provenance.document_id === 'string' ? provenance.document_id : '',
            source_record_sha256: typeof provenance.source_record_sha256 === 'string' ? provenance.source_record_sha256 : '',
            source_timestamp_raw: typeof provenance.source_timestamp_raw === 'string' ? provenance.source_timestamp_raw : event.timestamp,
            source_snapshot_preserved: false,
          },
        };
        next.push({ ...item, digest: await digestEvidence(item) });
      }
      const ids = new Set<string>();
      for (const item of next) {
        if (ids.has(item.id)) throw new Error('Wazuh page contains duplicate event identities; no records were loaded.');
        ids.add(item.id);
      }
      setEvidence(next);
      setPersistentCaseId('');
      setServerInvestigation(null);
      setAudit([{ time: new Date().toISOString(), action: 'WAZUH_ALERTS_IMPORTED', detail: 'Loaded ' + next.length + ' real Wazuh Indexer alert(s) through the authenticated read-only connector. Alerts are not yet persisted until saved to a case.' }]);
      
      setCaseOpen(true);
      setImportName('Wazuh alerts');
      setSourceFileSha256('');
      setSelected('evidence');
      setNotice('Loaded ' + next.length + ' real Wazuh alert(s) as a bounded preview. This UI import does not retain the full indexed source object; use the private persistent worker for source-snapshot preservation. Review the records and save them to a case only with that limitation understood.');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Wazuh alerts could not be loaded.');
    } finally {
      setBusy(false);
    }
  }

  async function downloadWazuhSource(item: Evidence) {
    const tenantId = getActiveTenant();
    const objectPath = item.metadata?.source_object_path;
    if (!session || !tenantId || !persistentCaseId || typeof objectPath !== 'string') {
      setNotice('Load the saved case and sign in to retrieve its preserved source object.');
      return;
    }
    try {
      const params = new URLSearchParams({ tenant_id: tenantId, case_id: persistentCaseId, path: objectPath });
      const response = await authenticatedFetch('/api/firstlight/evidence/source?' + params.toString());
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(typeof payload?.error === 'string' ? payload.error : 'Preserved source object could not be downloaded.');
      }
      const expectedHash = response.headers.get('X-Content-SHA256');
      const blob = await response.blob();
      const actualHash = await digestBytes(await blob.arrayBuffer());
      if (!expectedHash || actualHash !== expectedHash) throw new Error('Downloaded source digest did not match the server-verified digest.');
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'wazuh-source-' + expectedHash + '.json';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice('Original Wazuh source snapshot downloaded and SHA-256 verified: ' + expectedHash);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Source object download failed.');
    }
  }

  function log(action: string, detail: string) { setAudit(prev => [...prev, {time:new Date().toISOString(),action,detail}]); }
  async function importFile(file?: File) {
    if (!file || busy) return;
    if (evidence.length > 0 && !window.confirm('Replace the current in-memory evidence with this imported file? Export or save your current case first if you need it.')) return;
    setNotice('');
    if (file.size > 5 * 1024 * 1024) { setNotice('File exceeds the 5 MiB import limit.'); return; }
    setBusy(true);
    try {
      const rawBytes = await file.arrayBuffer();
      if (rawBytes.byteLength > 5 * 1024 * 1024) throw new Error('File exceeds the 5 MiB import limit.');
      const text = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes);
      const sourceDigest = await digestBytes(rawBytes);
      let rows: any[];
      if (file.name.toLowerCase().endsWith('.json')) {
        const parsed = JSON.parse(text);
        rows = Array.isArray(parsed) ? parsed : Array.isArray(parsed.events) ? parsed.events : [];
      } else if (file.name.toLowerCase().endsWith('.csv')) rows = parseCsv(text);
      else throw new Error('Use a JSON or CSV event file.');
      if (!rows.length) throw new Error('No event records found. JSON must be an array or contain an events array.');
      if (rows.length > 10000) throw new Error('Import exceeds 10,000 event records.');
      if (rows.some(row => !row || typeof row !== 'object' || Array.isArray(row))) throw new Error('Every JSON event must be an object with event fields.');
      const next: Evidence[] = [];
      for (const [i,row] of rows.entries()) {
        const rawTime = row.timestamp || row.time;
        if (rawTime === undefined || rawTime === null || String(rawTime).trim() === '') {
          throw new Error('Missing timestamp in event ' + (i + 1) + '. Add a source timestamp; SATARK will not invent event times.');
        }
        const parsedTime = parseIsoTimestamp(rawTime);
        if (!parsedTime) throw new Error('Invalid timestamp in event ' + (i + 1) + '. Use ISO 8601 date/time with an explicit timezone, e.g. 2026-10-11T10:00:00Z.');
        const rawSummary = row.summary ?? row.message ?? row.description;
        if (typeof rawSummary !== 'string' || !rawSummary.trim()) {
          throw new Error('Missing summary in event ' + (i + 1) + '. Include summary/message/description; SATARK will not invent event content.');
        }
        const rawId = row.id ?? row.evidence_id ?? row.event_id;
        const hasSourceId = typeof rawId === 'string' && rawId.trim().length > 0;
        // This deterministic local key is derived from the uploaded bytes and row
        // position. It is never represented as an ID issued by the source system.
        const eventId = hasSourceId
          ? rawId.trim()
          : 'LOCAL-' + sourceDigest.slice(0, 16) + '-' + String(i + 1).padStart(5, '0');
        const rawSource = row.source ?? row.provider ?? row.source_system;
        const rawKind = row.kind ?? row.event_type ?? row.category;
        const item = {
          id: eventId.slice(0, 100),
          time: parsedTime,
          source: typeof rawSource === 'string' && rawSource.trim() ? rawSource.trim().slice(0, 160) : 'Unknown source',
          kind: typeof rawKind === 'string' && rawKind.trim() ? rawKind.trim().slice(0, 100) : 'Unknown event type',
          summary: rawSummary.trim().slice(0, 4096),
          details: await boundedDetails(row.details),
          metadata: { identity_origin: hasSourceId ? 'source_record' : 'local_import_digest' },
        };
        next.push({ ...item, digest: await digestEvidence(item) });
      }
      const ids = new Set<string>();
      for (const item of next) {
        if (ids.has(item.id)) throw new Error('Duplicate evidence ID after normalization: ' + item.id + '. Each event must have a unique ID.');
        ids.add(item.id);
      }
      setEvidence(next); setPersistentCaseId(''); setServerInvestigation(null); setAudit([{time:new Date().toISOString(),action:'ARTIFACT_IMPORTED',detail:file.name+' · '+next.length+' normalized records · original file SHA-256: '+sourceDigest+' · IDs without source IDs are local digest-derived row keys, not source event IDs; no external anchor or custody log.'}]); setCaseOpen(true); setImportName(file.name); setSourceFileSha256(sourceDigest); setSelected('evidence'); setNotice('Imported locally. Original file bytes and normalized event records were hashed in this browser; nothing was sent to an AI provider.');
    } catch (e) { setNotice(e instanceof Error ? e.message : 'Could not parse this artifact.'); }
    finally { setBusy(false); }
  }
  async function verifyIntegrity(records: Evidence[] = evidence) {
    const verified: Evidence[] = [];
    for (const record of records) {
      const currentDigest = await digestEvidence(record);
      verified.push({ ...record, tampered: currentDigest !== record.digest });
    }
    setEvidence(verified);
    setServerInvestigation(null);
    const mismatches = verified.filter(record => record.tampered);
    log(mismatches.length ? 'INTEGRITY_MISMATCH' : 'INTEGRITY_VERIFIED',
      mismatches.length
        ? mismatches.length + ' record(s) differ from their stored SHA-256 digest: ' + mismatches.map(record => record.id).join(', ')
        : verified.length + ' record(s) match their stored SHA-256 digest.');
    setNotice(mismatches.length
      ? 'Integrity check found ' + mismatches.length + ' mismatch(es). Review the marked records; this check does not prove original-source authenticity.'
      : 'Integrity check complete: all ' + verified.length + ' current records match their stored digests. This does not independently prove original-source authenticity.');
  }
  function exportEvidence() {
    const payload = {
      schema_version: 1,
      exported_at: new Date().toISOString(),
      case_type: persistentCaseId ? 'persisted-case' : importName === 'Wazuh alerts' ? 'wazuh-preview' : 'imported-events',
      import_name: importName || null,
      source_file_sha256: sourceFileSha256 || null,
      evidence: evidence.map(item => ({
        id: item.id,
        timestamp: item.time,
        source: item.source,
        kind: item.kind,
        summary: item.summary,
        normalized_record_sha256: item.digest,
        details: item.details || {},
        source_metadata: item.metadata || {},
        integrity_mismatch: Boolean(item.tampered),
      })),
      activity_log: audit,
      limitations: [
        'This export is a local review bundle, not a certified forensic report or chain-of-custody record.',
        'The original source file bytes are not included in this bundle; only their SHA-256 is included when available.',
        'Browser-side hashes bind normalized records but are not independently anchored or proof of original-source authenticity.',
        'A direct Wazuh preview is not durable source preservation; use the configured persistent ingestion worker for full source snapshots.',
        'Live response approvals, execution and verification are recorded in the separate server response ledger; this export does not represent a response action.',
      ],
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'firstlight-evidence-review.json';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice('Evidence review JSON exported. This local bundle is not certified forensic preservation.');
  }
  if (!authChecked) return <div className="shell"><SiteHeader /><main id="main-content" className="container"><p role="status" className="muted">Checking your secure session…</p><FirstlightReadiness /></main></div>;
  if (!session) return <div className="shell"><SiteHeader /><main id="main-content" className="container"><p role="status" className="muted">Redirecting to secure sign-in…</p><FirstlightReadiness /></main></div>;

  return <main className="shell"><SiteHeader />
    <div className="container subpage firstlight-page" id="main-content" tabIndex={-1}>
      <div className="firstlight-hero"><div><div className="eyebrow">Primary workspace</div><h1>FIRSTLIGHT<span className="heading-line">Incident Command.</span></h1><p className="lead">Investigate actual Wazuh alerts or permitted source evidence. FIRSTLIGHT keeps provenance, integrity checks, case activity and guarded response separate; it does not seed sample incidents or treat missing integrations as healthy.</p><div className="actions"><button className="btn btn-primary" disabled={busy || !session} onClick={()=>void loadWazuhAlerts()}>{busy?'Loading Wazuh alerts…':'Load Wazuh alert preview'}</button><label className="btn btn-secondary upload-trigger">Import evidence JSON / CSV<input type="file" accept=".json,.csv,application/json,text/csv" disabled={busy} onChange={e=>{const file=e.currentTarget.files?.[0];e.currentTarget.value='';void importFile(file);}}/></label></div></div>
      <div className="incident-brief"><div className="brief-top"><span>Incident brief</span><span className="live-chip"><i/> {persistentCaseId?'PERSISTED':importName==='Wazuh alerts'?'WAZUH PREVIEW':importName?'IMPORTED':'NO CASE'}</span></div><div className="brief-id">{persistentCaseId || (caseOpen ? (importName==='Wazuh alerts' ? 'WAZUH ALERT PREVIEW' : importName ? 'IMPORTED EVIDENCE' : 'UNSAVED EVIDENCE') : 'FL / READY')}</div><p>{persistentCaseId?'Saved case loaded from the workspace database.':importName==='Wazuh alerts'?'Bounded Wazuh alert preview. It is not persisted, and this UI path does not retain the full indexed source object.':importName?'Evidence imported from '+importName:caseOpen?'Evidence is loaded but not yet saved to a persistent case.':'Create or load a saved case, then collect source evidence.'}</p><div className="brief-stats"><div><strong>{evidence.length}</strong><span>Artifacts</span></div><div><strong>{findings.length}</strong><span>Findings</span></div><div><strong>{audit.length}</strong><span>Audit events</span></div></div></div></div>
      <FirstlightReadiness />
      <div className="boundary-banner"><span className="boundary-icon">◇</span><div><strong>Evidence-first, not verdict-first</strong><p>Hashes prove only whether these in-session records changed relative to their captured digest. This is not independently anchored chain-of-custody evidence.</p></div></div>
      {notice&&<div className="notice-panel" role="status">{notice}</div>}
      <div id="persistent-workspace" ref={persistentPanelRef} style={{ minHeight: 120 }}>
        {persistentPanelVisible
          ? <PersistentCasePanel evidence={evidence} findings={findings} audit={audit} currentCaseId={persistentCaseId} importName={importName}
              onLoaded={(caseId, rows, events) => { setPersistentCaseId(caseId); setEvidence(rows); setAudit(events); setCaseOpen(true); setSelected('evidence'); setNotice('Persistent case loaded from the workspace database.'); }}
              onSaved={(caseId, message) => { setPersistentCaseId(caseId); setNotice(message); }} />
          : <div className="panel" role="status"><div className="panel-kicker">Persistent workspace</div><p className="muted">Workspace controls load when this section is near the viewport.</p></div>}
      </div>
      <div className="firstlight-layout"><aside className="incident-nav"><div className="eyebrow">Investigation flow</div>{[['overview','Overview'],['evidence','Evidence ledger'],['findings','Findings & gaps'],['timeline','Event timeline'],['response','Response review'],['audit','Audit trail']].map(([key,label])=><button key={key} className={selected===key?'selected':''} onClick={()=>setSelected(key)}>{label}<span>{key==='evidence'?evidence.length:key==='findings'?findings.length:key==='audit'?audit.length:''}</span></button>)}<div className="side-boundary">Live response requires an authorized Wazuh lab<br/>No response action is taken automatically</div></aside>
      <section className="incident-content">
        {selected==='overview'&&<div className="panel"><div className="panel-kicker">Case overview</div><h2>Establish the timeline before deciding.</h2><p>Connect real Wazuh telemetry or import a permitted JSON/CSV artifact. Records are normalized and hashed locally; this hash is not an external timestamp or proof of source authenticity. No sample data is loaded. Missing source fields remain unknown.</p><div className="overview-steps">{[['01','Collect','Connect Wazuh or import source events.'],['02','Validate','Inspect digests and source context.'],['03','Correlate','Review rules-based findings and gaps.'],['04','Decide','Use a saved case for guarded Wazuh approval and verification.']].map(x=><div key={x[0]}><span>{x[0]}</span><strong>{x[1]}</strong><small>{x[2]}</small></div>)}</div></div>}
        {selected==='evidence'&&<div className="panel"><div className="panel-heading"><div><div className="panel-kicker">Evidence ledger</div><h2>Artifacts & integrity</h2></div><div className="actions"><button className="mini-btn" onClick={() => { void verifyIntegrity(); }} disabled={!evidence.length || busy}>Verify integrity</button><button className="mini-btn" onClick={exportEvidence} disabled={!evidence.length}>Export evidence JSON ↓</button><span className="pill">{persistentCaseId?'SAVED CASE':importName||'UNSAVED EVIDENCE'}</span></div></div>{!evidence.length?<p className="empty-state">No evidence loaded. Fetch a configured Wazuh alert page or import a JSON/CSV file with source timestamps and summaries. No sample events are loaded.</p>:<><div className="table-wrap"><table className="evidence-table"><thead><tr><th>Artifact</th><th>Source / time</th><th>Observation</th><th>Integrity</th><th/></tr></thead><tbody>{evidence.map(item=><tr key={item.id}><td><strong>{item.id}</strong><small>{item.metadata?.identity_origin === 'local_import_digest' ? 'Local import identifier · ' : ''}{item.kind}</small></td><td>{item.source}<small title={item.time}>{new Date(item.time).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}</small></td><td>{item.summary}<small className="digest">{item.digest}</small></td><td><span className={item.tampered === true?'risk-chip':item.tampered === false?'safe-chip':'review-chip'}>{item.tampered === true?'MISMATCH':item.tampered === false?'MATCH':'DIGEST STORED'}</span></td><td>{typeof item.metadata?.source_object_path === 'string' && <button className="mini-btn" disabled={!persistentCaseId} onClick={()=>void downloadWazuhSource(item)}>Download source</button>}</td></tr>)}</tbody></table></div></>}</div>}
        {selected==='findings'&&<div className="panel"><div className="panel-kicker">Deterministic correlation</div><h2>Findings & evidence gaps</h2><p>Run the canonical Python investigation engine through the shared API. If that service is not configured, the local rule view is only a fallback.</p>{caseOpen&&evidence.length>0&&<FindingsInsights findings={findings} evidence={evidence}/>}{!caseOpen?<p className="empty-state">Load a case to generate findings.</p>:<button className="btn btn-primary" onClick={runSharedInvestigation} disabled={serverBusy}>{serverBusy?'Running shared investigation…':'Run shared Python investigation'}</button>}{notice&&<div className="notice-panel" role="status">{notice}</div>}{quarantinedEvidenceCount>0&&<div className="notice-panel" role="alert">{quarantinedEvidenceCount} evidence record(s) have a hash mismatch and are quarantined from local findings.</div>}{serverInvestigation&&<><div className="gap-card"><strong>Shared engine integrity result</strong><p>{serverInvestigation.integrity_summary.verified} verified · {serverInvestigation.integrity_summary.mismatched} mismatched · {serverInvestigation.integrity_summary.total} total records</p><p>Engine mode: {serverInvestigation.investigation.orchestrator.mode}. Independent model agents are not enabled.</p></div>{serverInvestigation.investigation.findings.map((f:any,i:number)=><article className="finding-card" key={f.finding_id}><div className="finding-number">{String(i+1).padStart(2,'0')}</div><div><div className="finding-title-row"><h3>{f.title}</h3><span className={f.severity==='high'?'risk-chip':'review-chip'}>{f.severity}</span></div><p>{f.explanation}</p><div className="reference-list">Evidence references: {f.evidence_ids.length?f.evidence_ids.join(', '):'No integrity-verified references'}</div><small>State: {f.state} · Confidence: {f.confidence}</small></div></article>)}<div className="gap-card"><strong>Investigation stage trace</strong>{serverInvestigation.investigation.agent_trace.map((agent:any)=><p key={agent.agent_id}><b>{agent.name}</b> · {agent.status} · {agent.inputs} input(s) → {agent.outputs} output(s)<br/><small>{agent.summary}</small></p>)}</div><div className="gap-card"><strong>Evidence gaps</strong><ul>{serverInvestigation.investigation.gaps.map((gap:string)=><li key={gap}>{gap}</li>)}</ul></div></>}{!serverInvestigation&&caseOpen&&trustedEvidence.length>0&&(findings.length?findings.map((f,i)=><article className="finding-card" key={f.title}><div className="finding-number">{String(i+1).padStart(2,'0')}</div><div><div className="finding-title-row"><h3>{f.title}</h3><span className={f.severity==='High'?'risk-chip':'review-chip'}>{f.severity}</span></div><p>{f.detail}</p><div className="reference-list">Evidence references: {f.refs.length?f.refs.join(', '):'No direct references'}</div></div></article>):<p className="empty-state">No local pattern matched. This does not prove the incident is benign.</p>)}{!serverInvestigation&&caseOpen&&trustedEvidence.length===0&&<p className="empty-state">No integrity-verified evidence is available. Findings are withheld until evidence is restored or re-collected.</p>}<div className="gap-card"><strong>Evidence gaps to resolve</strong><ul><li>Confirm the source system and collection time for each artifact.</li><li>Independently validate sign-in IP, device, and user context.</li><li>Verify any destination domain through a trusted channel.</li><li>Preserve originals and document external corroboration.</li></ul></div></div>}
        {selected==='timeline'&&<div className="panel"><div className="panel-kicker">Event reconstruction</div><h2>Put observations in context.</h2>{timeline.length>0&&<EventTracker timeline={timeline} findings={findings}/>}{!timeline.length?<p className="empty-state">No timeline yet. Load real source events or import a permitted artifact.</p>:<div className="timeline-list">{timeline.map((item,i)=><div className={'timeline-item'+(item.tampered?' is-tampered':'')} key={item.id}><div className="timeline-rail"><span/></div><div className="timeline-time">{new Date(item.time).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}</div><strong>{item.kind.replaceAll('_',' ')}</strong><p>{item.summary}</p><small>{item.source} · {item.id}</small></div>)}</div>}</div>}
        {selected==='response'&&<div className="panel"><div className="panel-kicker">Human decision gate</div><h2>Review before you respond.</h2><p>Real endpoint response is available from a saved case in the persistent workspace. It requires a configured private Wazuh Manager, an allowlisted lab agent, a separate requester, approver and executor, exact-target confirmation, and independent verification. It remains disabled when the server feature flag or lab credentials are absent.</p><div className="actions"><a className="btn btn-primary" href="#persistent-workspace">{persistentCaseId?'Open saved case response controls':'Save or load a case to access guarded response'} →</a></div><div className="gap-card"><strong>Response execution boundary</strong><p>Only the guarded live-response workflow in a saved case can request or execute an action. It requires a private Wazuh Manager, an explicit agent allowlist, distinct requester, approver and executor identities, exact-target confirmation, and independent verification. If the lab is not configured, response controls remain unavailable.</p></div></div>}
        {selected==='audit'&&<div className="panel"><div className="panel-kicker">Session activity</div><h2>Activity log</h2><p>This view is not the authoritative server audit ledger. Use the saved-case workspace to verify durable audit history and response records.</p>{!audit.length?<p className="empty-state">No activity recorded in this browser session yet.</p>:<div className="audit-list">{audit.map((item,i)=><div key={i} className="audit-row"><span className="audit-dot"/><div><strong>{item.action}</strong><p>{item.detail}</p><small>{new Date(item.time).toLocaleString('en-IN')}</small></div></div>)}</div>}</div>}
      </section></div>
      <section className="more-tools"><div><div className="eyebrow">Supporting workflow</div><h2>Analyze suspicious content</h2><p className="lead">Use SATARK's active same-site analysis workflow for messages and URLs. The separate legacy Streamlit deployment is not linked here because it is currently inactive.</p></div><div className="actions"><a className="btn btn-primary" href="/investigate">Open SATARK analysis →</a></div></section>
    </div></main>;
}
