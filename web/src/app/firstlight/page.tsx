'use client';

import SiteHeader from '../site-header';

import { useEffect, useMemo, useState } from 'react';
import { getActiveTenant, getSession, type SatarkSession } from '../../lib/satark-auth';
import PersistentCasePanel from './persistent-case-panel';
import { EventTracker, FindingsInsights } from './insights';
import { parseCsv, parseIsoTimestamp, toggleSimulatedTamper } from '../../lib/firstlight-import.mjs';
import { buildFirstlightFindings, getTrustedFirstlightEvidence } from '../../lib/firstlight-investigation.mjs';
// The fallback reads only supplied summaries; it does not inspect the endpoint or file.

type Evidence = { id: string; time: string; source: string; kind: string; summary: string; digest: string; tampered?: boolean; details?: Record<string, unknown>; metadata?: Record<string, unknown> };
type Audit = { time: string; action: string; detail: string };
const starter = [
  { id: 'EV-001', time: '2026-10-11T09:14:00+05:30', source: 'Identity provider', kind: 'sign_in', summary: 'Successful sign-in from a new browser profile.' },
  { id: 'EV-002', time: '2026-10-11T09:17:00+05:30', source: 'Mailbox audit', kind: 'rule_change', summary: 'A new inbox forwarding rule was created.' },
  { id: 'EV-003', time: '2026-10-11T09:19:00+05:30', source: 'Identity provider', kind: 'mfa_change', summary: 'Multi-factor authentication settings were changed.' },
  { id: 'EV-004', time: '2026-10-11T09:23:00+05:30', source: 'Endpoint telemetry', kind: 'process', summary: 'A browser process opened a suspicious attachment path.' },
  { id: 'EV-005', time: '2026-10-11T09:28:00+05:30', source: 'Mail gateway', kind: 'message', summary: 'A lookalike-domain message requested an urgent account review.' }
];

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
  const [session, setSession] = useState<SatarkSession | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [selected, setSelected] = useState('overview');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [actions, setActions] = useState<string[]>([]);
  const [caseOpen, setCaseOpen] = useState(false);
  const [showTamper, setShowTamper] = useState(false);
  const [importName, setImportName] = useState('');
  const [sourceFileSha256, setSourceFileSha256] = useState('');
  const [persistentCaseId, setPersistentCaseId] = useState('');
  const [serverInvestigation, setServerInvestigation] = useState<any>(null);
  const [serverBusy, setServerBusy] = useState(false);
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
      const caseId = persistentCaseId || (importName ? 'FL-IMPORT-' + sourceFileSha256.slice(0, 12) : 'FL-WEB-DEMO-001');
      const response = await fetch('/api/firstlight/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(session ? { Authorization: 'Bearer ' + session.access_token } : {}) },
        body: JSON.stringify({
          case_id: caseId,
          title: importName ? 'Imported evidence investigation' : 'Synthetic account-compromise training case',
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
    const tenantId = getActiveTenant();
    if (!tenantId) { setNotice('Select a workspace before loading real Wazuh alerts.'); return; }
    setBusy(true);
    setNotice('');
    try {
      const response = await fetch('/api/firstlight/wazuh/alerts?limit=100&tenant_id=' + encodeURIComponent(tenantId), {
        headers: { Authorization: 'Bearer ' + session.access_token },
        cache: 'no-store',
      });
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
      setActions([]);
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
      const response = await fetch('/api/firstlight/evidence/source?' + params.toString(), {
        headers: { Authorization: 'Bearer ' + session.access_token },
        cache: 'no-store',
      });
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
  async function loadCase() {
    setBusy(true); setNotice('');
    try {
      const sealed: Evidence[] = [];
      for (const event of starter) sealed.push({...event, digest: await digestEvidence(event)});
      setEvidence(sealed); setPersistentCaseId(''); setServerInvestigation(null); setAudit([]); setActions([]); setCaseOpen(true); setImportName(''); setSourceFileSha256('');
      setAudit([{time:new Date().toISOString(),action:'CASE_CREATED',detail:'Synthetic account-compromise training case loaded.'},{time:new Date().toISOString(),action:'EVIDENCE_SEALED',detail:sealed.length+' synthetic records hashed with SHA-256 in this browser session.'}]);
      setSelected('evidence');
    } catch { setNotice('Web Crypto is unavailable in this browser. Try a modern browser over HTTPS.'); }
    finally { setBusy(false); }
  }
  async function importFile(file?: File) {
    if (!file || busy) return;
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
        const item = {id:String(row.id || row.evidence_id || 'IMP-'+String(i+1).padStart(3,'0')).slice(0,100),time:parsedTime,source:String(row.source || 'Imported source').slice(0,160),kind:String(row.kind || 'observation').slice(0,100),summary:String(row.summary || row.message || row.description || 'No summary provided').slice(0,4096),details:await boundedDetails(row.details)};
        next.push({...item,digest:await digestEvidence(item)});
      }
      const ids = new Set<string>();
      for (const item of next) {
        if (ids.has(item.id)) throw new Error('Duplicate evidence ID after normalization: ' + item.id + '. Each event must have a unique ID.');
        ids.add(item.id);
      }
      setEvidence(next); setPersistentCaseId(''); setServerInvestigation(null); setAudit([{time:new Date().toISOString(),action:'ARTIFACT_IMPORTED',detail:file.name+' · '+next.length+' normalized records · original file SHA-256: '+sourceDigest+' · file bytes hashed locally; no external anchor or custody log.'}]); setActions([]); setCaseOpen(true); setImportName(file.name); setSourceFileSha256(sourceDigest); setSelected('evidence'); setNotice('Imported locally. Original file bytes and normalized event records were hashed in this browser; nothing was sent to an AI provider.');
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
  async function tamper(item: Evidence) {
    const changed = evidence.map(e => {
      if (e.id !== item.id) return e;
      return { ...e, summary: toggleSimulatedTamper(e.summary, Boolean(e.tampered)) };
    });
    await verifyIntegrity(changed);
  }
  function responseAction(action: string, decision: 'Approved'|'Rejected') {
    setActions(prev=>[...prev,decision+' · '+action]); log('SIMULATED_RESPONSE_'+decision.toUpperCase(),action+' · training only; no real system action executed.');
  }
  function exportEvidence() {
    const payload = {
      schema_version: 1,
      exported_at: new Date().toISOString(),
      case_type: importName ? 'imported-events' : 'synthetic-training',
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
        simulated_tamper: Boolean(item.tampered),
      })),
      audit_trail: audit,
      simulated_response_decisions: actions,
      limitations: [
        'This export is a local review bundle, not a certified forensic report or chain-of-custody record.',
        'The original source file bytes are not retained in this bundle; only their SHA-256 is included when available.',
        'Hashes and audit events are not independently anchored, signed, access-controlled, or durably stored by SATARK.',
        'Response decisions are simulations only; no real endpoint, identity provider, or network control was changed.',
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
  if (!authChecked || !session) return <div className="shell"><SiteHeader /><main id="main-content" className="container"><p role="status" className="muted">Checking your secure session…</p></main></div>;

  return <main className="shell"><SiteHeader />
    <div className="container subpage firstlight-page" id="main-content" tabIndex={-1}>
      <div className="firstlight-hero"><div><div className="eyebrow">Primary workspace</div><h1>FIRSTLIGHT<span className="heading-line">Incident Command.</span></h1><p className="lead">Reconstruct a security incident from evidence, verify integrity, correlate activity, and review response decisions. The training scenario is synthetic; no real accounts or endpoints are changed.</p><div className="actions"><button className="btn btn-primary" disabled={busy} onClick={loadCase}>{busy?'Loading evidence…':caseOpen && !importName?'Reset training case':caseOpen?'Load synthetic case':'Launch training case ↗'}</button><button className="btn btn-secondary" disabled={busy || !session} onClick={()=>void loadWazuhAlerts()}>Load real Wazuh alerts</button><label className="btn btn-secondary upload-trigger">Import JSON / CSV<input type="file" accept=".json,.csv,application/json,text/csv" disabled={busy} onChange={e=>{const file=e.currentTarget.files?.[0];e.currentTarget.value='';void importFile(file);}}/></label></div></div>
      <div className="incident-brief"><div className="brief-top"><span>Incident brief</span><span className="live-chip"><i/> SYNTHETIC</span></div><div className="brief-id">{caseOpen?'FL-TRAINING-001':'FL / READY'}</div><p>{caseOpen?'Account-compromise simulation · evidence loaded':'A guided investigation is ready to initialize.'}</p><div className="brief-stats"><div><strong>{evidence.length}</strong><span>Artifacts</span></div><div><strong>{findings.length}</strong><span>Findings</span></div><div><strong>{audit.length}</strong><span>Audit events</span></div></div></div></div>
      <div className="boundary-banner"><span className="boundary-icon">◇</span><div><strong>Evidence-first, not verdict-first</strong><p>Hashes prove only whether these in-session records changed relative to their captured digest. This is not independently anchored chain-of-custody evidence.</p></div></div>
      {notice&&<div className="notice-panel" role="status">{notice}</div>}
      <PersistentCasePanel evidence={evidence} findings={findings} audit={audit} actions={actions} currentCaseId={persistentCaseId} importName={importName}
        onLoaded={(caseId, rows, events) => { setPersistentCaseId(caseId); setEvidence(rows); setAudit(events); setActions([]); setCaseOpen(true); setSelected('evidence'); setNotice('Persistent case loaded from the workspace database.'); }}
        onSaved={(caseId, message) => { setPersistentCaseId(caseId); setNotice(message); }} />
      <div className="firstlight-layout"><aside className="incident-nav"><div className="eyebrow">Investigation flow</div>{[['overview','Overview'],['evidence','Evidence ledger'],['findings','Findings & gaps'],['timeline','Event timeline'],['response','Response review'],['audit','Audit trail']].map(([key,label])=><button key={key} className={selected===key?'selected':''} onClick={()=>setSelected(key)}>{label}<span>{key==='evidence'?evidence.length:key==='findings'?findings.length:key==='audit'?audit.length:''}</span></button>)}<div className="side-boundary">Session only<br/>No real response actions</div></aside>
      <section className="incident-content">
        {selected==='overview'&&<div className="panel"><div className="panel-kicker">Case overview</div><h2>Establish the timeline before deciding.</h2><p>Start with the synthetic case or import a permitted JSON/CSV event artifact. Each event is normalized, hashed locally and reviewed with simple deterministic patterns.</p><div className="overview-steps">{[['01','Collect','Load training data or import events.'],['02','Validate','Inspect digests and source context.'],['03','Correlate','Review rules-based findings and gaps.'],['04','Decide','Record simulated response approvals.']].map(x=><div key={x[0]}><span>{x[0]}</span><strong>{x[1]}</strong><small>{x[2]}</small></div>)}</div>{!caseOpen&&<button className="btn btn-primary" onClick={loadCase}>Load synthetic case →</button>}</div>}
        {selected==='evidence'&&<div className="panel"><div className="panel-heading"><div><div className="panel-kicker">Evidence ledger</div><h2>Artifacts & integrity</h2></div><div className="actions"><button className="mini-btn" onClick={() => { void verifyIntegrity(); }} disabled={!evidence.length || busy}>Verify integrity</button><button className="mini-btn" onClick={exportEvidence} disabled={!evidence.length}>Export evidence JSON ↓</button><span className="pill">{importName||'TRAINING CASE'}</span></div></div>{!evidence.length?<p className="empty-state">No case loaded. Launch the training case or import a JSON/CSV event file.</p>:<><div className="table-wrap"><table className="evidence-table"><thead><tr><th>Artifact</th><th>Source / time</th><th>Observation</th><th>Integrity</th><th/></tr></thead><tbody>{evidence.map(item=><tr key={item.id}><td><strong>{item.id}</strong><small>{item.kind}</small></td><td>{item.source}<small title={item.time}>{new Date(item.time).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}</small></td><td>{item.summary}<small className="digest">{item.digest}</small></td><td><span className={item.tampered?'risk-chip':'safe-chip'}>{item.tampered?'MISMATCH':'HASHED'}</span></td><td><button className="mini-btn" onClick={()=>tamper(item)}>{item.tampered?'Restore demo':'Simulate tamper'}</button>{typeof item.metadata?.source_object_path === 'string' && <button className="mini-btn" disabled={!persistentCaseId} onClick={()=>void downloadWazuhSource(item)}>Download source</button>}</td></tr>)}</tbody></table></div><p className="hint">Simulation note: a tamper toggle modifies the record while preserving its original digest so the mismatch can be demonstrated.</p></>}</div>}
        {selected==='findings'&&<div className="panel"><div className="panel-kicker">Deterministic correlation</div><h2>Findings & evidence gaps</h2><p>Run the canonical Python investigation engine through the shared API. If that service is not configured, the local rule view is only a fallback.</p>{caseOpen&&evidence.length>0&&<FindingsInsights findings={findings} evidence={evidence}/>}{!caseOpen?<p className="empty-state">Load a case to generate findings.</p>:<button className="btn btn-primary" onClick={runSharedInvestigation} disabled={serverBusy}>{serverBusy?'Running shared investigation…':'Run shared Python investigation'}</button>}{notice&&<div className="notice-panel" role="status">{notice}</div>}{quarantinedEvidenceCount>0&&<div className="notice-panel" role="alert">{quarantinedEvidenceCount} evidence record(s) have a hash mismatch and are quarantined from local findings.</div>}{serverInvestigation&&<><div className="gap-card"><strong>Shared engine integrity result</strong><p>{serverInvestigation.integrity_summary.verified} verified · {serverInvestigation.integrity_summary.mismatched} mismatched · {serverInvestigation.integrity_summary.total} total records</p><p>Engine mode: {serverInvestigation.investigation.orchestrator.mode}. Independent model agents are not enabled.</p></div>{serverInvestigation.investigation.findings.map((f:any,i:number)=><article className="finding-card" key={f.finding_id}><div className="finding-number">{String(i+1).padStart(2,'0')}</div><div><div className="finding-title-row"><h3>{f.title}</h3><span className={f.severity==='high'?'risk-chip':'review-chip'}>{f.severity}</span></div><p>{f.explanation}</p><div className="reference-list">Evidence references: {f.evidence_ids.length?f.evidence_ids.join(', '):'No integrity-verified references'}</div><small>State: {f.state} · Confidence: {f.confidence}</small></div></article>)}<div className="gap-card"><strong>Agent execution trace</strong>{serverInvestigation.investigation.agent_trace.map((agent:any)=><p key={agent.agent_id}><b>{agent.name}</b> · {agent.status} · {agent.inputs} input(s) → {agent.outputs} output(s)<br/><small>{agent.summary}</small></p>)}</div><div className="gap-card"><strong>Evidence gaps</strong><ul>{serverInvestigation.investigation.gaps.map((gap:string)=><li key={gap}>{gap}</li>)}</ul></div></>}{!serverInvestigation&&caseOpen&&trustedEvidence.length>0&&(findings.length?findings.map((f,i)=><article className="finding-card" key={f.title}><div className="finding-number">{String(i+1).padStart(2,'0')}</div><div><div className="finding-title-row"><h3>{f.title}</h3><span className={f.severity==='High'?'risk-chip':'review-chip'}>{f.severity}</span></div><p>{f.detail}</p><div className="reference-list">Evidence references: {f.refs.length?f.refs.join(', '):'No direct references'}</div></div></article>):<p className="empty-state">No local pattern matched. This does not prove the incident is benign.</p>)}{!serverInvestigation&&caseOpen&&trustedEvidence.length===0&&<p className="empty-state">No integrity-verified evidence is available. Findings are withheld until evidence is restored or re-collected.</p>}<div className="gap-card"><strong>Evidence gaps to resolve</strong><ul><li>Confirm the source system and collection time for each artifact.</li><li>Independently validate sign-in IP, device, and user context.</li><li>Verify any destination domain through a trusted channel.</li><li>Preserve originals and document external corroboration.</li></ul></div></div>}
        {selected==='timeline'&&<div className="panel"><div className="panel-kicker">Event reconstruction</div><h2>Put observations in context.</h2>{timeline.length>0&&<EventTracker timeline={timeline} findings={findings}/>}{!timeline.length?<p className="empty-state">No timeline yet. Load or import evidence first.</p>:<div className="timeline-list">{timeline.map((item,i)=><div className={'timeline-item'+(item.tampered?' is-tampered':'')} key={item.id}><div className="timeline-rail"><span/></div><div className="timeline-time">{new Date(item.time).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}</div><strong>{item.kind.replaceAll('_',' ')}</strong><p>{item.summary}</p><small>{item.source} · {item.id}</small></div>)}</div>}</div>}
        {selected==='response'&&<div className="panel"><div className="panel-kicker">Human decision gate</div><h2>Review before you respond.</h2><p>Approve or reject these simulated response proposals. Decisions are recorded in this browser session only; nothing is sent to an endpoint, identity provider, or network control.</p>{[['Preserve relevant logs','Export and retain original evidence under your organization’s policy.'],['Verify the account owner','Use a trusted out-of-band channel before making account changes.'],['Escalate for incident review','Ask an authorized responder to confirm scope and severity.']].map(([action,detail])=><div className="response-row" key={action}><div><strong>{action}</strong><p>{detail}</p></div><div className="response-buttons"><button className="mini-btn approve" onClick={()=>responseAction(action,'Approved')}>Approve</button><button className="mini-btn" onClick={()=>responseAction(action,'Rejected')}>Reject</button></div></div>)}{actions.length>0&&<div className="gap-card"><strong>Recorded decisions</strong>{actions.map((a,i)=><p key={i}>{a}</p>)}</div>}</div>}
        {selected==='audit'&&<div className="panel"><div className="panel-kicker">Session audit</div><h2>Decision trail</h2><p>Readable session events for this training run. This log is not externally anchored or tamper-proof.</p>{!audit.length?<p className="empty-state">No audit events yet. Load evidence or record a response decision.</p>:<div className="audit-list">{audit.map((item,i)=><div key={i} className="audit-row"><span className="audit-dot"/><div><strong>{item.action}</strong><p>{item.detail}</p><small>{new Date(item.time).toLocaleString('en-IN')}</small></div></div>)}</div>}</div>}
      </section></div>
      <section className="more-tools"><div><div className="eyebrow">Supporting workspace</div><h2>Need a content-level triage?</h2><p className="lead">Use SATARK's separate suspicious-content workflow for messages and URLs, or open the existing full Streamlit application for its additional scanners and learning tools.</p></div><div className="actions"><a className="btn btn-primary" href="/investigate">Open SATARK analysis →</a><a className="btn btn-secondary" href="https://satark-32uppvjxwmderrchbhj7gj.streamlit.app/" target="_blank" rel="noreferrer">Open full SATARK app ↗</a></div></section>
    </div></main>;
}
