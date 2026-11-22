/** FIRSTLIGHT deterministic investigation engine — JavaScript port of firstlight_engine.py + firstlight_rules.py.
 *
 * It lets the browser-only workspace run the same ten rules the hosted worker runs, over the same sealed
 * evidence envelopes, and produce the same findings, timeline, gaps and agent trace. Parity with the Python
 * engine is enforced by web/tests/firstlight-parity.test.mjs and tests/test_firstlight_js_parity.py, which both
 * check one shared golden fixture generated from the Python engine.
 *
 * Known, documented differences: JSON floats that are whole numbers (1.0) hash as `1` here because JavaScript
 * cannot tell them apart; integers above 2^53 lose precision; Python `str()` of nested lists/objects is not
 * reproduced exactly. Rules read strings and small integers, so these do not change findings on real telemetry.
 */

export const RULE_VERSION = '1.0.0';

const RULES = {
  'Wazuh source detection alert': { rule_id: 'FL-WAZUH-001', attack_techniques: [], logic_type: 'source_severity_context',
    limitations: ['Preserves Wazuh rule severity context; does not independently validate the source detection.'] },
  'Unfamiliar successful login': { rule_id: 'FL-IDENTITY-001', attack_techniques: ['T1078'], logic_type: 'single_event_heuristic',
    limitations: ['A novel login context is not proof of account compromise.'] },
  'Mailbox forwarding or rule change': { rule_id: 'FL-MAIL-001', attack_techniques: ['T1114.003'], logic_type: 'single_event_heuristic',
    limitations: ['The rule or forwarding destination must be independently checked for authorization.'] },
  'Authentication setting changed': { rule_id: 'FL-IDENTITY-002', attack_techniques: ['T1098'], logic_type: 'single_event_heuristic',
    limitations: ['The event does not establish whether the change was unauthorized.'] },
  'Social-engineering indicators': { rule_id: 'FL-PHISH-001', attack_techniques: ['T1566'], logic_type: 'keyword_heuristic',
    limitations: ['Message wording alone does not establish phishing or user interaction.'] },
  'Potentially suspicious endpoint activity': { rule_id: 'FL-ENDPOINT-001', attack_techniques: ['T1204.002'], logic_type: 'keyword_heuristic',
    limitations: ['FIRSTLIGHT has not inspected the underlying file or process in this rule.'] },
  'Unusual process ancestry': { rule_id: 'FL-ENDPOINT-002', attack_techniques: ['T1059'], logic_type: 'process_relationship_heuristic',
    limitations: ['Parent/child process context needs endpoint corroboration; suspicious ancestry can be legitimate.'] },
  'Potentially suspicious network activity': { rule_id: 'FL-NETWORK-001', attack_techniques: [], logic_type: 'network_indicator_heuristic',
    limitations: ['Destination reputation is not independently checked; temporal correlation does not prove causation.'] },
  'Possible data staging': { rule_id: 'FL-DISCOVERY-001', attack_techniques: ['T1074'], logic_type: 'file_path_heuristic',
    limitations: ['File paths and archive names do not prove collection, staging, or exfiltration.'] },
  'Follow-on identity session': { rule_id: 'FL-IDENTITY-003', attack_techniques: ['T1078'], logic_type: 'temporal_correlation',
    limitations: ['A session following authentication is expected in normal activity; verify account and session provenance.'] },
};

export function ruleMetadata(title) {
  const entry = RULES[title];
  if (!entry) {
    return { rule_id: 'FL-UNMAPPED-000', rule_version: RULE_VERSION, rule_source: 'FIRSTLIGHT', attack_techniques: [],
      logic_type: 'unmapped', rule_limitations: ['No versioned rule metadata is registered for this finding.'] };
  }
  return { ...structuredClone(entry), rule_version: RULE_VERSION, rule_source: 'FIRSTLIGHT', rule_limitations: [...entry.limitations] };
}

export function ruleTitles() { return Object.keys(RULES); }

// ---------- Python-compatible helpers ----------
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => isObject(o) && Object.prototype.hasOwnProperty.call(o, k);
const get = (o, k, d) => (has(o, k) ? o[k] : d);
const truthy = v => !(v === null || v === undefined || v === false || v === 0 || v === '' ||
  (Array.isArray(v) && v.length === 0) || (isObject(v) && Object.keys(v).length === 0));

/** Mirrors Python str() for the scalar values that appear in telemetry. */
function pyStr(v) {
  if (v === null || v === undefined) return 'None';
  if (v === true) return 'True';
  if (v === false) return 'False';
  if (typeof v === 'string') return v;
  if (typeof v === 'number') return String(v);
  return JSON.stringify(v);
}
const lower = v => pyStr(v).toLowerCase();
/** str(d.get(key, "")) */
const strGet = (o, k) => pyStr(get(o, k, ''));
const isPyInt = v => typeof v === 'number' && Number.isInteger(v);
const containsAny = (text, terms) => terms.some(term => text.includes(term));

/** Python datetime.fromisoformat (3.11+) for the ISO forms telemetry uses; naive values are UTC. Invalid → Infinity. */
export function timestampMs(value) {
  const text = pyStr(value).replace('Z', '+00:00');
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2})(?::(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?)?(?:([+-])(\d{2})(?::?(\d{2})(?::?(\d{2}))?)?)?$/.exec(text);
  if (!m) return Infinity;
  const [, y, mo, d, h = '0', mi = '0', s = '0', frac = '', sign, oh = '0', om = '0', os = '0'] = m;
  const Y = +y, M = +mo, D = +d, H = +h, MI = +mi, S = +s;
  if (M < 1 || M > 12 || D < 1 || H > 23 || MI > 59 || S > 59 || +oh > 23 || +om > 59 || +os > 59) return Infinity;
  const probe = new Date(Date.UTC(Y, M - 1, D));
  if (probe.getUTCMonth() !== M - 1) return Infinity; // day not in month
  const micros = frac ? Number((frac + '000000').slice(0, 6)) : 0;
  let epoch = Date.UTC(Y, M - 1, D, H, MI, S) + micros / 1000;
  if (sign) epoch -= (sign === '-' ? -1 : 1) * ((+oh * 3600 + +om * 60 + +os) * 1000);
  return epoch;
}

// ---------- canonical JSON + hashing (json.dumps(sort_keys, separators, ensure_ascii=False)) ----------
const compareCodePoints = (a, b) => {
  const ai = [...a], bi = [...b];
  for (let i = 0; i < Math.min(ai.length, bi.length); i++) {
    const d = ai[i].codePointAt(0) - bi[i].codePointAt(0);
    if (d) return d;
  }
  return ai.length - bi.length;
};

export function canonicalPy(value) {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Out of range float values are not JSON compliant');
    return JSON.stringify(value);
  }
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalPy).join(',') + ']';
  if (isObject(value)) {
    return '{' + Object.keys(value).filter(k => value[k] !== undefined).sort(compareCodePoints)
      .map(k => JSON.stringify(k) + ':' + canonicalPy(value[k])).join(',') + '}';
  }
  throw new TypeError('Value is not JSON serializable');
}

export async function sha256Text(text) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export const sha256Record = async record => sha256Text(canonicalPy(record));

export async function sealEvidence(event) {
  if (!isObject(event)) throw new Error('Evidence event must be an object.');
  const eventId = event.event_id;
  if (typeof eventId !== 'string' || !eventId.trim()) throw new Error('Evidence event must include a non-empty event_id.');
  const record = structuredClone(event);
  return { evidence_id: record.event_id, record, sha256: await sha256Record(record),
    collected_at: new Date().toISOString(), integrity_status: 'verified' };
}

const MISMATCH = 'HASH MISMATCH — POSSIBLE TAMPERING';

export async function verifyEvidence(item) {
  if (!isObject(item)) return { evidence_id: 'unknown', expected_sha256: '', actual_sha256: '', valid: false, status: MISMATCH };
  const record = get(item, 'record', {});
  let actual = '';
  try { actual = await sha256Record(record); } catch { actual = ''; }
  const expected = pyStr(get(item, 'sha256', ''));
  const evidenceId = get(item, 'evidence_id', 'unknown');
  const recordId = isObject(record) ? record.event_id : null;
  const idMatches = truthy(recordId) && evidenceId === recordId;
  const valid = truthy(expected) && truthy(actual) && actual === expected && idMatches;
  return { evidence_id: evidenceId, expected_sha256: expected, actual_sha256: actual, valid, status: valid ? 'VERIFIED' : MISMATCH };
}

// ---------- prioritization ----------
const VOLATILITY = [['memory', 35], ['process', 30], ['connection', 28], ['session', 26], ['authentication', 24], ['login', 24],
  ['network', 22], ['identity', 20], ['registry', 15], ['file', 12], ['log', 12]];
const RELEVANCE = ['suspicious', 'unusual', 'novel', 'powershell', 'mfa', 'forwarding', 'archive', 'lookalike', 'credential',
  'failed', 'unexpected', 'malicious'];

/** int(value) for the str/int shapes Python accepts here; -1 when it does not parse. */
function wazuhLevel(raw) {
  if (typeof raw === 'number') return Number.isInteger(raw) ? raw : null;
  if (typeof raw === 'string') return /^\s*[+-]?\d+\s*$/.test(raw) ? parseInt(raw.trim(), 10) : -1;
  return null; // not int/str (booleans and everything else are ignored)
}

export async function prioritizeEvidence(evidence, now) {
  if (!Array.isArray(evidence)) throw new Error('Evidence must be a list.');
  const currentMs = now === undefined ? Date.now() : (now instanceof Date ? now.getTime() : Number(now));
  const out = [];
  for (const item of evidence) {
    if (!isObject(item)) continue;
    let record = get(item, 'record', {});
    if (!isObject(record)) record = {};
    const evidenceId = pyStr(get(item, 'evidence_id', 'unknown'));
    const kind = strGet(record, 'kind').toLowerCase();
    const source = strGet(record, 'source').toLowerCase();
    const summary = strGet(record, 'summary').toLowerCase();
    const details = isObject(record.details) ? record.details : {};
    const groups = get(details, 'rule_groups', []);
    const groupText = (Array.isArray(groups) ? groups : []).filter(g => typeof g === 'string' || isPyInt(g) || typeof g === 'boolean').map(pyStr).join(' ');
    const searchable = [kind, source, summary, strGet(details, 'rule_id'), groupText].join(' ');
    const integrity = await verifyEvidence(item);
    const reasons = [];

    const matches = VOLATILITY.filter(([term]) => kind.includes(term) || source.includes(term));
    const volatilityScore = matches.length ? Math.max(...matches.map(([, p]) => p)) : 8;
    const topTerms = matches.filter(([, p]) => p === volatilityScore).map(([t]) => t).sort();
    reasons.push(`Volatility: ${topTerms.length ? topTerms[topTerms.length - 1] : 'general artifact'} (+${volatilityScore})`);

    let relevanceScore = containsAny(searchable, RELEVANCE) ? 20 : 8;
    const level = wazuhLevel(get(details, 'rule_level', null));
    if (details.provider === 'wazuh-indexer' && level !== null) {
      if (level >= 0 && level <= 16) {
        relevanceScore = Math.max(relevanceScore, level >= 12 ? 25 : level >= 10 ? 20 : level >= 7 ? 15 : 8);
        reasons.push(`Wazuh source rule level ${level} (vendor severity context, not a probability)`);
      }
    }
    reasons.push(`Investigation relevance heuristic (+${relevanceScore})`);

    let integrityScore, nextStep;
    if (integrity.valid) {
      integrityScore = 10; reasons.push('Stored digest matches (+10)');
      nextStep = 'Preserve the source snapshot and corroborate with independent logs.';
    } else {
      integrityScore = 25; reasons.push('Integrity mismatch or malformed baseline (+25 review urgency)');
      nextStep = 'Quarantine from trusted conclusions; compare with a protected baseline and re-collect if possible.';
    }

    let recencyScore = 0;
    const observed = timestampMs(get(record, 'timestamp', null));
    if (Number.isFinite(observed)) {
      const ageMinutes = (currentMs - observed) / 60000;
      if (ageMinutes >= 0 && ageMinutes <= 15) recencyScore = 15;
      else if (ageMinutes >= 0 && ageMinutes <= 60) recencyScore = 12;
      else if (ageMinutes >= 0 && ageMinutes <= 360) recencyScore = 8;
      else if (ageMinutes >= 0 && ageMinutes <= 1440) recencyScore = 4;
      if (recencyScore) reasons.push(`Recent source timestamp (+${recencyScore})`);
    }

    const score = Math.min(100, volatilityScore + relevanceScore + integrityScore + recencyScore);
    const priority = score >= 75 ? 'critical' : score >= 55 ? 'high' : score >= 35 ? 'medium' : 'low';
    out.push({ evidence_id: evidenceId, priority, priority_score: score, integrity: integrity.status, reasons, recommended_next_step: nextStep });
  }
  return out.sort((a, b) => (b.priority_score - a.priority_score) || compareCodePoints(a.evidence_id, b.evidence_id));
}

// ---------- investigation ----------
const NO_MATCH_TITLE = 'No rule matched — analyst review required';

export async function investigateCase(caseObj, evidence, options = {}) {
  if (!isObject(caseObj)) throw new Error('Case must be an object.');
  const caseId = caseObj.case_id;
  if (typeof caseId !== 'string' || !caseId.trim()) throw new Error('Case must include a non-empty case_id.');
  if (!Array.isArray(evidence)) throw new Error('Evidence must be a list.');
  evidence = evidence.filter(isObject);

  const verdicts = new Map();
  for (const item of evidence) verdicts.set(item, await verifyEvidence(item));
  const validIds = evidence.filter(i => get(i, 'evidence_id', null) !== null && verdicts.get(i).valid).map(i => pyStr(i.evidence_id));
  const validIdSet = new Set(validIds);
  const findings = [];

  const addBase = (fid, title, explanation, severity, refs, confidence) => {
    const validRefs = [...new Set(refs.filter(r => validIdSet.has(r)))];
    findings.push({ finding_id: fid, title, explanation, severity, evidence_ids: validRefs, evidence_available: validRefs.length > 0,
      confidence: validRefs.length ? confidence : 'low', state: validRefs.length ? 'supported' : 'unverified' });
  };

  // Map keeps first-insertion order on overwrite, exactly like a Python dict.
  const validRecords = new Map();
  for (const item of evidence) {
    if (get(item, 'evidence_id', null) !== null && verdicts.get(item).valid && isObject(item.record)) validRecords.set(pyStr(item.evidence_id), item.record);
  }
  let nextFinding = 1;
  const addRule = (title, explanation, severity, refs, confidence) => {
    addBase('F-' + String(nextFinding).padStart(3, '0'), title, explanation, severity, refs, confidence);
    Object.assign(findings[findings.length - 1], ruleMetadata(title));
    nextFinding++;
  };

  const records = [...validRecords.entries()];
  for (const [evidenceId, record] of records) {
    const kind = strGet(record, 'kind').toLowerCase();
    const source = strGet(record, 'source').toLowerCase();
    const summary = strGet(record, 'summary').toLowerCase();
    let details = get(record, 'details', {});
    details = isObject(details) ? details : {};
    const groups = get(details, 'rule_groups', []);
    const groupsText = Array.isArray(groups) ? groups.filter(g => typeof g === 'string' || isPyInt(g) || typeof g === 'boolean').map(lower).join(' ') : '';
    const searchable = [kind, source, summary, strGet(details, 'rule').toLowerCase(), strGet(details, 'rule_id').toLowerCase(), groupsText].join(' ');
    const success = ['success', 'successful', 'succeeded'].includes(strGet(details, 'result').toLowerCase());

    const level = wazuhLevel(get(details, 'rule_level', null));
    if (details.provider === 'wazuh-indexer' && level !== null && level >= 7 && level <= 16) {
      const severity = level >= 12 ? 'critical' : level >= 10 ? 'high' : 'medium';
      addRule('Wazuh source detection alert',
        `The Wazuh Indexer record carries source rule level ${level}. This preserves the source detector's severity context; it is not an independently calibrated probability or proof of compromise. Corroborate the underlying event and host context.`,
        severity, [evidenceId], level >= 10 ? 'medium' : 'low');
    }

    if ((['authentication', 'login', 'sign_in'].includes(kind) || searchable.includes('login') || searchable.includes('sign-in')) &&
        (details.novel_source === true || containsAny(searchable, ['new source', 'new browser', 'new device', 'new location', 'unfamiliar'])) &&
        (success || searchable.includes('successful'))) {
      addRule('Unfamiliar successful login',
        'The source record describes a successful login in a new or unfamiliar context. This is an investigation lead, not proof of account compromise.',
        'high', [evidenceId], 'medium');
    }

    if (containsAny(searchable, ['forwarding rule', 'mailbox rule', 'inbox forwarding', 'mail forwarding'])) {
      addRule('Mailbox forwarding or rule change',
        'The supplied record describes a mailbox forwarding or rule change. Verify the rule owner, destination, and authorization independently.',
        'high', [evidenceId], 'medium');
    }

    if (containsAny(searchable, ['mfa', 'multi-factor', 'authentication settings', 'authentication method changed'])) {
      addRule('Authentication setting changed',
        'The supplied record describes an authentication-setting change. Verify whether it was authorized and whether recovery methods were affected.',
        'high', [evidenceId], 'medium');
    }

    if (['message', 'email', 'mail'].includes(kind) && containsAny(searchable, ['lookalike', 'urgent', 'password', 'otp', 'credential'])) {
      addRule('Social-engineering indicators',
        'The message summary includes urgency, lookalike-domain, or credential-request language. Verify sender and destination independently; wording alone is not proof of phishing.',
        'medium', [evidenceId], 'low');
    }

    if (kind === 'process' && containsAny(searchable, ['suspicious attachment', 'suspicious process', 'attachment path'])) {
      addRule('Potentially suspicious endpoint activity',
        'The supplied summary describes a potentially suspicious process or attachment path. This workflow does not inspect the actual process or file.',
        'medium', [evidenceId], 'low');
    }

    const parent = strGet(details, 'parent').toLowerCase();
    const processName = strGet(details, 'process').toLowerCase();
    const unusualParent = containsAny(parent, ['outlook', 'winword', 'excel', 'browser', 'email']);
    const scriptProcess = containsAny(processName, ['powershell', 'wscript', 'cscript', 'cmd.exe', 'bash', 'python']);
    if (kind === 'process' && (get(details, 'rule', null) === 'unusual_parent_child' || (unusualParent && scriptProcess))) {
      addRule('Unusual process ancestry',
        'The source records a script-capable process with a potentially unusual parent or rule match. Correlate with endpoint telemetry before inferring intent.',
        'high', [evidenceId], 'medium');
    }

    const destination = strGet(details, 'destination').toLowerCase();
    if (['connection', 'network'].includes(kind) && (searchable.includes('suspicious') || get(details, 'disposition', null) === 'suspicious' || destination.endsWith('.invalid'))) {
      const related = [evidenceId];
      const host = get(details, 'host', null);
      const currentTime = timestampMs(get(record, 'timestamp', null));
      const priorProcesses = records.filter(([eid, other]) => eid !== evidenceId &&
        strGet(other, 'kind').toLowerCase() === 'process' && isObject(other.details) &&
        (!truthy(host) || other.details.host === host) && timestampMs(get(other, 'timestamp', null)) <= currentTime);
      priorProcesses.sort((a, b) => cmpNum(timestampMs(get(a[1], 'timestamp', null)), timestampMs(get(b[1], 'timestamp', null))));
      if (priorProcesses.length) related.unshift(priorProcesses[priorProcesses.length - 1][0]);
      addRule('Potentially suspicious network activity',
        'The record contains a suspicious-destination signal. Any link to earlier process activity is temporal correlation, not proof of causation; verify destination context independently.',
        'medium', related, related.length === 1 ? 'low' : 'medium');
    }

    const path = strGet(details, 'path').toLowerCase();
    if (['file', 'filesystem'].includes(kind) &&
        (containsAny(path, ['.zip', '.7z', '.rar', '.tar', '.gz']) || containsAny(searchable, ['archive', 'staging', 'staged']) || path.includes('temp'))) {
      addRule('Possible data staging',
        'A file or archive-like artifact may indicate staging. The artifact alone does not establish its contents, purpose, or transfer.',
        'medium', [evidenceId], 'low');
    }

    if (kind === 'session' || searchable.includes('session')) {
      const account = get(details, 'account', null);
      const currentTime = timestampMs(get(record, 'timestamp', null));
      const priorAuth = records.filter(([eid, other]) => eid !== evidenceId &&
        ['authentication', 'login'].includes(strGet(other, 'kind').toLowerCase()) && isObject(other.details) &&
        (!truthy(account) || other.details.account === account) && timestampMs(get(other, 'timestamp', null)) <= currentTime);
      priorAuth.sort((a, b) => cmpNum(timestampMs(get(a[1], 'timestamp', null)), timestampMs(get(b[1], 'timestamp', null))));
      if (priorAuth.length) {
        addRule('Follow-on identity session',
          'A session record follows an authentication event for the same account or an unspecified account. Confirm session provenance before taking action.',
          'medium', [priorAuth[priorAuth.length - 1][0], evidenceId], 'medium');
      }
    }
  }

  if (!findings.length) {
    findings.push({ finding_id: 'F-001', title: NO_MATCH_TITLE,
      explanation: 'The supplied evidence did not match the current deterministic triage rules. This is not a safety clearance; review the source records and add case-specific checks as needed.',
      severity: 'info', evidence_ids: [], evidence_available: false, confidence: 'low', state: 'unverified',
      rule_id: 'FL-GENERIC-000', rule_version: RULE_VERSION, rule_source: 'FIRSTLIGHT', attack_techniques: [], logic_type: 'no_rule_match',
      rule_limitations: ['No detection rule matched; this is not a clearance that the system or case is safe.'] });
  }

  const timeline = evidence.map(item => {
    const checked = verdicts.get(item);
    let record = get(item, 'record', {});
    record = isObject(record) ? record : {};
    return { timestamp: get(record, 'timestamp', ''), event_id: get(item, 'evidence_id', ''), summary: get(record, 'summary', 'Unknown event'),
      source: get(record, 'source', 'unknown'), integrity: checked.status, evidence_ids: checked.valid ? [get(item, 'evidence_id', '')] : [] };
  });
  timeline.sort((a, b) => cmpNum(timestampMs(a.timestamp), timestampMs(b.timestamp)));

  const validKinds = new Set(records.map(([, r]) => strGet(r, 'kind').toLowerCase()));
  const gaps = ['Only supplied artifacts were reviewed; no live endpoint or identity collection was performed.'];
  if (!(validKinds.has('memory') || validKinds.has('process_snapshot'))) gaps.push('No memory image or live process snapshot is included in the supplied evidence.');
  const hasArchive = records.some(([, r]) => ['file', 'filesystem'].includes(strGet(r, 'kind').toLowerCase()) &&
    containsAny(strGet(r, 'summary').toLowerCase(), ['archive', 'staging', 'staged']));
  if (hasArchive) gaps.push('Archive contents and any successful transfer are not established by these records.');
  if (records.some(([, r]) => ['connection', 'network'].includes(strGet(r, 'kind').toLowerCase()))) gaps.push('Network destination reputation was not independently verified by this workflow.');

  const evidencePriorities = await prioritizeEvidence(evidence, options.now);
  const matched = findings.filter(f => f.title !== NO_MATCH_TITLE);
  const referencedIds = [...new Set(findings.flatMap(f => f.evidence_ids))].sort(compareCodePoints);
  const agentTrace = [
    { agent_id: 'evidence_integrity', name: 'Evidence Integrity Agent', mode: 'deterministic', status: 'completed', inputs: evidence.length, outputs: validIds.length,
      evidence_ids: [...validIds], summary: `Checked ${evidence.length} supplied records; ${validIds.length} matched their sealed hash and identity.` },
    { agent_id: 'evidence_triage', name: 'Evidence Triage Agent', mode: 'deterministic', status: 'completed', inputs: evidence.length, outputs: evidencePriorities.length,
      evidence_ids: evidencePriorities.map(p => p.evidence_id), summary: 'Ranked supplied records using transparent volatility, relevance, recency and integrity heuristics; scores are not probabilities.' },
    { agent_id: 'detection_correlation', name: 'Detection & Correlation Agent', mode: 'deterministic', status: 'completed', inputs: validRecords.size, outputs: matched.length,
      evidence_ids: referencedIds, summary: `Produced ${matched.length} rule-backed investigation lead(s) from integrity-verified records; temporal links do not prove causation.` },
    { agent_id: 'timeline_reconstruction', name: 'Timeline Reconstruction Agent', mode: 'deterministic', status: 'completed', inputs: evidence.length, outputs: timeline.length,
      evidence_ids: timeline.filter(t => t.evidence_ids.length).map(t => t.event_id), summary: `Ordered ${timeline.length} supplied events by source timestamp; records with invalid integrity remain visible but untrusted.` },
    { agent_id: 'verification', name: 'Verification & Gap Agent', mode: 'deterministic', status: 'completed', inputs: findings.length, outputs: findings.filter(f => f.evidence_ids.length).length,
      evidence_ids: referencedIds, summary: `Checked evidence references and recorded ${gaps.length} explicit evidence gap(s); unsupported claims remain unverified.` },
  ];
  return { schema_version: '1.1', case_id: caseId,
    orchestrator: { status: 'completed', mode: 'bounded_deterministic', strategy: 'Preserve → triage → detect/correlate → reconstruct → verify',
      agent_count: agentTrace.length, model_agents_enabled: false,
      note: 'Named stages are deterministic workflow agents in this prototype, not independent LLM agents.' },
    agents: agentTrace, agent_trace: agentTrace, findings, evidence_priorities: evidencePriorities, timeline, gaps };
}

function cmpNum(a, b) { return a === b ? 0 : a < b ? -1 : 1; }
