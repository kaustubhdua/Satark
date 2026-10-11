'use client';

import SiteHeader from '../site-header';
import { LatticeLoader, ThoughtLine } from '../../components/react-bits';
import { useState } from 'react';

type ThreatIntel = { status: string; source: string; detail: string; reference?: string };
type Analysis = {
  threat_category: string;
  risk_score: number;
  summary: string;
  key_indicators: string[];
  recommendations: string[];
  limitations: string[];
  deterministic_signals: string[];
  model: string;
  notice: string;
  threat_intel?: ThreatIntel;
  ip_threat_intel?: ThreatIntel;
};

export default function InvestigatePage() {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Analysis | null>(null);
  const [shareWithThreatIntel, setShareWithThreatIntel] = useState(false);
  const [shareIpWithThreatIntel, setShareIpWithThreatIntel] = useState(false);

  async function run() {
    const trimmed = input.trim();
    setError('');
    setResult(null);
    if (!trimmed) {
      setError('Add a suspicious URL or message before starting the analysis.');
      return;
    }

    setBusy(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ input: trimmed, shareWithThreatIntel, shareIpWithThreatIntel }),
      });
      const data: unknown = (response.headers.get('content-type') || '').includes('application/json')
        ? await response.json()
        : null;

      if (!response.ok) {
        const message = data && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
          ? data.error
          : response.status === 429
            ? 'Too many requests. Wait a minute and retry.'
            : response.status >= 500
              ? 'The analysis service is temporarily unavailable. Please retry.'
              : 'Analysis failed. Please check your input and retry.';
        throw new Error(message);
      }

      if (!data || typeof data !== 'object') {
        throw new Error('The analysis service returned an unreadable response. Please retry.');
      }
      const candidate = data as Partial<Analysis>;
      if (
        typeof candidate.threat_category !== 'string' ||
        typeof candidate.risk_score !== 'number' ||
        typeof candidate.summary !== 'string' ||
        !Array.isArray(candidate.key_indicators) ||
        !Array.isArray(candidate.recommendations) ||
        !Array.isArray(candidate.limitations) ||
        !Array.isArray(candidate.deterministic_signals) ||
        typeof candidate.model !== 'string' ||
        typeof candidate.notice !== 'string' ||
        (candidate.threat_intel !== undefined && (!candidate.threat_intel || typeof candidate.threat_intel !== 'object' || typeof candidate.threat_intel.status !== 'string' || typeof candidate.threat_intel.detail !== 'string')) ||
        (candidate.ip_threat_intel !== undefined && (!candidate.ip_threat_intel || typeof candidate.ip_threat_intel !== 'object' || typeof candidate.ip_threat_intel.status !== 'string' || typeof candidate.ip_threat_intel.detail !== 'string'))
      ) {
        throw new Error('The analysis service returned an incomplete result. Please retry.');
      }
      setResult(candidate as Analysis);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not complete analysis.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">WORKSPACE / INVESTIGATE</div>
        <h1>Start with the evidence.</h1>
        <p className="lead">Submit a suspicious message or URL as text. SATARK combines AI-assisted triage with basic deterministic signals. It will not visit the URL or execute files.</p>
        <section className="form-panel" aria-labelledby="investigation-title">
          <h2 id="investigation-title">New investigation</h2>
          <p className="field-note">Use content you are permitted to analyze. Never include passwords, OTPs, private keys, or other secrets.</p>
          <label htmlFor="content">Suspicious URL or message</label>
          <textarea id="content" value={input} onChange={event => { setInput(event.target.value); setError(''); setResult(null); }}
            maxLength={12000} placeholder="Paste a suspicious URL or message here…" aria-describedby="content-hint" />
          <label className="intel-consent"><input type="checkbox" checked={shareWithThreatIntel} onChange={event => setShareWithThreatIntel(event.target.checked)} /> Also check the extracted URL against URLhaus. If enabled on the server, the full extracted URL—including path and query string—is shared with this external service. Do not submit private or signed URLs. This is optional.</label>
          <label className="intel-consent"><input type="checkbox" checked={shareIpWithThreatIntel} onChange={event => setShareIpWithThreatIntel(event.target.checked)} /> Also check a literal IP address against AbuseIPDB. If enabled on the server, the extracted IP address is shared with this external service. Domains and arbitrary text are not queried. This is optional.</label>
          <div className="form-bottom">
            <span className="hint" id="content-hint" aria-live="polite">{input.length.toLocaleString()} / 12,000 characters</span>
            <button className="btn btn-primary" onClick={run} disabled={busy || !input.trim()}>
              {busy ? 'Analyzing…' : 'Analyze content →'}
            </button>
          </div>
          {busy && <div className="analysis-progress" aria-label="Analysis in progress"><LatticeLoader status="working" label="Analyzing" pattern="orbit" grid={3} color="#c9f36b" showTimer /><ThoughtLine label="Reviewing submitted content" doneLabel="Analysis complete" steps={["Validating input", "Checking deterministic signals", "Requesting AI-assisted triage"]} working={busy} color="#c9f36b" fontSize={13} shimmer /></div>}
          {error && <div className="result error" role="alert">{error}</div>}
          {result && <section className="analysis-result" aria-live="polite" aria-labelledby="analysis-result-title">
            <div className="result-top">
              <span className="pill">{result.threat_category}</span>
              <strong id="analysis-result-title">Risk signal: {result.risk_score}/100</strong>
            </div>
            <p>{result.summary}</p>
            {result.deterministic_signals.length > 0 && <><h3>Deterministic signals</h3><ul>{result.deterministic_signals.map((item, index) => <li key={index}>{item}</li>)}</ul></>}
            <h3>AI-identified indicators</h3>
            <ul>{result.key_indicators.map((item, index) => <li key={index}>{item}</li>)}</ul>
            <h3>Recommended next steps</h3>
            <ul>{result.recommendations.map((item, index) => <li key={index}>{item}</li>)}</ul>
            {result.limitations.length > 0 && <><h3>Limitations</h3><ul>{result.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></>}
            {result.threat_intel && <div className="threat-intel-result"><h3>URL reputation · {result.threat_intel.source}</h3><p><strong>{result.threat_intel.status.replaceAll('_', ' ')}</strong> — {result.threat_intel.detail}</p>{result.threat_intel.reference && <a href={result.threat_intel.reference} target="_blank" rel="noreferrer">Open URLhaus reference ↗</a>}</div>}
            {result.ip_threat_intel && <div className="threat-intel-result"><h3>IP reputation · {result.ip_threat_intel.source}</h3><p><strong>{result.ip_threat_intel.status.replaceAll('_', ' ')}</strong> — {result.ip_threat_intel.detail}</p>{result.ip_threat_intel.reference && <a href={result.ip_threat_intel.reference} target="_blank" rel="noreferrer">Open AbuseIPDB reference ↗</a>}</div>}
            <p className="hint">{result.notice} · Model: {result.model}</p>
          </section>}
        </section>
        <div className="notice-panel"><strong>How to read the result</strong><p>A risk score is a triage signal, not proof that content is malicious or safe. Verify important claims through a trusted channel you open independently.</p></div>
      </div>
    </main>
  );
}
