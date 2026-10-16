'use client';

import SiteHeader from '../site-header';
import { LatticeLoader, ThoughtLine } from '../../components/react-bits';
import ServiceReadiness from '../../components/service-readiness';
import { useState } from 'react';

const LAST_ANALYSIS_KEY = 'satark:last-analysis:v1';

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
  model_suggestions?: {
    summary: string;
    key_indicators: string[];
    recommendations: string[];
    verification_status: 'unverified';
    model: string;
  };
  threat_intel?: ThreatIntel;
  ip_threat_intel?: ThreatIntel;
  local_ioc_cache?: {
    status: string;
    fresh_sources: number;
    stale_sources: number;
    matches: Array<{
      type: string;
      evidence: string;
      source: string;
      source_id: string;
      source_url: string;
      source_license: string;
      source_version: string;
      last_successful_sync: string;
    }>;
  };
};

export default function InvestigatePage() {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Analysis | null>(null);

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
        body: JSON.stringify({ input: trimmed }),
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
        (candidate.model_suggestions !== undefined && (!candidate.model_suggestions || typeof candidate.model_suggestions !== 'object' || typeof candidate.model_suggestions.summary !== 'string' || !Array.isArray(candidate.model_suggestions.key_indicators) || !Array.isArray(candidate.model_suggestions.recommendations) || candidate.model_suggestions.verification_status !== 'unverified' || typeof candidate.model_suggestions.model !== 'string')) ||
        (candidate.threat_intel !== undefined && (!candidate.threat_intel || typeof candidate.threat_intel !== 'object' || typeof candidate.threat_intel.status !== 'string' || typeof candidate.threat_intel.detail !== 'string')) ||
        (candidate.ip_threat_intel !== undefined && (!candidate.ip_threat_intel || typeof candidate.ip_threat_intel !== 'object' || typeof candidate.ip_threat_intel.status !== 'string' || typeof candidate.ip_threat_intel.detail !== 'string'))
      ) {
        throw new Error('The analysis service returned an incomplete result. Please retry.');
      }
      const verifiedResult = candidate as Analysis;
      setResult(verifiedResult);
      // Session-only snapshot: never persist the submitted source text.
      try {
        window.sessionStorage.setItem(LAST_ANALYSIS_KEY, JSON.stringify({
          schema_version: 1,
          created_at: new Date().toISOString(),
          // Keep model-generated suggestions out of the session snapshot.
          analysis: { ...verifiedResult, model_suggestions: undefined },
        }));
      } catch {
        // Keep the analysis usable if browser storage is blocked or full.
      }
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
        <ServiceReadiness />
        <div className="eyebrow">WORKSPACE / INVESTIGATE</div>
        <h1>Start with the evidence.</h1>
        <p className="lead">Submit a suspicious message or URL as text. SATARK runs local deterministic checks and can use an optional self-hosted Ollama model. It will not visit the URL or execute files.</p>
        <section className="form-panel" aria-labelledby="investigation-title">
          <h2 id="investigation-title">New investigation</h2>
          <p className="field-note">Local deterministic checks by default; no third-party AI key is required. If you configure your own Ollama instance, the submitted text is sent only to that self-hosted model. No third-party AI or reputation API is called in local-only mode. Never submit passwords, OTPs, private keys, or secrets.</p>
          <label htmlFor="content">Suspicious URL or message</label>
          <textarea id="content" value={input} onChange={event => { setInput(event.target.value); setError(''); setResult(null); }}
            maxLength={12000} placeholder="Paste a suspicious URL or message here…" aria-describedby="content-hint" />
          <div className="form-bottom">
            <span className="hint" id="content-hint" aria-live="polite">{input.length.toLocaleString()} / 12,000 characters</span>
            <div className="form-actions">
              <button type="button" className="btn btn-secondary" onClick={() => { setInput(''); setError(''); setResult(null); }} disabled={busy || !input}>
                Clear
              </button>
              <button type="button" className="btn btn-primary" onClick={run} disabled={busy || !input.trim()}>
                {busy ? 'Analyzing…' : 'Analyze content →'}
              </button>
            </div>
          </div>
          {busy && <div className="analysis-progress" aria-label="Analysis in progress"><LatticeLoader status="working" label="Analyzing" pattern="orbit" grid={3} color="#c9f36b" showTimer /><ThoughtLine label="Reviewing submitted content" doneLabel="Analysis complete" steps={["Validating input", "Checking local rules", "Using self-hosted model if configured"]} working={busy} color="#c9f36b" fontSize={13} shimmer /></div>}
          {error && <div className="result error" role="alert">{error}</div>}
          {result && <section className="analysis-result" aria-live="polite" aria-labelledby="analysis-result-title">
            <div className="result-top">
              <span className="pill">{result.threat_category}</span>
              <strong id="analysis-result-title">Heuristic priority: {result.risk_score}/100</strong>
            </div>
            <div className="risk-meter-panel" aria-label="Heuristic priority visualization">
              <div className="risk-meter-labels"><span>Priority signal</span><span>{result.risk_score} / 100</span></div>
              <div className="risk-meter-track" role="meter" aria-label="Heuristic priority score" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.max(0, Math.min(100, result.risk_score))}>
                <span className="risk-meter-fill" style={{ width: Math.max(0, Math.min(100, result.risk_score)) + '%' }} />
              </div>
              <div className="risk-meter-scale"><span>Lower signal</span><span>Higher signal</span></div>
              <p className="field-note">This is a heuristic triage score, not a probability or a verdict.</p>
            </div>
            <p>{result.summary}</p><p className="field-note">{result.notice}</p>
            {result.model_suggestions && <div className="notice-panel" aria-label="Unverified local-model suggestions">
              <h3>Unverified local-model suggestions</h3>
              <p>These suggestions are generated by an optional self-hosted model and are not verified findings. Deterministic signals, the summary and recommended next steps remain authoritative.</p>
              <p>{result.model_suggestions.summary}</p>
              {result.model_suggestions.key_indicators.length > 0 && <ul>{result.model_suggestions.key_indicators.map((item, index) => <li key={'model-indicator-' + index}>{item}</li>)}</ul>}
              {result.model_suggestions.recommendations.length > 0 && <ul>{result.model_suggestions.recommendations.map((item, index) => <li key={'model-recommendation-' + index}>{item}</li>)}</ul>}
              <p className="hint">Source: {result.model_suggestions.model} · Status: unverified</p>
            </div>}
            {result.threat_intel && <div className="notice-panel" aria-label="Local threat-intelligence status">
              <h3>Local threat-intelligence cache</h3>
              <p><strong>Status: {result.threat_intel.status.replace(/_/g, ' ')}</strong> — {result.threat_intel.detail}</p>
              {result.local_ioc_cache && <p className="hint">{result.local_ioc_cache.fresh_sources} fresh source(s) · {result.local_ioc_cache.stale_sources} stale source(s)</p>}
              {result.local_ioc_cache?.matches.map((match, index) => <div className="evidence" key={match.source_id + ':' + match.type + ':' + index}>
                <div className="evidence-icon" aria-hidden="true">!</div>
                <div className="evidence-copy">
                  <strong>{match.source} · {match.type} match</strong>
                  <small>Indicator: {match.evidence} · Version: {match.source_version} · Last sync: {match.last_successful_sync}</small>
                  <small>License: {match.source_license} · Source: {match.source_url}</small>
                </div>
              </div>)}
            </div>}
            <h3>Deterministic signals</h3>
            {result.deterministic_signals.length > 0
              ? <ul>{result.deterministic_signals.map((item, index) => <li key={index}>{item}</li>)}</ul>
              : <div className="analysis-empty-state"><strong>No deterministic signals triggered</strong><p>The current checks did not flag a specific rule. This does not mean the content is safe.</p></div>}
            <h3>Indicators and context</h3>
            {result.key_indicators.length > 0
              ? <ul>{result.key_indicators.map((item, index) => <li key={index}>{item}</li>)}</ul>
              : <p className="field-note">No additional indicators were returned for this analysis.</p>}
            <h3>Recommended next steps</h3>
            {result.recommendations.length > 0
              ? <ul>{result.recommendations.map((item, index) => <li key={index}>{item}</li>)}</ul>
              : <p className="field-note">No automated next steps were returned. Verify the source independently before acting.</p>}
            {result.limitations.length > 0 && <><h3>Limitations</h3><ul>{result.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></>}
            <p className="hint">{result.notice} · Model: {result.model}</p>
          </section>}
        </section>
        <div className="notice-panel"><strong>How to read the result</strong><p>A risk score is a triage signal, not proof that content is malicious or safe. Verify important claims through a trusted channel you open independently.</p></div>
      </div>
    </main>
  );
}
