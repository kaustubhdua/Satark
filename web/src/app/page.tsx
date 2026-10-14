'use client';

import SiteHeader from './site-header';
import { Radar, SplitFlapText } from '../components/react-bits';
import ServiceReadiness from '../components/service-readiness';

import { useState } from 'react';

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
  threat_intel?: { status: string; source: string; detail: string; reference?: string };
  ip_threat_intel?: { status: string; source: string; detail: string; reference?: string };
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

export default function Home() {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Analysis | null>(null);

  async function analyze() {
    setError('');
    setResult(null);
    if (!input.trim()) {
      setError('Add a URL or suspicious message to begin.');
      return;
    }
    setBusy(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ input: input.trim() })
      });
      const contentType = response.headers.get('content-type') || '';
      const data: unknown = contentType.includes('application/json')
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
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not complete analysis.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <SiteHeader status />

      <div className="container" id="main-content" tabIndex={-1}>
        <ServiceReadiness />
        <section className="hero">
          <div>
            <div className="eyebrow">✳ DIGITAL THREAT INVESTIGATION</div>
            <h1>Pause the panic.<br /><span>Find the signal.</span></h1>
            <div className="hero-signal" aria-label="Security workspace status"><SplitFlapText words={['EVIDENCE FIRST', 'SIGNAL DETECTED', 'VERIFY THEN ACT']} fontSize={24} padTo={15} tileColor="#111827" textColor="#c9f36b" gap={3} cycleDelay={3200} /></div>
            <p className="lead">A calmer, evidence-first workspace for investigating suspicious digital content. Understand what was detected, why it matters, and what remains uncertain.</p>
            <div className="actions"><a className="btn btn-primary" href="#investigate">Start an investigation ↗</a><a className="btn btn-secondary" href="/firstlight">Open FIRSTLIGHT →</a></div>
          </div>
          <div className="signal-card">
            <div className="radar-preview"><Radar color="#c9f36b" mode="sweep" speed={0.8} trail={0.3} scale={0.86} ringCount={5} spokeCount={12} targets={5} clutter={0.3} mouseInteraction={false} grain={0.01} /></div>
            <div className="card-head"><span>INVESTIGATION SNAPSHOT</span><span className="pill">SAMPLE DATA</span></div>
            <div className="score-row"><div className="score">3</div><div className="score-meta"><strong>Signal groups in this sample</strong><span>Illustrative training case · not a live scan</span></div></div>
            <div className="evidence-list">
              {[
                ['↗', 'Source context', 'Review origin and destination'],
                ['⌁', 'Evidence integrity', 'Keep findings tied to evidence'],
                ['◷', 'Event timeline', 'Put observations in context']
              ].map(item => <div className="evidence" key={item[1]}><div className="evidence-icon">{item[0]}</div><div className="evidence-copy"><strong>{item[1]}</strong><small>{item[2]}</small></div><span className="check">READY</span></div>)}
            </div>
          </div>
        </section>

        <section>
          <div className="section-title"><div><div className="eyebrow">YOUR WORKSPACE</div><h2>Investigate with context.</h2></div><p>Clear workflows. Evidence before conclusions.</p></div>
          <div className="workspace-grid">
            <article className="workspace-card"><div className="workspace-icon">⌕</div><h3>Investigate content</h3><p>Analyze a suspicious URL or message with local rules and optional self-hosted AI.</p><a className="text-link" href="/investigate">Open investigation →</a></article>
            <article className="workspace-card"><div className="workspace-icon">✳</div><h3>FIRSTLIGHT case lab</h3><p>Explore a guided synthetic case, evidence integrity, timelines and response decisions.</p><a className="text-link" href="/firstlight">Open case lab →</a></article>
            <article className="workspace-card"><div className="workspace-icon">▤</div><h3>Evidence & reports</h3><p>Draft and export your own investigation review notes.</p><a className="text-link" href="/reports">Open reports →</a></article>
            <article className="workspace-card"><div className="workspace-icon">◎</div><h3>Security learning</h3><p>Practice identifying social engineering signals with safe, educational examples.</p><a className="text-link" href="/learn">Open learning hub →</a></article>
          </div>
        </section>

        <section className="tools-section">
          <div className="section-title"><div><div className="eyebrow">SATARK TOOLKIT</div><h2>One workspace. Different kinds of evidence.</h2></div><p>Choose a focused workflow. Unported tools are clearly marked as planned and will not redirect to an unverified legacy deployment.</p></div>
          <details className="tools-disclosure"><summary><span><strong>Browse all eight tools</strong><small>Shows what is available now and what is still being migrated</small></span><span className="disclosure-icon" aria-hidden="true">＋</span></summary><div className="tool-grid">
            {[
              ['01','Text & message triage','Spot pressure tactics, impersonation cues and risky requests.','/investigate','OPEN ANALYSIS'],
              ['02','URL review','Review a URL as text without automatically visiting it.','/investigate','OPEN ANALYSIS'],
              ['03','Image & deepfake review','Local image metadata and content-analysis workflow is not yet migrated.','', 'NOT YET PORTED'],
              ['04','QR-code investigation','Decode QR payloads locally with safe parsing and evidence capture.','', 'NOT YET PORTED'],
              ['05','PDF & document review','Extract text and metadata in a sandboxed local file pipeline.','', 'NOT YET PORTED'],
              ['06','Video & media signals','Media processing and provenance checks are not yet migrated.','', 'NOT YET PORTED'],
              ['07','History & reports','Persistent case history and evidence-linked report exports are in progress.','', 'NOT YET PORTED'],
              ['08','Academy & scam challenge','Practice recognition and awareness workflows.','/learn','OPEN LEARNING']
            ].map(([number,title,description,href,action]) => <article className="tool-card" key={number}><div className="tool-card-top"><span>{number}</span><span className="tool-arrow">↗</span></div><h3>{title}</h3><p>{description}</p>{href ? <a className="text-link" href={href} target={href.startsWith('http')?'_blank':undefined} rel={href.startsWith('http')?'noreferrer':undefined}>{action} →</a> : <span className="text-link" aria-disabled="true">{action}</span>}</article>)}
          </div>
          <div className="tool-boundary"><span>i</span><p><strong>Feature availability:</strong> text/URL triage and the interactive FIRSTLIGHT training workflow run in this Next.js workspace. Image, QR, PDF, video, and durable case-history features are not yet ported to the local-only web app; no external legacy link is presented as a working native feature.</p></div>
          </details>
        </section>

        <section className="investigation" id="investigate">
          <div className="info-panel"><div className="eyebrow">START HERE</div><h3>Inspect before you trust.</h3><p>Submit only content you are permitted to analyze. Do not include passwords, authentication codes, private keys or other secrets.</p><p><strong style={{ color: '#dce6f4' }}>Important:</strong> AI output is an assessment, not proof. The app does not visit submitted URLs or execute files.</p></div>
          <div className="form-panel">
            <h3>New investigation</h3>
            <p className="field-note">Analysis runs with local deterministic rules by default. If you configure your own Ollama instance, the text is sent only to that self-hosted model. No third-party AI or reputation API is called in local-only mode. Never submit passwords, OTPs, private keys or secrets.</p>
            <label htmlFor="content">Suspicious URL or message</label>
            <textarea id="content" value={input} onChange={event => { setInput(event.target.value); setError(''); setResult(null); }} placeholder="Paste a suspicious URL or message here…" maxLength={12000} aria-describedby="content-hint" />
            <div className="form-bottom"><span className="hint" id="content-hint" aria-live="polite">{input.length.toLocaleString()} / 12,000 characters</span><button className="btn btn-primary" disabled={busy || !input.trim()} onClick={analyze}>{busy ? 'Analyzing…' : 'Analyze with SATARK →'}</button></div>
            {error && <div className="result error" role="alert">{error}</div>}
            {result && <div className="analysis-result" role="status">
              <div className="result-top"><span className="pill">{result.threat_category}</span><strong>Heuristic priority: {result.risk_score}/100</strong></div>
              <p>{result.summary}</p><p className="field-note">{result.notice}</p>
              {result.threat_intel && <div className="notice-panel" aria-label="Local threat-intelligence status">
                <h4>Local threat-intelligence cache</h4>
                <p><strong>Status: {result.threat_intel.status.replaceAll('_', ' ')}</strong> — {result.threat_intel.detail}</p>
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
              {result.deterministic_signals.length > 0 && <><h4>Deterministic signals</h4><ul>{result.deterministic_signals.map(signal => <li key={signal}>{signal}</li>)}</ul></>}
              <h4>Indicators and context</h4><ul>{result.key_indicators.map((item, index) => <li key={index}>{item}</li>)}</ul>
              <h4>Recommended next steps</h4><ul>{result.recommendations.map((item, index) => <li key={index}>{item}</li>)}</ul>
              {result.limitations.length > 0 && <><h4>Limitations</h4><ul>{result.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></>}
              <small>{result.notice} · Model: {result.model}</small>
            </div>}
          </div>
        </section>
      </div>
      <footer className="footer"><span>SATARK · Evidence-backed digital security</span><span>AI-assisted triage · Human review required</span></footer>
    </main>
  );
}
