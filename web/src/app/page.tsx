'use client';

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
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Analysis failed. Please retry.');
      setResult(data as Analysis);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not complete analysis.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="/"><span className="brand-mark">S</span><span>SATARK<span style={{ color: 'var(--lime)' }}>.</span></span></a>
        <nav className="nav-links" aria-label="Main navigation">
          <a href="/investigate">Investigate</a><a href="/firstlight">FIRSTLIGHT</a><a href="/reports">Reports</a><a href="/learn">Learn</a>
        </nav>
        <div className="status">● SECURITY WORKSPACE</div>
      </header>

      <div className="container">
        <section className="hero">
          <div>
            <div className="eyebrow">✳ DIGITAL THREAT INVESTIGATION</div>
            <h1>Pause the panic.<br /><span>Find the signal.</span></h1>
            <p className="lead">A calmer, evidence-first workspace for investigating suspicious digital content. Understand what was detected, why it matters, and what remains uncertain.</p>
            <div className="actions"><a className="btn btn-primary" href="#investigate">Start an investigation ↗</a><a className="btn btn-secondary" href="/firstlight">Open FIRSTLIGHT →</a></div>
          </div>
          <div className="signal-card">
            <div className="card-head"><span>INVESTIGATION SNAPSHOT</span><span className="pill">SAMPLE DATA</span></div>
            <div className="score-row"><div className="score">4/5</div><div className="score-meta"><strong>Evidence signals reviewed</strong><span>Illustrative training case · not a live scan</span></div></div>
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
            <article className="workspace-card"><div className="workspace-icon">⌕</div><h3>Investigate content</h3><p>Analyze a suspicious URL or message with AI-assisted triage and deterministic signals.</p><a className="text-link" href="/investigate">Open investigation →</a></article>
            <article className="workspace-card"><div className="workspace-icon">✳</div><h3>FIRSTLIGHT case lab</h3><p>Explore a guided synthetic case, evidence integrity, timelines and response decisions.</p><a className="text-link" href="/firstlight">Open case lab →</a></article>
            <article className="workspace-card"><div className="workspace-icon">▤</div><h3>Evidence & reports</h3><p>Review analysis results and export a report from your current session.</p><a className="text-link" href="/reports">Open reports →</a></article>
            <article className="workspace-card"><div className="workspace-icon">◎</div><h3>Security learning</h3><p>Practice identifying social engineering signals with safe, educational examples.</p><a className="text-link" href="/learn">Open learning hub →</a></article>
          </div>
        </section>

        <section className="tools-section">
          <div className="section-title"><div><div className="eyebrow">SATARK TOOLKIT</div><h2>One workspace. Different kinds of evidence.</h2></div><p>Choose a focused workflow. Tools that are not yet ported into Next.js open the existing full SATARK application.</p></div>
          <div className="tool-grid">
            {[
              ['01','Text & message triage','Spot pressure tactics, impersonation cues and risky requests.','/investigate','OPEN ANALYSIS'],
              ['02','URL review','Review a URL as text without automatically visiting it.','/investigate','OPEN ANALYSIS'],
              ['03','Image & deepfake review','Image authenticity and visual-content analysis in the full app.','https://satark-32uppvjxwmderrchbhj7gj.streamlit.app/','OPEN FULL APP'],
              ['04','QR-code investigation','Inspect suspicious QR content using the existing scanner.','https://satark-32uppvjxwmderrchbhj7gj.streamlit.app/','OPEN FULL APP'],
              ['05','PDF & document review','Review document content with the full SATARK scanner.','https://satark-32uppvjxwmderrchbhj7gj.streamlit.app/','OPEN FULL APP'],
              ['06','Video & media signals','Explore available video and media workflows in the full app.','https://satark-32uppvjxwmderrchbhj7gj.streamlit.app/','OPEN FULL APP'],
              ['07','History & reports','Review the full app’s session history and export options.','https://satark-32uppvjxwmderrchbhj7gj.streamlit.app/','OPEN FULL APP'],
              ['08','Academy & scam challenge','Practice recognition and awareness workflows.','/learn','OPEN LEARNING']
            ].map(([number,title,description,href,action]) => <article className="tool-card" key={number}><div className="tool-card-top"><span>{number}</span><span className="tool-arrow">↗</span></div><h3>{title}</h3><p>{description}</p><a className="text-link" href={href} target={href.startsWith('http')?'_blank':undefined} rel={href.startsWith('http')?'noreferrer':undefined}>{action} →</a></article>)}
          </div>
          <div className="tool-boundary"><span>i</span><p><strong>Feature availability:</strong> text/URL triage and the interactive FIRSTLIGHT training workflow run in this Next.js workspace. The image, QR, PDF, video, and extended history tools still run in the existing Streamlit application; they are linked here rather than falsely presented as native Next.js features.</p></div>
        </section>

        <section className="investigation" id="investigate">
          <aside className="info-panel"><div className="eyebrow">START HERE</div><h3>Inspect before you trust.</h3><p>Submit only content you are permitted to analyze. Do not include passwords, authentication codes, private keys or other secrets.</p><p><strong style={{ color: '#dce6f4' }}>Important:</strong> AI output is an assessment, not proof. The app does not visit submitted URLs or execute files.</p></aside>
          <div className="form-panel">
            <h3>New investigation</h3>
            <label htmlFor="content">Suspicious URL or message</label>
            <textarea id="content" value={input} onChange={event => setInput(event.target.value)} placeholder="Paste a suspicious URL or message here…" maxLength={12000} />
            <div className="form-bottom"><span className="hint">{input.length.toLocaleString()} / 12,000 characters</span><button className="btn btn-primary" disabled={busy} onClick={analyze}>{busy ? 'Analyzing…' : 'Analyze with SATARK →'}</button></div>
            {error && <div className="result error" role="alert">{error}</div>}
            {result && <div className="analysis-result" role="status">
              <div className="result-top"><span className="pill">{result.threat_category}</span><strong>Risk signal: {result.risk_score}/100</strong></div>
              <p>{result.summary}</p>
              {result.deterministic_signals.length > 0 && <><h4>Deterministic signals</h4><ul>{result.deterministic_signals.map(signal => <li key={signal}>{signal}</li>)}</ul></>}
              <h4>AI-identified indicators</h4><ul>{result.key_indicators.map((item, index) => <li key={index}>{item}</li>)}</ul>
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
