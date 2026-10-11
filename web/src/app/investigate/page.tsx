'use client';

import { useState } from 'react';

export default function InvestigatePage() {
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<any>(null);
  async function run() {
    setBusy(true); setError(''); setResult(null);
    try {
      const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ input }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Analysis failed.');
      setResult(data);
    } catch (e) { setError(e instanceof Error ? e.message : 'Analysis failed.'); }
    finally { setBusy(false); }
  }
  return <main className="shell"><header className="topbar"><a className="brand" href="/"><span className="brand-mark">S</span>SATARK<span style={{color:'var(--lime)'}}>.</span></a><nav className="nav-links"><a href="/investigate">Investigate</a><a href="/firstlight">FIRSTLIGHT</a><a href="/reports">Reports</a><a href="/learn">Learn</a></nav></header><div className="container subpage"><div className="eyebrow">WORKSPACE / INVESTIGATE</div><h1>Start with the evidence.</h1><p className="lead">Submit a suspicious message or URL as text. SATARK will combine AI-assisted triage with basic deterministic signals. It will not visit the URL or execute files.</p><section className="form-panel"><label htmlFor="content">Suspicious URL or message</label><textarea id="content" value={input} onChange={e=>setInput(e.target.value)} maxLength={12000} placeholder="Paste content here. Never include passwords, OTPs, or secrets."/><div className="form-bottom"><span className="hint">{input.length.toLocaleString()} / 12,000 characters</span><button className="btn btn-primary" onClick={run} disabled={busy}>{busy?'Analyzing…':'Analyze content →'}</button></div>{error&&<div className="result error" role="alert">{error}</div>}{result&&<div className="analysis-result"><div className="result-top"><span className="pill">{result.threat_category}</span><strong>Risk signal: {result.risk_score}/100</strong></div><p>{result.summary}</p><h4>Indicators</h4><ul>{result.key_indicators.map((x:string,i:number)=><li key={i}>{x}</li>)}</ul><h4>Recommendations</h4><ul>{result.recommendations.map((x:string,i:number)=><li key={i}>{x}</li>)}</ul><h4>Deterministic signals</h4><ul>{result.deterministic_signals.map((x:string,i:number)=><li key={i}>{x}</li>)}</ul><p className="hint">{result.notice}</p></div>}</section></div></main>;
}