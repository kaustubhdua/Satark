'use client';

import SiteHeader from '../site-header';

import { useState } from 'react';
export default function ReportsPage() {
  const [report,setReport] = useState('');
  function download() { if (!report.trim()) return; const blob = new Blob([report], {type:'text/plain;charset=utf-8'}); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href=url; a.download='satark-review-notes.txt'; a.click(); URL.revokeObjectURL(url); }
  return <main className="shell"><SiteHeader /><div className="container subpage" id="main-content" tabIndex={-1}><div className="eyebrow">WORKSPACE / REPORTS</div><h1>Keep the reasoning reviewable.</h1><p className="lead">Draft and export your own review notes. AI analysis results are not automatically saved to a server or shared across sessions.</p><section className="form-panel"><label htmlFor="notes">Investigation notes</label><textarea id="notes" value={report} onChange={e=>setReport(e.target.value)} maxLength={20000} placeholder="Record observed facts, evidence references, unresolved questions, and your next steps…"/><div className="form-bottom"><span className="hint">{report.length.toLocaleString()} / 20,000 characters</span><button className="btn btn-primary" disabled={!report.trim()} onClick={download}>Export notes (.txt) ↓</button></div></section><div className="notice-panel"><strong>Report boundary</strong><p>This exports notes you enter here, not a certified forensic report. Verify evidence independently and record the limits of your review.</p></div></div></main>;
}