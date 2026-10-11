'use client';

import SiteHeader from '../site-header';
import { useState } from 'react';

export default function ReportsPage() {
  const [report, setReport] = useState('');
  const [exported, setExported] = useState(false);

  function download() {
    const notes = report.trim();
    if (!notes) return;
    const blob = new Blob([notes + '\n'], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'satark-review-notes.txt';
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    setExported(true);
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">WORKSPACE / REPORTS</div>
        <h1>Keep the reasoning reviewable.</h1>
        <p className="lead">Draft and export your own review notes. Analysis results are not automatically saved to a server or shared across sessions.</p>
        <section className="form-panel" aria-labelledby="notes-title">
          <h2 id="notes-title">Investigation notes</h2>
          <p className="field-note">Record observable facts, evidence references, unresolved questions, and your next steps.</p>
          <label htmlFor="notes">Review notes</label>
          <textarea id="notes" value={report} onChange={event => { setReport(event.target.value); setExported(false); }}
            maxLength={20000} placeholder="Example: Sender display name differs from the actual address. Verify through the official channel…"
            aria-describedby="notes-hint" />
          <div className="form-bottom">
            <span className="hint" id="notes-hint" aria-live="polite">{report.length.toLocaleString()} / 20,000 characters</span>
            <div className="button-row">
              <button className="btn btn-secondary" type="button" disabled={!report} onClick={() => { setReport(''); setExported(false); }}>Clear notes</button>
              <button className="btn btn-primary" type="button" disabled={!report.trim()} onClick={download}>Export notes (.txt) ↓</button>
            </div>
          </div>
          <p className="export-feedback" role="status" aria-live="polite">{exported ? 'Your notes were sent to the browser download manager.' : ''}</p>
        </section>
        <div className="notice-panel"><strong>Report boundary</strong><p>This exports only the notes you enter here, not a certified forensic report. Verify evidence independently and record the limits of your review. Notes are held in page memory and are not uploaded; export them before leaving.</p></div>
      </div>
    </main>
  );
}
