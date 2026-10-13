'use client';

import SiteHeader from '../site-header';
import { useEffect, useState } from 'react';
import PersistentReports from './persistent-reports';

const LAST_ANALYSIS_KEY = 'satark:last-analysis:v1';

type SavedAnalysis = {
  schema_version: 1;
  created_at: string;
  analysis: {
    threat_category: string; risk_score: number; summary: string;
    key_indicators: string[]; recommendations: string[];
    deterministic_signals: string[]; limitations: string[]; model: string; notice: string;
    threat_intel?: { status: string; source: string; detail: string };
    ip_threat_intel?: { status: string; source: string; detail: string };
  };
};

function isSavedAnalysis(value: unknown): value is SavedAnalysis {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<SavedAnalysis>;
  const analysis = candidate.analysis;
  return candidate.schema_version === 1 && typeof candidate.created_at === 'string' &&
    !!analysis && typeof analysis === 'object' &&
    typeof analysis.threat_category === 'string' && typeof analysis.risk_score === 'number' &&
    typeof analysis.summary === 'string' && Array.isArray(analysis.key_indicators) &&
    Array.isArray(analysis.recommendations) && Array.isArray(analysis.deterministic_signals) &&
    Array.isArray(analysis.limitations) && typeof analysis.model === 'string' &&
    typeof analysis.notice === 'string';
}

export default function ReportsPage() {
  const [report, setReport] = useState('');
  const [exported, setExported] = useState(false);
  const [savedAnalysis, setSavedAnalysis] = useState<SavedAnalysis | null>(null);

  useEffect(() => {
    try {
      const raw = window.sessionStorage.getItem(LAST_ANALYSIS_KEY);
      if (!raw) return;
      const parsed: unknown = JSON.parse(raw);
      if (isSavedAnalysis(parsed)) setSavedAnalysis(parsed);
    } catch {
      setSavedAnalysis(null);
    }
  }, []);

  function clearSavedAnalysis() {
    try { window.sessionStorage.removeItem(LAST_ANALYSIS_KEY); } catch {}
    setSavedAnalysis(null);
    setExported(false);
  }

  function saveFile(filename: string, content: string, type: string) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    setExported(true);
  }

  function download() {
    const notes = report.trim();
    if (!notes && !savedAnalysis) return;
    const analysis = savedAnalysis?.analysis;
    const analysisText = analysis ? [
      '',
      '--- SATARK analysis snapshot (session-only) ---',
      'Created: ' + savedAnalysis.created_at,
      'Category: ' + analysis.threat_category,
      'Risk signal: ' + analysis.risk_score + '/100',
      'Summary: ' + analysis.summary,
      'Deterministic signals: ' + (analysis.deterministic_signals.join('; ') || 'None reported'),
      'Indicators: ' + (analysis.key_indicators.join('; ') || 'None reported'),
      'Recommendations: ' + (analysis.recommendations.join('; ') || 'None reported'),
      'Limitations: ' + (analysis.limitations.join('; ') || 'See analysis notice'),
      'Model: ' + analysis.model,
      'Notice: ' + analysis.notice,
      'External reputation lookups are observations, not proof of safety.',
    ].join('\n') : '';
    saveFile('satark-review-notes.txt', notes + analysisText + '\n', 'text/plain;charset=utf-8');
  }

  function downloadJson() {
    const notes = report.trim();
    if (!notes && !savedAnalysis) return;
    const exportedAt = new Date().toISOString();
    saveFile('satark-review-notes.json', JSON.stringify({
      schema_version: 1,
      exported_at: exportedAt,
      report_type: 'review-notes-with-optional-session-analysis',
      notes,
      analysis_snapshot: savedAnalysis,
      provenance: {
        analysis_included: !!savedAnalysis,
        analysis_source: savedAnalysis ? 'last successful analysis in this browser tab session' : 'none',
        submitted_source_text_saved: false,
        persistent_server_history: false,
      },
      limitations: ['The analysis snapshot is a triage result, not independently verified evidence.', 'Only the last successful analysis available in this tab session is included.', 'The original submitted source text is not saved in this snapshot.', 'This export is not a certified forensic report or a verified chain-of-custody record.'],
    }, null, 2) + '\n', 'application/json;charset=utf-8');
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">WORKSPACE / REPORTS</div>
        <h1>Keep the reasoning reviewable.</h1>
        <p className="lead">Draft and export review notes locally, or save an immutable report snapshot against a persistent case when signed in.</p>
        <section className="form-panel" aria-labelledby="notes-title">
          <h2 id="notes-title">Investigation notes</h2>
          <p className="field-note">Record observable facts, evidence references, unresolved questions, and your next steps. Reports remain local to this browser session unless you export them.</p>
          <div className="notice-panel" aria-live="polite">
            <strong>Latest session analysis</strong>
            {savedAnalysis ? <>
              <p>{savedAnalysis.analysis.threat_category} · Risk signal {savedAnalysis.analysis.risk_score}/100</p>
              <p>{savedAnalysis.analysis.summary}</p>
              <p className="hint">Captured {new Date(savedAnalysis.created_at).toLocaleString()}. The submitted source text is not stored in the report snapshot.</p>
              <button className="btn btn-secondary" type="button" onClick={clearSavedAnalysis}>Remove session analysis</button>
            </> : <p>No successful analysis is available in this browser tab. Run an analysis first to include its findings in exports.</p>}
          </div>
          <label htmlFor="notes">Review notes</label>
          <textarea id="notes" value={report} onChange={event => { setReport(event.target.value); setExported(false); }}
            maxLength={20000} placeholder="Example: Sender display name differs from the actual address. Verify through the official channel…"
            aria-describedby="notes-hint" />
          <div className="form-bottom">
            <span className="hint" id="notes-hint" aria-live="polite">{report.length.toLocaleString()} / 20,000 characters</span>
            <div className="button-row">
              <button className="btn btn-secondary" type="button" disabled={!report} onClick={() => { setReport(''); setExported(false); }}>Clear notes</button>
              <button className="btn btn-primary" type="button" disabled={!report.trim() && !savedAnalysis} onClick={download}>Export notes (.txt) ↓</button>
              <button className="btn btn-secondary" type="button" disabled={!report.trim() && !savedAnalysis} onClick={downloadJson}>Export notes (.json) ↓</button>
            </div>
          </div>
          <p className="export-feedback" role="status" aria-live="polite">{exported ? 'Your notes were sent to the browser download manager.' : ''}</p>
        </section>
        <PersistentReports notes={report} analysis={savedAnalysis} />
        <div className="notice-panel"><strong>Report boundary</strong><p>Local exports include notes and, when available, the last successful analysis snapshot from this browser tab. Persistent reports are immutable snapshots attached to a case and have a server-calculated digest. Neither type is a certified forensic report or proof of source authenticity.</p></div>
      </div>
    </main>
  );
}
