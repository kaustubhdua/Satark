'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import SiteHeader from '../site-header';
import LearnTabs from '../learn-tabs';
import { HIGH_PRIORITY_THRESHOLD, SESSION_LOG_KEY, parseLog, summarize, summaryText } from '../../lib/session-log.mjs';
import type { SessionEntry } from '../../lib/session-log.mjs';

export default function ClassroomPage() {
  const [entries, setEntries] = useState<SessionEntry[] | null>(null);
  const [exportNote, setExportNote] = useState('');

  useEffect(() => {
    try { setEntries(parseLog(window.sessionStorage.getItem(SESSION_LOG_KEY))); } catch { setEntries([]); }
  }, []);

  const summary = summarize(entries ?? []);
  const maxCount = Math.max(1, ...summary.patterns.map((pattern) => pattern.count));

  const exportSummary = () => {
    const blob = new Blob([summaryText(entries ?? [])], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = 'SATARK_classroom_session.txt';
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    setExportNote('Session summary downloaded. It contains counts only, no analysed content.');
  };

  const clearSession = () => {
    try { window.sessionStorage.removeItem(SESSION_LOG_KEY); } catch { /* storage may be blocked */ }
    setEntries([]); setExportNote('Session summary cleared.');
  };

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <LearnTabs current="/classroom" />
        <div className="eyebrow">Classroom</div>
        <h1>Teach from a live session.</h1>
        <p className="lead">A teaching summary of the analyses run in this browser tab. It records only the threat category, the heuristic priority score and the time. Analysed text and links are never stored, and nothing is saved as a student record. Closing the tab clears it.</p>

        {entries === null ? <p role="status" className="hint">Loading session…</p> : (<>
          <dl className="sc-stats" aria-label="Session totals">
            <div><dt>Analyses this session</dt><dd>{summary.total}</dd></div>
            <div><dt>Average priority</dt><dd>{summary.average}/100</dd></div>
            <div><dt>High priority (≥ {HIGH_PRIORITY_THRESHOLD})</dt><dd>{summary.highPriority}</dd></div>
          </dl>

          <section className="form-panel" aria-labelledby="patterns-title">
            <h2 id="patterns-title">Session patterns</h2>
            {summary.patterns.length === 0
              ? <p className="notice-panel">No analyses yet. Run a few in the analyzer and they will appear here, ready to discuss.</p>
              : <ul className="class-patterns">{summary.patterns.map(({ category, count }) => (
                  <li key={category}>
                    <span className="class-pattern-name">{category}</span>
                    <span className="class-pattern-bar" aria-hidden="true"><span style={{ width: `${(count / maxCount) * 100}%` }} /></span>
                    <span className="class-pattern-count">{count} {count === 1 ? 'analysis' : 'analyses'}</span>
                  </li>))}</ul>}
          </section>

          <section className="form-panel" aria-labelledby="flow-title">
            <h2 id="flow-title">Teaching flow</h2>
            <ol className="class-flow">
              <li>Present the suspicious content.</li>
              <li>Ask learners to name the evidence they notice.</li>
              <li>Run it through SATARK.</li>
              <li>Compare the learners&apos; reasoning with the signals found.</li>
              <li>Practice the pattern in Scam Challenge.</li>
            </ol>
            <p className="hint">Priority scores are triage signals, not verdicts. A low score never proves a message is safe.</p>
          </section>

          <div className="button-row">
            <button type="button" className="btn btn-primary" onClick={exportSummary} disabled={summary.total === 0}>Export session summary</button>
            <button type="button" className="btn btn-secondary" onClick={clearSession} disabled={summary.total === 0}>Clear session</button>
            <Link className="btn btn-ghost" href="/investigate">Open the analyzer</Link>
            <Link className="btn btn-ghost" href="/challenge">Scam Challenge</Link>
          </div>
          <div className="hint" role="status" aria-live="polite">{exportNote}</div>
        </>)}
      </div>
    </main>
  );
}
