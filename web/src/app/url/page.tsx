'use client';

import { useState } from 'react';
import Link from 'next/link';
import SiteHeader from '../site-header';
import { inspectUrl } from '../../lib/url-inspection.mjs';

type UrlResult = {
  ok: true;
  normalized: string;
  hostname: string;
  protocol: string;
  path: string;
  queryParameterNames: string[];
  hasFragment: boolean;
  findings: Array<{ severity: string; title: string; detail: string }>;
  summary: string;
  notice: string;
} | { ok: false; error: string };

export default function UrlReviewPage() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<UrlResult | null>(null);

  function inspect() {
    setResult(inspectUrl(input) as UrlResult);
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">WORKSPACE / URL INSPECTION</div>
        <h1>Inspect the link. Don’t visit it.</h1>
        <p className="lead">Review URL structure locally before deciding what to do next. SATARK never fetches the destination from this page.</p>
        <section className="form-panel" aria-labelledby="url-inspect-heading">
          <h2 id="url-inspect-heading">URL structure review</h2>
          <p className="field-note">Paste a link or hostname. Inspection runs in this browser using format-based heuristics only. If you omit the scheme, the input is interpreted as HTTPS.</p>
          <label className="field-label" htmlFor="url-input">URL or hostname</label>
          <textarea id="url-input" value={input} onChange={event => { setInput(event.target.value); setResult(null); }}
            maxLength={4096} rows={3} placeholder="https://example.com/account/verify" />
          <div className="actions">
            <button className="btn btn-primary" type="button" disabled={!input.trim()} onClick={inspect}>Inspect URL locally</button>
            <button className="btn btn-secondary" type="button" disabled={!input} onClick={() => { setInput(''); setResult(null); }}>Clear</button>
          </div>
          {result && !result.ok && <p className="error-message" role="alert">{result.error}</p>}
          {result?.ok && (
            <section className="notice-panel" aria-labelledby="url-result-heading" aria-live="polite">
              <div className="eyebrow">OBSERVATIONS · NOT A VERDICT</div>
              <h3 id="url-result-heading">{result.summary}</h3>
              <dl className="detail-list">
                <div><dt>Hostname</dt><dd>{result.hostname}</dd></div>
                <div><dt>Scheme</dt><dd>{result.protocol}</dd></div>
                <div><dt>Path</dt><dd>{result.path}</dd></div>
                <div><dt>Query keys</dt><dd>{result.queryParameterNames.length ? result.queryParameterNames.join(', ') : 'None'}</dd></div>
                <div><dt>Fragment present</dt><dd>{result.hasFragment ? 'Yes' : 'No'}</dd></div>
              </dl>
              <p><strong>Normalized display:</strong> <code>{result.normalized}</code></p>
              {result.findings.length ? (
                <ul className="result-list">
                  {result.findings.map((finding, index) => <li key={finding.title + index}>
                    <strong>{finding.title}</strong> <span className="pill">{finding.severity.toUpperCase()}</span>
                    <p>{finding.detail}</p>
                  </li>)}
                </ul>
              ) : <p>No configured format-based cues were found.</p>}
              <p className="muted">{result.notice}</p>
            </section>
          )}
        </section>
        <section className="panel">
          <h2>Next steps</h2>
          <ul>
            <li>Check the registered domain, spelling and destination through a trusted independent channel.</li>
            <li>Never enter passwords, payment details or one-time codes because a message creates urgency.</li>
            <li>For broader message analysis, use <Link href="/investigate">text and message triage</Link>. Production analysis remains unavailable until the shared rate limiter is configured.</li>
          </ul>
        </section>
      </div>
    </main>
  );
}
