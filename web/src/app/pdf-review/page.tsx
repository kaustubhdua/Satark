'use client';

import SiteHeader from '../site-header';
import { useMemo, useState } from 'react';
import { FileSearch, Fingerprint, LockKeyhole, Download, RotateCcw, AlertTriangle, CheckCircle2, FileText } from 'lucide-react';
import { extractPdfStats, scoreMessage, scorePdf } from '../../lib/learned-models.mjs';

const MAX_PDF_BYTES = 15 * 1024 * 1024;
const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const MAX_PAGES = 50;
const MAX_TEXT_CHARS = 300_000;
const PREVIEW_CHARS = 16_000;

type LocalSignal = { label: string; detail: string };
type ModelSignal = { model: string; band: string; score: number };
type Extraction = {
  name: string;
  kind: 'PDF' | 'Text document';
  bytes: number;
  sha256: string;
  extractedCharacters: number;
  pages: number | null;
  truncated: boolean;
  text: string;
  extractedAt: string;
  pdfModel: ModelSignal | null;
  textModel: ModelSignal | null;
  structuralFlags: string[];
};

const indicators: Array<{ label: string; detail: string; pattern: RegExp }> = [
  { label: 'Urgency or time pressure', detail: 'Language that pressures someone to act quickly can discourage independent verification.', pattern: /\b(?:urgent|immediately|act now|within\s+\d+\s*(?:minutes?|hours?)|final warning|account will be (?:blocked|closed|suspended))\b/i },
  { label: 'Credential or verification-code request', detail: 'Requests for passwords, one-time codes, recovery codes or PINs should be verified through an official channel.', pattern: /\b(?:password|passcode|one[- ]time (?:code|password)|\bOTP\b|verification code|recovery code|PIN)\b/i },
  { label: 'Payment or financial pressure', detail: 'Unexpected transfer, fee, gift-card or cryptocurrency instructions deserve independent verification.', pattern: /\b(?:wire transfer|bank transfer|gift cards?|crypto(?:currency)?|wallet address|processing fee|payment required|send (?:the )?(?:money|funds))\b/i },
  { label: 'Prize or unexpected reward', detail: 'Unexpected winnings or rewards paired with a request for money or personal information can be a social-engineering pattern.', pattern: /\b(?:you (?:have )?(?:won|w[oó]n)|winner|claim your prize|free reward|lottery)\b/i },
  { label: 'Instruction to open a link or attachment', detail: 'Treat unexpected links and files cautiously; verify the sender independently before opening or acting on them.', pattern: /\b(?:click (?:here|this link)|open the attachment|download (?:the )?(?:file|attachment)|verify your account (?:here|now))\b/i },
  { label: 'Impersonation or secrecy pressure', detail: 'Requests to bypass normal process, keep a transaction secret or impersonate an authority should be confirmed using a trusted contact method.', pattern: /\b(?:keep this confidential|do not tell anyone|don't tell anyone|CEO fraud|impersonat(?:e|ing)|pretend to be|avoid the usual process)\b/i },
];

function sha256(bytes: ArrayBuffer) {
  return crypto.subtle.digest('SHA-256', bytes).then(digest =>
    Array.from(new Uint8Array(digest)).map(value => value.toString(16).padStart(2, '0')).join(''),
  );
}

function classify(text: string): LocalSignal[] {
  return indicators.filter(item => item.pattern.test(text)).map(({ label, detail }) => ({ label, detail }));
}

function saveTextFile(filename: string, text: string) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function extractPlainText(text: string) {
  return text.replace(/\u0000/g, '').replace(/\r\n?/g, '\n').trim();
}

export default function PdfReviewPage() {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [result, setResult] = useState<Extraction | null>(null);
  const [search, setSearch] = useState('');
  const [showText, setShowText] = useState(false);

  const signals = useMemo(() => result ? classify(result.text) : [], [result]);
  const matchingCount = useMemo(() => {
    if (!result || !search.trim()) return 0;
    const query = search.trim().toLocaleLowerCase();
    const text = result.text.toLocaleLowerCase();
    let count = 0;
    let from = 0;
    while (count < 10_000) {
      const found = text.indexOf(query, from);
      if (found < 0) break;
      count++;
      from = found + Math.max(1, query.length);
    }
    return count;
  }, [result, search]);

  function selectFile(next: File | null) {
    setFile(next);
    setError('');
    setNotice('');
    setResult(null);
    setSearch('');
    setShowText(false);
  }

  async function extract() {
    setError('');
    setNotice('');
    setResult(null);
    setSearch('');
    setShowText(false);
    if (!file) {
      setError('Choose a PDF or supported text document first.');
      return;
    }

    const filename = file.name.toLocaleLowerCase();
    const isPdf = file.type === 'application/pdf' || filename.endsWith('.pdf');
    const isText = /\.(txt|md|csv|log)$/i.test(file.name) ||
      ['text/plain', 'text/markdown', 'text/csv'].includes(file.type);
    if (!isPdf && !isText) {
      setError('Supported formats are PDF, TXT, Markdown, CSV and LOG. Office documents, archives and embedded files are not opened by this tool.');
      return;
    }
    const sizeLimit = isPdf ? MAX_PDF_BYTES : MAX_TEXT_BYTES;
    if (file.size === 0) {
      setError('This file is empty.');
      return;
    }
    if (file.size > sizeLimit) {
      setError(isPdf ? 'PDFs are limited to 15 MiB per inspection.' : 'Text documents are limited to 2 MiB per inspection.');
      return;
    }

    setBusy(true);
    let disposePdf: (() => Promise<void>) | null = null;
    try {
      const buffer = await file.arrayBuffer();
      let text = '';
      let pages: number | null = null;
      let truncated = false;
      let kind: Extraction['kind'] = isPdf ? 'PDF' : 'Text document';

      let pdfModel: ModelSignal | null = null;
      const structuralFlags: string[] = [];

      if (isPdf) {
        const bytes = new Uint8Array(buffer);
        const header = new TextDecoder('ascii').decode(bytes.subarray(0, Math.min(bytes.length, 1024)));
        if (!header.includes('%PDF-')) throw new Error('The file does not have a valid PDF signature. Renaming another file to .pdf is not sufficient.');

        const pdfjs = await import('pdfjs-dist');
        pdfjs.GlobalWorkerOptions.workerSrc = '/pdf.worker.mjs';
        const pdfOptions = {
          data: bytes,
          isEvalSupported: false,
          enableXfa: false,
          useWorkerFetch: false,
          useWasm: false,
        };
        const loadingTask = pdfjs.getDocument(pdfOptions);
        disposePdf = () => loadingTask.destroy();
        const pdf = await loadingTask.promise;
        pages = pdf.numPages;
        if (pages > MAX_PAGES) throw new Error('This PDF contains more than 50 pages. Split it into smaller files and inspect only the relevant pages.');

        const pdfStats = extractPdfStats(bytes, pages);
        pdfModel = scorePdf(pdfStats);
        if (pdfStats.js > 0 || pdfStats.javascript > 0) structuralFlags.push('Embedded JavaScript (/JS)');
        if (pdfStats.openaction > 0) structuralFlags.push('Automatic OpenAction trigger');
        if (pdfStats.aa > 0) structuralFlags.push('Additional Actions (/AA)');
        if (pdfStats.launch > 0) structuralFlags.push('External Launch action');
        if (pdfStats.embeddedfile > 0) structuralFlags.push('Embedded file attachment');
        if (pdfStats.acroform > 0) structuralFlags.push('Interactive AcroForm');
        if (pdfStats.xfa > 0) structuralFlags.push('XFA form payload');
        if (pdfStats.objstm > 0) structuralFlags.push('Compressed object stream (/ObjStm)');
        const chunks: string[] = [];
        let characterCount = 0;
        for (let pageNumber = 1; pageNumber <= pages; pageNumber++) {
          const page = await pdf.getPage(pageNumber);
          const textContent = await page.getTextContent();
          const pageText = textContent.items
            .map(item => ('str' in item && typeof item.str === 'string') ? item.str : '')
            .filter(Boolean)
            .join(' ');
          const separator = pageNumber === 1 ? '' : '\n\n';
          const room = Math.max(0, MAX_TEXT_CHARS - characterCount - separator.length);
          if (pageText.length > room) {
            chunks.push(separator + pageText.slice(0, room));
            characterCount += separator.length + room;
            truncated = true;
            break;
          }
          chunks.push(separator + pageText);
          characterCount += separator.length + pageText.length;
          if (characterCount >= MAX_TEXT_CHARS) {
            truncated = true;
            break;
          }
        }
        text = extractPlainText(chunks.join(''));
      } else {
        text = extractPlainText(new TextDecoder('utf-8').decode(buffer));
        if (text.length > MAX_TEXT_CHARS) {
          text = text.slice(0, MAX_TEXT_CHARS);
          truncated = true;
        }
      }

      const digest = await sha256(buffer);
      const textModel = text.trim() ? scoreMessage(text) : null;
      const extracted: Extraction = {
        name: file.name,
        kind,
        bytes: file.size,
        sha256: digest,
        extractedCharacters: text.length,
        pages,
        truncated,
        text,
        extractedAt: new Date().toISOString(),
        pdfModel,
        textModel,
        structuralFlags,
      };
      setResult(extracted);
      if (!text.trim()) {
        setNotice(isPdf
          ? 'PDF opened locally, but no selectable text was extracted. It may be scanned, image-only, encrypted or use an unsupported font/layout. OCR is not included.'
          : 'No readable text was found in this file.');
      } else {
        setNotice('Local extraction complete. The file and extracted text were not uploaded or sent to a third-party service.');
      }
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'The document could not be inspected.';
      if (/password|encrypted/i.test(message)) {
        setError('This PDF appears to be password-protected or encrypted. Password-protected PDF extraction is not supported in this workflow.');
      } else if (/worker|fake worker/i.test(message)) {
        setError('The local PDF worker could not start. Refresh the page and try again; the matching worker must be served from this SATARK deployment.');
      } else {
        setError(message);
      }
    } finally {
      if (disposePdf) {
        await disposePdf().catch(() => undefined);
      }
      setBusy(false);
    }
  }

  function exportSummary() {
    if (!result) return;
    const text = [
      'SATARK SENTINEL — LOCAL DOCUMENT REVIEW',
      'Triage guidance only. This export is not a certification of safety or authenticity.',
      '',
      `File: ${result.name}`,
      `Format: ${result.kind}`,
      `Bytes: ${result.bytes}`,
      `SHA-256: ${result.sha256}`,
      `Pages: ${result.pages ?? 'Not applicable'}`,
      `Extracted characters: ${result.extractedCharacters}`,
      `Extraction truncated: ${result.truncated ? 'Yes' : 'No'}`,
      `Inspected at: ${result.extractedAt}`,
      '',
      'Local heuristic signals',
      ...(signals.length ? signals.map(item => `- ${item.label}: ${item.detail}`) : ['- No listed heuristic patterns were found. This does not mean the document is safe.']),
      '',
      'Limitations',
      '- Analysis is a set of local text-pattern indicators, not a trained threat detector or a verdict.',
      '- Text extraction does not render all layout, images, attachments, annotations or active content.',
      '- Scanned/image-only PDFs are not OCR-processed by this workflow.',
      '- The original document and its extracted contents are not included in this summary export.',
    ].join('\n');
    saveTextFile('satark-document-review-summary.txt', text);
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage local-review-page" id="main-content" tabIndex={-1}>
        <div className="eyebrow">Documents</div>
        <h1>Review the <span>document.</span></h1>
        <p className="lead">Extract text from supported PDFs and plain-text files, fingerprint the original file, and check for explainable social-engineering cues—all in this browser tab.</p>

        <section className="form-panel local-review-intro" aria-labelledby="document-method-heading">
          <div className="panel-heading">
            <div>
              <div className="panel-kicker">Private by design</div>
              <h2 id="document-method-heading">The file stays on your device</h2>
            </div>
            <span className="safe-chip"><LockKeyhole size={14} /> No file upload</span>
          </div>
          <div className="local-review-points">
            <div><CheckCircle2 size={16} /><span>Text extraction and pattern checks run locally.</span></div>
            <div><Fingerprint size={16} /><span>SHA-256 fingerprint of the original bytes.</span></div>
            <div><AlertTriangle size={16} /><span>Patterns are triage hints—not a safe/malicious verdict.</span></div>
          </div>
        </section>

        <section className="form-panel" aria-labelledby="document-input-heading">
          <div className="panel-kicker">Supported input</div>
          <h2 id="document-input-heading">Choose a document</h2>
          <p className="muted">PDF up to 15 MiB and 50 pages; TXT, Markdown, CSV or LOG up to 2 MiB. Office files, archives, embedded attachments and OCR for scanned PDFs are not supported in this workflow.</p>
          <label className="field-label" htmlFor="document-file">Document file</label>
          <input
            id="document-file"
            type="file"
            accept=".pdf,.txt,.md,.csv,.log,application/pdf,text/plain,text/markdown,text/csv"
            onChange={event => selectFile(event.target.files?.[0] ?? null)}
            aria-describedby="document-file-help"
          />
          <p className="hint" id="document-file-help">Never open or execute a document to inspect it with SATARK. This tool extracts supported text; it does not execute document scripts or automatically open embedded links.</p>
          {file && <div className="file-selection"><FileText size={18} /><div><strong>{file.name}</strong><span>{(file.size / 1024).toFixed(1)} KiB · {file.type || 'type not supplied by browser'}</span></div><button type="button" className="btn btn-secondary" onClick={() => selectFile(null)} disabled={busy}><RotateCcw size={14} /> Clear</button></div>}
          {error && <p className="error-message" role="alert">{error}</p>}
          {notice && <p className="success-message" role="status">{notice}</p>}
          <div className="actions">
            <button type="button" className="btn btn-primary" onClick={() => void extract()} disabled={!file || busy}>
              <FileSearch size={16} /> {busy ? 'Extracting locally…' : 'Extract and inspect locally'}
            </button>
            <span className="hint">No third-party AI or reputation service is called by this page.</span>
          </div>
        </section>

        {result && (
          <>
            <section className="form-panel" aria-labelledby="document-results-heading">
              <div className="panel-heading">
                <div><div className="panel-kicker">Extraction results</div><h2 id="document-results-heading">Local review summary</h2></div>
                <span className="safe-chip"><CheckCircle2 size={14} /> Processed in browser</span>
              </div>
              <div className="local-review-stats">
                <article className="local-review-stat"><span>Format</span><strong>{result.kind}</strong></article>
                <article className="local-review-stat"><span>PAGES</span><strong>{result.pages ?? '—'}</strong></article>
                <article className="local-review-stat"><span>Text characters</span><strong>{result.extractedCharacters.toLocaleString()}</strong></article>
                <article className="local-review-stat"><span>Local cues</span><strong>{signals.length}</strong></article>
              </div>
              <div className="local-review-hash">
                <span><Fingerprint size={15} /> Original file SHA-256</span>
                <code>{result.sha256}</code>
              </div>
              {(result.pdfModel || result.textModel || result.structuralFlags.length > 0) && (
                <div className="document-signal-list" style={{ marginTop: '14px' }}>
                  {result.pdfModel && (
                    <article className="document-signal">
                      <span className="signal-mark"><AlertTriangle size={15} /></span>
                      <div>
                        <strong>Trained PDF structure model (satark-pdf-v1): {result.pdfModel.band.toUpperCase()}</strong>
                        <p>Advisory score from PDF object/script/action structure trained on CIC-Evasive-PDFMal2022. {result.structuralFlags.length ? 'Observed markers: ' + result.structuralFlags.join(', ') + '.' : 'No high-risk active PDF markers observed.'}</p>
                      </div>
                    </article>
                  )}
                  {result.textModel && (
                    <article className="document-signal">
                      <span className="signal-mark"><AlertTriangle size={15} /></span>
                      <div>
                        <strong>Trained wording model ({result.textModel.model === 'email' ? 'satark-email-v1' : 'satark-message-v1'}): {result.textModel.band.toUpperCase()}</strong>
                        <p>Advisory wording score on extracted document text. Combine with manual verification before trusting links or payment requests.</p>
                      </div>
                    </article>
                  )}
                </div>
              )}
              {result.truncated && <p className="notice-panel">The extraction was capped at 300,000 characters to keep processing bounded. Review the source document directly for omitted content.</p>}
              {result.text.trim() && (
                <>
                  <div className="panel-heading document-findings-heading">
                    <div><div className="panel-kicker">Explainable signals</div><h3>Patterns worth reviewing</h3></div>
                    <span className="pill">{signals.length} INDICATOR{signals.length === 1 ? '' : 'S'}</span>
                  </div>
                  {signals.length ? <div className="document-signal-list">
                    {signals.map(item => <article className="document-signal" key={item.label}><span className="signal-mark"><AlertTriangle size={15} /></span><div><strong>{item.label}</strong><p>{item.detail}</p></div></article>)}
                  </div> : <p className="empty-state">No listed heuristic patterns were detected in the extracted text. This is not evidence that the document is safe, genuine, or complete.</p>}
                </>
              )}
              <div className="actions">
                <button type="button" className="btn btn-primary" onClick={exportSummary}><Download size={15} /> Export summary (TXT)</button>
                <button type="button" className="btn btn-secondary" onClick={() => { setResult(null); setNotice(''); setError(''); }}><RotateCcw size={15} /> Clear results</button>
              </div>
            </section>
            {result.text.trim() && (
              <section className="form-panel" aria-labelledby="document-text-heading">
                <div className="panel-heading">
                  <div><div className="panel-kicker">Extracted content</div><h2 id="document-text-heading">Review the text</h2></div>
                  <span className="pill">Local only</span>
                </div>
                <label className="field-label" htmlFor="document-text-search">Find text in extracted content</label>
                <input id="document-text-search" type="search" value={search} maxLength={160} onChange={event => setSearch(event.target.value)} placeholder="Search the extracted text…" />
                {search.trim() && <p className="hint" role="status">{matchingCount.toLocaleString()} occurrence{matchingCount === 1 ? '' : 's'} found in the extracted text.</p>}
                <button type="button" className="text-disclosure" aria-expanded={showText} onClick={() => setShowText(value => !value)}>
                  {showText ? 'Hide extracted text' : 'Show extracted text'} <span>{showText ? '−' : '+'}</span>
                </button>
                {showText && <pre className="extracted-text-preview">{result.text.slice(0, PREVIEW_CHARS)}{result.text.length > PREVIEW_CHARS ? '\n\n[Preview capped. Use your original file for the remaining content.]' : ''}</pre>}
              </section>
            )}
          </>
        )}

        <section className="sentinel-boundary" aria-label="Document review limitations">
          <div className="boundary-icon"><AlertTriangle size={19} /></div>
          <div><strong>What this can—and cannot—establish.</strong><p>This workflow extracts selectable text and checks a small set of transparent patterns. It does not inspect macros or attachments, perform OCR, validate document signatures, check URLs against reputation feeds, detect deepfakes, or certify authenticity. A missing indicator never proves safety.</p></div>
          <a href="/tools#pdf">Capability status <span aria-hidden="true">↗</span></a>
        </section>
      </div>
    </main>
  );
}
