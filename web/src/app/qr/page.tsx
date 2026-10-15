'use client';

import SiteHeader from '../site-header';
import { useState } from 'react';

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_PIXELS = 40_000_000;

type DetectedBarcode = { rawValue: string; format?: string };
type BarcodeDetectorLike = { detect(source: ImageBitmap): Promise<DetectedBarcode[]> };
type BarcodeDetectorConstructor = new (options?: { formats?: string[] }) => BarcodeDetectorLike;
type LocalAnalysis = {
  threat_category: string;
  risk_score: number;
  summary: string;
  key_indicators: string[];
  recommendations: string[];
  limitations: string[];
  notice: string;
  model: string;
};

function getDetector(): BarcodeDetectorConstructor | null {
  const browserWindow = window as Window & { BarcodeDetector?: BarcodeDetectorConstructor };
  return browserWindow.BarcodeDetector ?? null;
}

function classifyPayload(value: string) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return { kind: 'URL', isWebUrl: true, note: 'Destination decoded only. The local analysis below inspects the URL text; it does not visit the destination.' };
    }
    return { kind: 'Non-web URI', isWebUrl: false, note: 'Do not open this value unless you understand its scheme and trust its source.' };
  } catch {
    return { kind: 'Text payload', isWebUrl: false, note: 'This QR code contains text rather than a directly recognized HTTP/HTTPS URL.' };
  }
}

export default function QrPage() {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [analyzingPayload, setAnalyzingPayload] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [analysisError, setAnalysisError] = useState('');
  const [payloads, setPayloads] = useState<string[]>([]);
  const [analyses, setAnalyses] = useState<Record<string, LocalAnalysis>>({});
  const [notice, setNotice] = useState('');

  async function decode() {
    setError('');
    setAnalysisError('');
    setNotice('');
    setPayloads([]);
    setAnalyses({});
    if (!file) { setError('Choose a QR-code image first.'); return; }
    if (file.size > MAX_FILE_BYTES) { setError('Image exceeds the 10 MiB processing limit.'); return; }
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) { setError('Use a JPEG, PNG or WebP image.'); return; }
    const Detector = getDetector();
    if (!Detector) {
      setError('This browser does not provide a native QR decoder. Use a browser with BarcodeDetector support. Your file has not been uploaded.');
      return;
    }

    setBusy(true);
    let bitmap: ImageBitmap | null = null;
    try {
      bitmap = await createImageBitmap(file);
      if (bitmap.width * bitmap.height > MAX_PIXELS) throw new Error('Image dimensions exceed the 40-million-pixel processing limit.');
      const detector = new Detector({ formats: ['qr_code'] });
      const results = await detector.detect(bitmap);
      const values = [...new Set(results.map(item => item.rawValue.trim()).filter(Boolean))];
      if (!values.length) setNotice('No QR payload was decoded. This does not mean the image or any embedded destination is safe.');
      else { setPayloads(values); setNotice('Decoded locally in your browser. SATARK did not upload the image or open the payload.'); }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not decode this image.');
    } finally {
      bitmap?.close();
      setBusy(false);
    }
  }

  async function analyzePayload(payload: string) {
    setAnalysisError('');
    setAnalyzingPayload(payload);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ input: payload }),
      });
      const data: unknown = (response.headers.get('content-type') || '').includes('application/json') ? await response.json() : null;
      if (!response.ok) {
        const message = data && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
          ? data.error
          : 'Local analysis could not complete. Please retry.';
        throw new Error(message);
      }
      if (!data || typeof data !== 'object') throw new Error('The local analyzer returned an unreadable response.');
      const result = data as Partial<LocalAnalysis>;
      if (typeof result.threat_category !== 'string' || typeof result.risk_score !== 'number' ||
          typeof result.summary !== 'string' || !Array.isArray(result.key_indicators) ||
          !Array.isArray(result.recommendations) || !Array.isArray(result.limitations) ||
          typeof result.notice !== 'string' || typeof result.model !== 'string') {
        throw new Error('The local analyzer returned an incomplete result.');
      }
      setAnalyses(current => ({ ...current, [payload]: result as LocalAnalysis }));
    } catch (cause) {
      setAnalysisError(cause instanceof Error ? cause.message : 'Local analysis could not complete.');
    } finally {
      setAnalyzingPayload(null);
    }
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">WORKSPACE / QR INVESTIGATION</div>
        <h1>Decode first. Inspect locally.</h1>
        <p className="lead">QR decoding happens in your browser. If a decoded value is an HTTP/HTTPS URL, SATARK can inspect the URL text with its local analysis engine without visiting the destination or calling a third-party API.</p>
        <section className="panel" aria-labelledby="upload-heading">
          <div className="eyebrow">LOCAL PROCESSING</div>
          <h2 id="upload-heading">Choose a QR-code image</h2>
          <p>JPEG, PNG or WebP · maximum 10 MiB · maximum 40 million pixels. Native decoder support varies by browser.</p>
          <label className="field-label" htmlFor="qr-image">QR image</label>
          <input id="qr-image" type="file" accept="image/jpeg,image/png,image/webp" onChange={(event) => { setFile(event.target.files?.[0] ?? null); setError(''); setAnalysisError(''); setNotice(''); setPayloads([]); setAnalyses({}); }} />
          {file && <p className="muted">{file.name} · {(file.size / 1024).toFixed(1)} KiB</p>}
          <div className="actions">
            <button className="btn btn-primary" type="button" disabled={busy || !file} onClick={decode}>{busy ? 'Decoding…' : 'Decode QR locally'}</button>
          </div>
          {error && <p role="alert" className="error-message">{error}</p>}
          {notice && <p role="status" className="notice">{notice}</p>}
        </section>
        {payloads.length > 0 && (
          <section className="panel" aria-labelledby="results-heading">
            <div className="eyebrow">OBSERVATIONS · NOT A VERDICT</div>
            <h2 id="results-heading">Decoded payloads</h2>
            {payloads.map((payload, index) => {
              const classification = classifyPayload(payload);
              const analysis = analyses[payload];
              return (
                <article className="workspace-card" key={payload + ':' + index}>
                  <h3>Payload {index + 1} · {classification.kind}</h3>
                  <pre className="code-output">{payload}</pre>
                  <p>{classification.note}</p>
                  <div className="actions">
                    <button className="btn btn-secondary" type="button" onClick={() => { void navigator.clipboard?.writeText(payload).catch(() => undefined); }}>Copy payload</button>
                    {classification.isWebUrl && <button className="btn btn-primary" type="button" disabled={analyzingPayload !== null} onClick={() => { void analyzePayload(payload); }}>{analyzingPayload === payload ? 'Inspecting locally…' : analysis ? 'Run local inspection again' : 'Inspect URL locally'}</button>}
                  </div>
                  {analysisError && analyzingPayload === null && <p role="alert" className="error-message">{analysisError}</p>}
                  {analysis && <section className="analysis-result" aria-live="polite" aria-label="Local URL inspection result">
                    <div className="result-top"><span className="pill">{analysis.threat_category}</span><strong>Heuristic priority: {analysis.risk_score}/100</strong></div>
                    <p>{analysis.summary}</p>
                    <p className="field-note">{analysis.notice}</p>
                    <h4>Observed signals</h4>
                    {analysis.key_indicators.length ? <ul>{analysis.key_indicators.map((item, signalIndex) => <li key={signalIndex}>{item}</li>)}</ul> : <p>No configured signals detected. This is not evidence that the URL is safe.</p>}
                    <h4>Recommended next steps</h4>
                    <ul>{analysis.recommendations.map((item, recommendationIndex) => <li key={recommendationIndex}>{item}</li>)}</ul>
                    <details><summary>Method and limitations</summary><p>Analysis method: {analysis.model}. {analysis.limitations.join(' ')}</p></details>
                  </section>}
                </article>
              );
            })}
            <p className="muted">A decoded URL is never opened automatically. This inspection evaluates the URL as text; it does not fetch pages, resolve redirects, or check live reputation.</p>
          </section>
        )}
        <section className="panel">
          <h2>Local-only guarantees and limits</h2>
          <ul>
            <li>The image is decoded in the browser and is not uploaded by this page.</li>
            <li>URL inspection calls SATARK's own local analysis route; no third-party reputation or AI API is required.</li>
            <li>Optional local-model enhancement works only if a local Ollama service is installed and configured.</li>
            <li>This page does not fetch or execute the decoded destination and cannot guarantee detection across all browsers.</li>
          </ul>
        </section>
      </div>
    </main>
  );
}
