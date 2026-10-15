'use client';

import { useState } from 'react';
import SiteHeader from '../site-header';

const capabilities = [
  { id: 'text', number: '01', title: 'Text & message triage', status: 'Available · production dependency currently blocks analysis', detail: 'The Next.js API runs deterministic local checks and can optionally use a self-hosted Ollama model. Shared rate limiting must be configured before production analysis can run.', href: '/investigate', action: 'Open investigation' },
  { id: 'url', number: '02', title: 'URL inspection', status: 'Partial · currently treated as input text', detail: 'The original Python application has hardened public-URL fetching. The complete legacy fetch-and-analyze chain is not yet established in this workspace.', href: '/investigate', action: 'Open investigation' },
  { id: 'image', number: '03', title: 'Image metadata & integrity', status: 'Available · local inspection', detail: 'Inspect supported metadata and calculate a local SHA-256 fingerprint. This is not a deepfake verdict or a visual threat scan.', href: '/image-review', action: 'Open image review' },
  { id: 'qr', number: '04', title: 'QR-code investigation', status: 'Partial · native browser decoder only', detail: 'Decode QR payloads locally in browsers that support BarcodeDetector. This is not yet cross-browser and never opens the decoded destination automatically.', href: '/qr', action: 'Open QR decoder' },
  { id: 'pdf', number: '05', title: 'PDF & document review', status: 'Partial · local structural triage available', detail: 'Inspect a PDF locally for integrity and review-worthy structure markers. This does not extract document text, execute embedded content, or prove a file is malicious or safe.', href: '#pdf-review', action: 'Open local PDF review' },
  { id: 'video', number: '06', title: 'Video & media review', status: 'Partial · local frame sampling available', detail: 'Sample a small, bounded set of video frames in your browser and calculate frame fingerprints. Semantic analysis, audio transcription and provenance verification are not provided.', href: '#video-review', action: 'Open local video review' },
  { id: 'intel', number: '07', title: 'Threat intelligence', status: 'Partial · local IOC cache requires approved feed data', detail: 'No match must never mean safe. A useful result needs source provenance, version, freshness and distinct unavailable/no-match/match states.', href: '/investigate', action: 'View analysis' },
  { id: 'firstlight', number: '08', title: 'FIRSTLIGHT incident command', status: 'Training available · persistence needs end-to-end verification', detail: 'Review synthetic evidence, findings, event timelines and simulated response decisions. Simulation controls do not execute real containment actions.', href: '/firstlight', action: 'Open FIRSTLIGHT' },
  { id: 'reports', number: '09', title: 'Reports & saved cases', status: 'Partial · authenticated journey requires acceptance tests', detail: 'Local TXT/JSON export and persistent-report code exist. Full PDF export and end-to-end case reconciliation are not yet established.', href: '/reports', action: 'Open reports' },
  { id: 'learn', number: '10', title: 'Security learning', status: 'Available · educational only', detail: 'Practice with synthetic scam-awareness examples. The visual code-entry demo does not authenticate an account or verify an OTP.', href: '/learn', action: 'Open learning' },
];


const PDF_MAX_BYTES = 10 * 1024 * 1024;
const VIDEO_MAX_BYTES = 50 * 1024 * 1024;
const VIDEO_MAX_DURATION_SECONDS = 15 * 60;
const VIDEO_MAX_DIMENSION_PIXELS = 40_000_000;

type PdfInspection = {
  name: string;
  bytes: number;
  sha256: string;
  headerValid: boolean;
  eofMarkerPresent: boolean;
  markers: string[];
};

type VideoInspection = {
  name: string;
  bytes: number;
  durationSeconds: number;
  width: number;
  height: number;
  sampledFrames: Array<{ timeSeconds: number; sha256: string }>;
};

async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map(value => value.toString(16).padStart(2, '0')).join('');
}

function formatBytes(bytes: number): string {
  return bytes < 1024 * 1024
    ? (bytes / 1024).toFixed(1) + ' KiB'
    : (bytes / (1024 * 1024)).toFixed(2) + ' MiB';
}

function PdfReview() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<PdfInspection | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function inspect() {
    setError('');
    setResult(null);
    if (!file) { setError('Choose a PDF file first.'); return; }
    if (file.size === 0 || file.size > PDF_MAX_BYTES) {
      setError('Choose a non-empty PDF no larger than 10 MiB.');
      return;
    }
    if (file.type && file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) {
      setError('Choose a PDF file.');
      return;
    }

    setBusy(true);
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const decoder = new TextDecoder('latin1');
      const head = decoder.decode(bytes.subarray(0, Math.min(bytes.length, 1024)));
      const tail = decoder.decode(bytes.subarray(Math.max(0, bytes.length - 2048)));
      const searchable = decoder.decode(bytes);
      const candidates = [
        ['/JavaScript', 'JavaScript action marker'],
        ['/JS', 'JavaScript entry marker'],
        ['/OpenAction', 'automatic open action marker'],
        ['/AA', 'additional action marker'],
        ['/Launch', 'launch action marker'],
        ['/EmbeddedFile', 'embedded file marker'],
        ['/Encrypt', 'encryption marker'],
        ['/URI', 'URI action marker'],
        ['/RichMedia', 'rich media marker'],
      ] as const;
      setResult({
        name: file.name,
        bytes: file.size,
        sha256: await sha256Hex(buffer),
        headerValid: head.includes('%PDF-'),
        eofMarkerPresent: tail.includes('%%EOF'),
        markers: candidates.filter(([marker]) => searchable.includes(marker)).map(([, label]) => label),
      });
    } catch {
      setError('The file could not be inspected in this browser.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" id="pdf-review" aria-labelledby="pdf-review-heading">
      <div className="eyebrow">LOCAL FILE REVIEW · NO UPLOAD</div>
      <h2 id="pdf-review-heading">PDF structural triage</h2>
      <p>Check a PDF signature, ending marker, SHA-256 fingerprint and a short list of structure markers that deserve review. Processing stays in this browser tab.</p>
      <p className="muted">Limit: 10 MiB. This is a lightweight byte-level check, not full PDF parsing or malware scanning. Compressed objects may hide markers; matches can be benign.</p>
      <label className="field-label" htmlFor="satark-pdf-file">PDF file</label>
      <input id="satark-pdf-file" type="file" accept="application/pdf,.pdf" onChange={event => { setFile(event.target.files?.[0] ?? null); setResult(null); setError(''); }} />
      {file && <p className="muted">{file.name} · {formatBytes(file.size)}</p>}
      <div className="actions">
        <button className="btn btn-primary" type="button" disabled={!file || busy} onClick={inspect}>{busy ? 'Inspecting locally…' : 'Inspect PDF locally'}</button>
      </div>
      {error && <p role="alert" className="error-message">{error}</p>}
      {result && (
        <div className="workspace-card" aria-live="polite">
          <h3>Local inspection result</h3>
          <p><strong>File:</strong> {result.name}</p>
          <p><strong>Size:</strong> {formatBytes(result.bytes)}</p>
          <p><strong>PDF header:</strong> {result.headerValid ? 'Found' : 'Not found in the first 1 KiB'}</p>
          <p><strong>End marker:</strong> {result.eofMarkerPresent ? 'Found near the end' : 'Not found near the end'}</p>
          <p><strong>SHA-256:</strong></p>
          <code>{result.sha256}</code>
          <h3>Markers to review</h3>
          {result.markers.length
            ? <ul>{result.markers.map(marker => <li key={marker}>{marker}</li>)}</ul>
            : <p>No listed markers were found in the raw bytes. This is not evidence that the document is safe.</p>}
          <p className="muted">No content was uploaded or stored by SATARK. Review the file with a trusted PDF reader and security tooling before opening or sharing it.</p>
        </div>
      )}
    </section>
  );
}

function waitForVideoEvent(video: HTMLVideoElement, eventName: 'loadedmetadata' | 'seeked'): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      video.removeEventListener(eventName, onReady);
      video.removeEventListener('error', onError);
    };
    const onReady = () => { cleanup(); resolve(); };
    const onError = () => { cleanup(); reject(new Error('The browser could not decode this video format.')); };
    video.addEventListener(eventName, onReady, { once: true });
    video.addEventListener('error', onError, { once: true });
  });
}

function VideoReview() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<VideoInspection | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function inspect() {
    setError('');
    setResult(null);
    if (!file) { setError('Choose a video file first.'); return; }
    if (file.size === 0 || file.size > VIDEO_MAX_BYTES) {
      setError('Choose a non-empty video no larger than 50 MiB.');
      return;
    }
    if (file.type && !file.type.startsWith('video/')) {
      setError('Choose a video format supported by your browser.');
      return;
    }

    setBusy(true);
    const objectUrl = URL.createObjectURL(file);
    const video = document.createElement('video');
    video.preload = 'metadata';
    video.muted = true;
    video.playsInline = true;
    try {
      const metadataLoaded = waitForVideoEvent(video, 'loadedmetadata');
      video.src = objectUrl;
      video.load();
      await metadataLoaded;
      const duration = video.duration;
      const width = video.videoWidth;
      const height = video.videoHeight;
      if (!Number.isFinite(duration) || duration <= 0) throw new Error('The video duration could not be read.');
      if (duration > VIDEO_MAX_DURATION_SECONDS) throw new Error('Video exceeds the 15-minute local sampling limit.');
      if (!width || !height || width * height > VIDEO_MAX_DIMENSION_PIXELS) {
        throw new Error('Video dimensions are missing or exceed the 40-million-pixel limit.');
      }

      const points = [...new Set([0, duration * 0.25, duration * 0.5, duration * 0.75, Math.max(0, duration - 0.1)]
        .map(value => Math.max(0, Math.min(value, duration - 0.01)))
        .map(value => Math.round(value * 100) / 100))].slice(0, 5);
      const canvas = document.createElement('canvas');
      const scale = Math.min(1, 1280 / width, 1280 / height);
      canvas.width = Math.max(1, Math.round(width * scale));
      canvas.height = Math.max(1, Math.round(height * scale));
      const context = canvas.getContext('2d', { alpha: false });
      if (!context) throw new Error('The browser could not create a local frame canvas.');

      const sampledFrames: Array<{ timeSeconds: number; sha256: string }> = [];
      for (const timeSeconds of points) {
        if (timeSeconds > 0) {
          const seeking = waitForVideoEvent(video, 'seeked');
          video.currentTime = timeSeconds;
          await seeking;
        }
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        const frame = await new Promise<Blob>((resolve, reject) => {
          canvas.toBlob(blob => blob ? resolve(blob) : reject(new Error('Could not encode a sampled frame.')), 'image/jpeg', 0.8);
        });
        sampledFrames.push({ timeSeconds, sha256: await sha256Hex(await frame.arrayBuffer()) });
      }

      setResult({ name: file.name, bytes: file.size, durationSeconds: Math.round(duration * 100) / 100, width, height, sampledFrames });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The video could not be inspected.');
    } finally {
      URL.revokeObjectURL(objectUrl);
      video.removeAttribute('src');
      video.load();
      setBusy(false);
    }
  }

  return (
    <section className="panel" id="video-review" aria-labelledby="video-review-heading">
      <div className="eyebrow">LOCAL MEDIA REVIEW · NO UPLOAD</div>
      <h2 id="video-review-heading">Sample video frames</h2>
      <p>Read basic media metadata and calculate fingerprints for up to five evenly spaced frames locally in your browser. The source video and sampled frames are not uploaded or saved.</p>
      <p className="muted">Limit: 50 MiB and 15 minutes. This does not interpret scene meaning, inspect every frame, analyze audio, or verify provenance. Codec support depends on your browser.</p>
      <label className="field-label" htmlFor="satark-video-file">Video file</label>
      <input id="satark-video-file" type="file" accept="video/*" onChange={event => { setFile(event.target.files?.[0] ?? null); setResult(null); setError(''); }} />
      {file && <p className="muted">{file.name} · {formatBytes(file.size)}</p>}
      <div className="actions">
        <button className="btn btn-primary" type="button" disabled={!file || busy} onClick={inspect}>{busy ? 'Sampling locally…' : 'Sample frames locally'}</button>
      </div>
      {error && <p role="alert" className="error-message">{error}</p>}
      {result && (
        <div className="workspace-card" aria-live="polite">
          <h3>Local media result</h3>
          <p><strong>File:</strong> {result.name}</p>
          <p><strong>Size:</strong> {formatBytes(result.bytes)}</p>
          <p><strong>Duration:</strong> {result.durationSeconds} seconds</p>
          <p><strong>Resolution:</strong> {result.width} × {result.height}</p>
          <h3>Sampled frame fingerprints</h3>
          <ul>{result.sampledFrames.map(frame => <li key={frame.timeSeconds}><strong>{frame.timeSeconds}s</strong> — <code>{frame.sha256}</code></li>)}</ul>
          <p className="muted">Frame fingerprints identify the sampled renderings produced by this browser; they are not source-file hashes and do not establish authenticity.</p>
        </div>
      )}
    </section>
  );
}

export default function ToolsPage() {
  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <div className="eyebrow">WORKSPACE / CAPABILITY DIRECTORY</div>
        <h1>Every tool, with its real status.</h1>
        <p className="lead">SATARK includes legacy Python scanners and a newer Next.js workspace. This directory distinguishes what can be opened today from capabilities that still need migration. A legacy implementation is not the same as a working web feature.</p>
        <div className="workspace-grid">
          {capabilities.map((item) => (
            <article className="workspace-card" id={item.id} key={item.id}>
              <div className="eyebrow">{item.number} / CAPABILITY</div>
              <h2>{item.title}</h2>
              <p><strong>{item.status}</strong></p>
              <p>{item.detail}</p>
              {item.href ? <a className="btn btn-secondary" href={item.href}>{item.action} <span aria-hidden="true">↗</span></a> : <span className="pill">Migration required</span>}
            </article>
          ))}
        </div>
        <div className="workspace-grid">
          <PdfReview />
          <VideoReview />
        </div>
        <section className="panel" aria-labelledby="migration-heading">
          <div className="eyebrow">ENGINEERING PLAN</div>
          <h2 id="migration-heading">Restore the missing workflows</h2>
          <p>The feature-by-feature migration matrix defines implementation boundaries, required security controls, dependencies and acceptance tests.</p>
          <a className="btn btn-primary" href="https://github.com/kaustubhdua/Satark/blob/main/docs/SECURITY_TOOL_PARITY_MATRIX.md">Read the security-tool parity matrix <span aria-hidden="true">↗</span></a>
        </section>
      </div>
    </main>
  );
}
