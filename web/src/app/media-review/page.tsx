'use client';

import SiteHeader from '../site-header';
import { type SyntheticEvent, useEffect, useRef, useState } from 'react';
import { Activity, AlertTriangle, Download, Fingerprint, LockKeyhole, RotateCcw, ScanSearch, ShieldCheck, Video } from 'lucide-react';

const MAX_VIDEO_BYTES = 50 * 1024 * 1024;
const MAX_VIDEO_SECONDS = 120;
const MAX_VIDEO_PIXELS = 3840 * 2160;
const MAX_SAMPLE_COUNT = 6;
const SAMPLE_POINTS = [0.08, 0.22, 0.38, 0.54, 0.72, 0.90];

type MediaMetadata = {
  durationSeconds: number;
  width: number;
  height: number;
  bytes: number;
  type: string;
  lastModified: string;
  withinLimits: boolean;
};
type SampledFrame = {
  index: number;
  timestampSeconds: number;
  width: number;
  height: number;
  sha256: string;
  meanLuminance: number;
  preview: string;
};
type MediaReview = {
  fileName: string;
  fileSha256: string;
  metadata: MediaMetadata;
  sampledAt: string;
  frames: SampledFrame[];
};

function sha256(bytes: ArrayBuffer) {
  return crypto.subtle.digest('SHA-256', bytes).then(digest =>
    Array.from(new Uint8Array(digest)).map(value => value.toString(16).padStart(2, '0')).join(''),
  );
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds < 0) return 'Unknown';
  const minutes = Math.floor(seconds / 60);
  const remainder = (seconds % 60).toFixed(2).padStart(5, '0');
  return minutes + ':' + remainder;
}

function waitForSeek(video: HTMLVideoElement, target: number) {
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      video.removeEventListener('seeked', onSeeked);
      video.removeEventListener('error', onError);
      window.clearTimeout(timer);
    };
    const finish = (cause?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      cause ? reject(cause) : resolve();
    };
    const onSeeked = () => finish();
    const onError = () => finish(new Error('The browser could not decode one of the requested sample frames.'));
    const timer = window.setTimeout(() => finish(new Error('The browser timed out while seeking to a sample frame.')), 8_000);
    video.addEventListener('seeked', onSeeked, { once: true });
    video.addEventListener('error', onError, { once: true });
    if (video.readyState >= 2 && Math.abs(video.currentTime - target) < 0.025) {
      queueMicrotask(() => finish());
    } else {
      try {
        video.currentTime = target;
      } catch {
        finish(new Error('The video could not seek to the requested sample time.'));
      }
    }
  });
}

async function captureFrame(video: HTMLVideoElement, timestamp: number, index: number): Promise<SampledFrame> {
  const maxWidth = 640;
  const maxHeight = 360;
  const scale = Math.min(1, maxWidth / video.videoWidth, maxHeight / video.videoHeight);
  const width = Math.max(1, Math.round(video.videoWidth * scale));
  const height = Math.max(1, Math.round(video.videoHeight * scale));
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext('2d', { willReadFrequently: true });
  if (!context) throw new Error('This browser could not prepare a local frame for review.');
  context.drawImage(video, 0, 0, width, height);

  const pixels = context.getImageData(0, 0, width, height).data;
  let luminanceTotal = 0;
  let samples = 0;
  const stride = 4 * 16;
  for (let offset = 0; offset < pixels.length; offset += stride) {
    luminanceTotal += 0.2126 * pixels[offset] + 0.7152 * pixels[offset + 1] + 0.0722 * pixels[offset + 2];
    samples++;
  }

  const encodedFrame = await new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(blob => blob ? resolve(blob) : reject(new Error('The browser could not encode a frame preview.')), 'image/jpeg', 0.8);
  });
  const preview = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('The browser could not prepare a local frame preview.'));
    reader.onload = () => typeof reader.result === 'string'
      ? resolve(reader.result)
      : reject(new Error('The browser returned an invalid frame preview.'));
    reader.readAsDataURL(encodedFrame);
  });
  canvas.width = 0;
  canvas.height = 0;
  const digest = await sha256(await encodedFrame.arrayBuffer());
  return {
    index,
    timestampSeconds: timestamp,
    width,
    height,
    sha256: digest,
    meanLuminance: samples ? Math.round((luminanceTotal / samples) * 10) / 10 : 0,
    preview,
  };
}

function exportSummary(review: MediaReview) {
  const text = [
    'SATARK SENTINEL — LOCAL VIDEO FRAME REVIEW',
    'Triage and sampling metadata only. This is not a deepfake, authenticity or chain-of-custody verdict.',
    '',
    'File: ' + review.fileName,
    'MIME type: ' + (review.metadata.type || 'Not provided by browser'),
    'Bytes: ' + review.metadata.bytes,
    'SHA-256: ' + review.fileSha256,
    'Duration seconds: ' + review.metadata.durationSeconds,
    'Dimensions: ' + review.metadata.width + ' × ' + review.metadata.height,
    'Sampled frame count: ' + review.frames.length,
    'Inspected at: ' + review.sampledAt,
    '',
    'FRAME SAMPLES',
    ...review.frames.map(frame => [
      'Frame ' + frame.index + ' at ' + frame.timestampSeconds.toFixed(3) + ' s',
      '  Preview dimensions: ' + frame.width + ' × ' + frame.height,
      '  Sampled preview SHA-256: ' + frame.sha256,
      '  Mean preview luminance (0–255): ' + frame.meanLuminance,
    ].join('\n')),
    '',
    'LIMITATIONS',
    '- Only six representative times are sampled. Motion between samples is not inspected.',
    '- The browser decoder determines the frames and media metadata available to this tool.',
    '- Audio is not transcribed or analyzed; container/codec forensic metadata is not extracted.',
    '- Preview hashes identify encoded JPEG previews, not the corresponding original source frame bytes.',
    '- A low-light or unusually bright frame measurement is not evidence of tampering.',
    '- No file upload, third-party analysis API, or automatic media destination request is performed by this page.',
  ].join('\n');

  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'satark-media-review-summary.txt';
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function MediaReviewPage() {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [objectUrl, setObjectUrl] = useState('');
  const [metadata, setMetadata] = useState<MediaMetadata | null>(null);
  const [review, setReview] = useState<MediaReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  useEffect(() => {
    if (!file) {
      setObjectUrl('');
      return;
    }
    const url = URL.createObjectURL(file);
    setObjectUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [file]);

  function clear() {
    setFile(null);
    setMetadata(null);
    setReview(null);
    setError('');
    setNotice('');
  }

  function chooseFile(next: File | null) {
    setError('');
    setNotice('');
    setReview(null);
    setMetadata(null);
    if (!next) {
      setFile(null);
      return;
    }
    const lowerName = next.name.toLocaleLowerCase();
    const isSupported = next.type === 'video/mp4' || next.type === 'video/webm' ||
      lowerName.endsWith('.mp4') || lowerName.endsWith('.webm');
    if (!isSupported) {
      setFile(null);
      setError('Use an MP4 or WebM video. MOV, AVI, MKV and audio-only files are not supported in this browser workflow.');
      return;
    }
    if (next.size === 0) {
      setFile(null);
      setError('This file is empty.');
      return;
    }
    if (next.size > MAX_VIDEO_BYTES) {
      setFile(null);
      setError('Video files are limited to 50 MiB. Trim the clip or select a smaller segment.');
      return;
    }
    setFile(next);
  }

  function handleMetadata(event: SyntheticEvent<HTMLVideoElement>) {
    const video = event.currentTarget;
    const selected = file;
    if (!selected) return;
    const durationSeconds = video.duration;
    const width = video.videoWidth;
    const height = video.videoHeight;
    const withinLimits = Number.isFinite(durationSeconds) && durationSeconds > 0 &&
      durationSeconds <= MAX_VIDEO_SECONDS && width > 0 && height > 0 && width * height <= MAX_VIDEO_PIXELS;
    setMetadata({
      durationSeconds,
      width,
      height,
      bytes: selected.size,
      type: selected.type,
      lastModified: new Date(selected.lastModified).toISOString(),
      withinLimits,
    });
    setReview(null);
    if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) {
      setError('The browser could not read a finite video duration. Try exporting a supported MP4 or WebM file.');
    } else if (durationSeconds > MAX_VIDEO_SECONDS) {
      setError('This clip is longer than 120 seconds. Trim it and inspect a shorter segment.');
    } else if (!width || !height || width * height > MAX_VIDEO_PIXELS) {
      setError('Frame dimensions are invalid or exceed the 4K pixel-processing limit.');
    } else {
      setNotice('Video metadata loaded locally. No upload has occurred.');
    }
  }

  async function inspect() {
    setError('');
    setNotice('');
    setReview(null);
    const video = videoRef.current;
    if (!file || !metadata || !video) {
      setError('Choose a supported video and wait for its metadata to load.');
      return;
    }
    if (!metadata.withinLimits) {
      setError('This video exceeds the local processing limits.');
      return;
    }

    setBusy(true);
    try {
      if (video.readyState < 2) {
        await new Promise<void>((resolve, reject) => {
          const timer = window.setTimeout(() => reject(new Error('The video preview did not become ready in time.')), 8_000);
          video.addEventListener('loadeddata', () => { window.clearTimeout(timer); resolve(); }, { once: true });
          video.addEventListener('error', () => { window.clearTimeout(timer); reject(new Error('The browser could not decode this video.')); }, { once: true });
        });
      }
      video.pause();
      const originalHash = await sha256(await file.arrayBuffer());
      const duration = metadata.durationSeconds;
      const times = SAMPLE_POINTS.slice(0, MAX_SAMPLE_COUNT)
        .map(fraction => Math.min(Math.max(0.05, duration * fraction), Math.max(0.05, duration - 0.05)))
        .filter((value, index, items) => items.findIndex(candidate => Math.abs(candidate - value) < 0.025) === index);
      if (!times.length) throw new Error('The clip is too short to sample reliable representative frames.');

      const frames: SampledFrame[] = [];
      for (let index = 0; index < times.length; index++) {
        const target = times[index];
        await waitForSeek(video, target);
        frames.push(await captureFrame(video, target, index + 1));
      }

      setReview({
        fileName: file.name,
        fileSha256: originalHash,
        metadata,
        sampledAt: new Date().toISOString(),
        frames,
      });
      setNotice('Local frame sampling complete. The file was not uploaded or sent to an external analysis service.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The video could not be inspected in this browser.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <SiteHeader status />
      <div className="container subpage local-review-page" id="main-content" tabIndex={-1}>
        <div className="eyebrow">LOCAL ANALYSIS / MEDIA</div>
        <h1>Inspect the <span>frames.</span></h1>
        <p className="lead">Read browser-decoded metadata, fingerprint the original video file, and sample a handful of representative frames without uploading the media.</p>

        <section className="form-panel local-review-intro" aria-labelledby="media-method-heading">
          <div className="panel-heading">
            <div><div className="panel-kicker">BOUNDED LOCAL PROCESSING</div><h2 id="media-method-heading">A video sample, not a forensic verdict</h2></div>
            <span className="safe-chip"><LockKeyhole size={14} /> NO FILE UPLOAD</span>
          </div>
          <div className="local-review-points">
            <div><ShieldCheck size={16} /><span>MP4/WebM only, 50 MiB and 120-second limits.</span></div>
            <div><Fingerprint size={16} /><span>Original file SHA-256 plus hashes of encoded sample previews.</span></div>
            <div><AlertTriangle size={16} /><span>Six frame samples cannot prove authenticity or detect all tampering.</span></div>
          </div>
        </section>

        <section className="form-panel" aria-labelledby="media-input-heading">
          <div className="panel-kicker">SUPPORTED INPUT</div>
          <h2 id="media-input-heading">Choose a video</h2>
          <p className="muted">The supported browser decoder must be able to read the clip. This feature does not inspect audio, run deepfake detection, transcribe speech or parse all container metadata.</p>
          <label className="field-label" htmlFor="media-file">Video file</label>
          <input id="media-file" type="file" accept="video/mp4,video/webm,.mp4,.webm" onChange={event => chooseFile(event.target.files?.[0] ?? null)} />
          {file && <div className="file-selection"><Video size={18} /><div><strong>{file.name}</strong><span>{(file.size / (1024 * 1024)).toFixed(2)} MiB · local preview</span></div><button type="button" className="btn btn-secondary" onClick={clear} disabled={busy}><RotateCcw size={14} /> Clear</button></div>}
          {objectUrl && <div className="local-video-preview"><video ref={videoRef} src={objectUrl} controls playsInline preload="metadata" onLoadedMetadata={handleMetadata} onError={() => setError('This browser cannot decode the selected video. Try a supported MP4 or WebM re-encoded with a browser-compatible codec.')} aria-label="Locally loaded video preview" /></div>}
          {metadata && (
            <div className="local-review-stats">
              <article className="local-review-stat"><span>DURATION</span><strong>{formatDuration(metadata.durationSeconds)}</strong></article>
              <article className="local-review-stat"><span>FRAME SIZE</span><strong>{metadata.width} × {metadata.height}</strong></article>
              <article className="local-review-stat"><span>FILE SIZE</span><strong>{(metadata.bytes / (1024 * 1024)).toFixed(2)} MiB</strong></article>
            </div>
          )}
          {error && <p className="error-message" role="alert">{error}</p>}
          {notice && <p className="success-message" role="status">{notice}</p>}
          <div className="actions">
            <button type="button" className="btn btn-primary" onClick={() => void inspect()} disabled={!file || !metadata?.withinLimits || busy}>
              <ScanSearch size={16} /> {busy ? 'Sampling frames locally…' : 'Inspect six representative frames'}
            </button>
            <span className="hint">The selected video is read via a local object URL; the page makes no remote media request.</span>
          </div>
        </section>

        {review && (
          <section className="form-panel" aria-labelledby="media-results-heading">
            <div className="panel-heading">
              <div><div className="panel-kicker">INSPECTION RESULTS</div><h2 id="media-results-heading">Sampled frame timeline</h2></div>
              <span className="safe-chip"><Activity size={14} /> {review.frames.length} LOCAL SAMPLES</span>
            </div>
            <div className="local-review-hash"><span><Fingerprint size={15} /> Original file SHA-256</span><code>{review.fileSha256}</code></div>
            <p className="hint">Each preview is an independently encoded JPEG sample. Its hash is a reproducible identifier for that preview—not a hash of the source video's original decoded frame or a proof of provenance.</p>
            <div className="media-frame-grid">
              {review.frames.map(frame => <article className="media-frame-card" key={frame.index}>
                <img src={frame.preview} alt={'Locally sampled video frame ' + frame.index + ' at ' + frame.timestampSeconds.toFixed(2) + ' seconds'} />
                <div className="media-frame-meta"><span>FRAME {String(frame.index).padStart(2, '0')}</span><strong>{frame.timestampSeconds.toFixed(2)} s</strong></div>
                <div className="media-luminance"><span>Mean preview luminance</span><strong>{frame.meanLuminance} / 255</strong></div>
                <code>SHA-256 {frame.sha256}</code>
              </article>)}
            </div>
            <div className="actions"><button type="button" className="btn btn-primary" onClick={() => exportSummary(review)}><Download size={15} /> Export summary (TXT)</button><button type="button" className="btn btn-secondary" onClick={() => setReview(null)}><RotateCcw size={15} /> Clear sample report</button></div>
          </section>
        )}

        <section className="sentinel-boundary" aria-label="Video review limitations">
          <div className="boundary-icon"><AlertTriangle size={19} /></div>
          <div><strong>Sampling is not authenticity verification.</strong><p>The page inspects selected still frames and browser-reported duration/dimensions. It does not verify signatures, detect all edits, analyze every frame, inspect audio or certify provenance. Mean luminance is a descriptive measurement only; no match or unusual metric is not evidence of maliciousness.</p></div>
          <a href="/tools#video">Capability status <span aria-hidden="true">↗</span></a>
        </section>
      </div>
    </main>
  );
}
