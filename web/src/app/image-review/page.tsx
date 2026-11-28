'use client';

import SiteHeader from '../site-header';
import ServiceReadiness from '../../components/service-readiness';
import { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { scoreHost, scoreImage } from '../../lib/learned-models.mjs';

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_PIXELS = 40_000_000;
const ACCEPTED_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);

type ImageInspection = {
  name: string;
  mime: string;
  bytes: number;
  width: number;
  height: number;
  sha256: string;
  lastModified: string;
  metadataHints: string[];
  elaMean: number;
  elaStd: number;
  lapMean: number;
  flatRatio: number;
  elaPreview: string;
  modelResult: { band: string; score: number } | null;
  qrPayload: string | null;
  qrHostBand: string | null;
};

async function analyzeImageForensics(bitmap: ImageBitmap, width: number, height: number) {
  const grid = 128;
  const c1 = document.createElement('canvas');
  c1.width = grid;
  c1.height = grid;
  const ctx1 = c1.getContext('2d');
  if (!ctx1) return null;
  ctx1.drawImage(bitmap, 0, 0, grid, grid);
  const orig = ctx1.getImageData(0, 0, grid, grid).data;

  // Re-compress at JPEG quality 0.90 for Error Level Analysis (ELA)
  const jpegUrl = c1.toDataURL('image/jpeg', 0.9);
  const recompImg = await new Promise<HTMLImageElement>((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('ELA recompression failed'));
    img.src = jpegUrl;
  });
  const c2 = document.createElement('canvas');
  c2.width = grid;
  c2.height = grid;
  const ctx2 = c2.getContext('2d');
  if (!ctx2) return null;
  ctx2.drawImage(recompImg, 0, 0, grid, grid);
  const recomp = ctx2.getImageData(0, 0, grid, grid).data;

  const elaOut = ctx2.createImageData(grid, grid);
  const lum = new Float32Array(grid * grid);
  let elaSum = 0;
  let elaSq = 0;
  let elaHighCount = 0;
  let satSum = 0;
  const totalPx = grid * grid;

  for (let i = 0; i < totalPx; i++) {
    const idx = i * 4;
    const r1 = orig[idx], g1 = orig[idx + 1], b1 = orig[idx + 2];
    const dr = Math.abs(r1 - recomp[idx]);
    const dg = Math.abs(g1 - recomp[idx + 1]);
    const db = Math.abs(b1 - recomp[idx + 2]);
    const pxMean = (dr + dg + db) / 3;
    if (pxMean > 12) elaHighCount++;
    for (const d of [dr, dg, db]) {
      elaSum += d;
      elaSq += d * d;
    }
    elaOut.data[idx] = Math.min(255, dr * 10);
    elaOut.data[idx + 1] = Math.min(255, dg * 10);
    elaOut.data[idx + 2] = Math.min(255, db * 10);
    elaOut.data[idx + 3] = 255;

    lum[i] = 0.299 * r1 + 0.587 * g1 + 0.114 * b1;
    const cmax = Math.max(r1, g1, b1);
    const cmin = Math.min(r1, g1, b1);
    satSum += cmax > 0 ? (cmax - cmin) / cmax : 0;
  }

  ctx2.putImageData(elaOut, 0, 0);
  const elaPreview = c2.toDataURL('image/png');
  const elaN = totalPx * 3;
  const elaMean = elaSum / elaN;
  const elaStd = Math.sqrt(Math.max(0, elaSq / elaN - elaMean * elaMean));
  const elaHighRatio = elaHighCount / totalPx;
  const satMean = satSum / totalPx;

  let lapSum = 0;
  let lapSq = 0;
  let lapN = 0;
  for (let y = 1; y < grid - 1; y++) {
    for (let x = 1; x < grid - 1; x++) {
      const i = y * grid + x;
      const v = Math.abs(4 * lum[i] - lum[i - grid] - lum[i + grid] - lum[i - 1] - lum[i + 1]);
      lapSum += v;
      lapSq += v * v;
      lapN++;
    }
  }
  const lapMean = lapSum / Math.max(1, lapN);
  const lapStd = Math.sqrt(Math.max(0, lapSq / Math.max(1, lapN) - lapMean * lapMean));

  let flatCount = 0;
  const dxTotal = grid * (grid - 1);
  for (let y = 0; y < grid; y++) {
    for (let x = 0; x < grid - 1; x++) {
      if (Math.abs(lum[y * grid + x + 1] - lum[y * grid + x]) < 2.0) flatCount++;
    }
  }
  const flatRatio = flatCount / dxTotal;

  // Bounded QR scan on up to 720px canvas
  let qrPayload: string | null = null;
  let qrHostBand: string | null = null;
  const scale = Math.min(1, 720 / Math.max(width, height));
  const qw = Math.max(1, Math.round(width * scale));
  const qh = Math.max(1, Math.round(height * scale));
  const qc = document.createElement('canvas');
  qc.width = qw;
  qc.height = qh;
  const qctx = qc.getContext('2d');
  if (qctx) {
    qctx.drawImage(bitmap, 0, 0, qw, qh);
    const qdata = qctx.getImageData(0, 0, qw, qh);
    const decoded = jsQR(qdata.data, qw, qh);
    if (decoded?.data) {
      qrPayload = decoded.data.slice(0, 300);
      try {
        const u = new URL(decoded.data);
        const scored = scoreHost(u.hostname);
        if (scored) qrHostBand = scored.band;
      } catch {
        // non-URL QR payload
      }
    }
  }

  const modelResult = scoreImage({
    width,
    height,
    elaMean,
    elaStd,
    elaHighRatio,
    lapMean,
    lapStd,
    flatRatio,
    satMean,
  });

  return {
    elaMean,
    elaStd,
    lapMean,
    flatRatio,
    elaPreview,
    modelResult,
    qrPayload,
    qrHostBand,
  };
}

function hex(bytes: ArrayBuffer) {
  return Array.from(new Uint8Array(bytes)).map(value => value.toString(16).padStart(2, '0')).join('');
}

function ascii(bytes: Uint8Array, start: number, length: number) {
  return String.fromCharCode(...bytes.slice(start, start + length));
}

function u16be(bytes: Uint8Array, offset: number) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function u32be(bytes: Uint8Array, offset: number) {
  return (bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
}

function headerDimensions(bytes: Uint8Array, mime: string): { width: number; height: number } | null {
  if (mime === 'image/png' && bytes.length >= 24 && ascii(bytes, 1, 3) === 'PNG') {
    return { width: u32be(bytes, 16), height: u32be(bytes, 20) };
  }
  if (mime === 'image/gif' && bytes.length >= 10 && ascii(bytes, 0, 3) === 'GIF') {
    return { width: bytes[6] | (bytes[7] << 8), height: bytes[8] | (bytes[9] << 8) };
  }
  if (mime === 'image/webp' && bytes.length >= 30 && ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 4) === 'WEBP') {
    const kind = ascii(bytes, 12, 4);
    if (kind === 'VP8X') {
      return {
        width: 1 + bytes[24] + (bytes[25] << 8) + (bytes[26] << 16),
        height: 1 + bytes[27] + (bytes[28] << 8) + (bytes[29] << 16),
      };
    }
    if (kind === 'VP8 ' && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a) {
      return {
        width: ((bytes[26] | (bytes[27] << 8)) & 0x3fff),
        height: ((bytes[28] | (bytes[29] << 8)) & 0x3fff),
      };
    }
    if (kind === 'VP8L' && bytes[20] === 0x2f) {
      return {
        width: 1 + bytes[21] + ((bytes[22] & 0x3f) << 8),
        height: 1 + ((bytes[22] & 0xc0) >> 6) + (bytes[23] << 2) + ((bytes[24] & 0x0f) << 10),
      };
    }
  }
  if (mime === 'image/jpeg' && bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8) {
    let offset = 2;
    while (offset + 4 < bytes.length && bytes[offset] === 0xff) {
      const marker = bytes[offset + 1];
      if (marker === 0xd9 || marker === 0xda) break;
      const length = u16be(bytes, offset + 2);
      if (length < 2 || offset + 2 + length > bytes.length) break;
      if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker) && length >= 7) {
        return { height: u16be(bytes, offset + 5), width: u16be(bytes, offset + 7) };
      }
      offset += 2 + length;
    }
  }
  return null;
}

function metadataHints(bytes: Uint8Array, mime: string) {
  const hints: string[] = [];
  if (mime === 'image/jpeg') {
    let offset = 2;
    while (offset + 4 <= bytes.length && bytes[offset] === 0xff) {
      const marker = bytes[offset + 1];
      if (marker === 0xd9 || marker === 0xda) break;
      const length = u16be(bytes, offset + 2);
      if (length < 2 || offset + 2 + length > bytes.length) break;
      if (marker === 0xe1) hints.push(ascii(bytes, offset + 4, Math.min(6, length - 2)) === 'Exif\0\0' ? 'EXIF metadata marker present' : 'JPEG APP1 metadata segment present');
      if (marker === 0xed) hints.push('Photoshop/IPTC APP13 metadata segment present');
      if (marker === 0xe2) hints.push('ICC profile or APP2 metadata segment present');
      if (marker === 0xfe) hints.push('JPEG comment segment present');
      offset += 2 + length;
    }
  } else if (mime === 'image/png' && bytes.length >= 8 && ascii(bytes, 1, 3) === 'PNG') {
    let offset = 8;
    while (offset + 12 <= bytes.length) {
      const length = u32be(bytes, offset);
      if (length > bytes.length || offset + 12 + length > bytes.length) break;
      const kind = ascii(bytes, offset + 4, 4);
      if (kind === 'eXIf') hints.push('PNG EXIF metadata chunk present');
      if (['tEXt', 'iTXt', 'zTXt'].includes(kind)) hints.push('PNG text metadata chunk present');
      if (kind === 'iCCP') hints.push('PNG ICC color profile present');
      offset += 12 + length;
      if (kind === 'IEND') break;
    }
  } else if (mime === 'image/webp' && bytes.length >= 12 && ascii(bytes, 8, 4) === 'WEBP') {
    for (let offset = 12; offset + 8 <= bytes.length;) {
      const kind = ascii(bytes, offset, 4);
      const length = bytes[offset + 4] | (bytes[offset + 5] << 8) | (bytes[offset + 6] << 16) | (bytes[offset + 7] << 24);
      if (length < 0 || offset + 8 + length > bytes.length) break;
      if (kind === 'EXIF') hints.push('WebP EXIF metadata chunk present');
      if (kind === 'XMP ') hints.push('WebP XMP metadata chunk present');
      if (kind === 'ICCP') hints.push('WebP ICC color profile present');
      offset += 8 + length + (length % 2);
    }
  } else if (mime === 'image/gif') {
    for (let offset = 0; offset + 1 < bytes.length; offset += 1) {
      if (bytes[offset] === 0x21 && bytes[offset + 1] === 0xfe) {
        hints.push('GIF comment extension present');
        break;
      }
    }
  }
  return [...new Set(hints)].slice(0, 8);
}

export default function ImageReviewPage() {
  const [inspection, setInspection] = useState<ImageInspection | null>(null);
  const [preview, setPreview] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const previewRef = useRef('');

  useEffect(() => () => {
    if (previewRef.current) URL.revokeObjectURL(previewRef.current);
  }, []);

  async function inspectFile(file?: File) {
    setError('');
    setCopied(false);
    setInspection(null);
    if (previewRef.current) URL.revokeObjectURL(previewRef.current);
    previewRef.current = '';
    setPreview('');
    if (!file) return;
    if (!ACCEPTED_TYPES.has(file.type)) {
      setError('Choose a JPEG, PNG, WebP, or GIF image. AVIF, SVG and unknown file types are not supported.');
      return;
    }
    if (file.size <= 0 || file.size > MAX_FILE_BYTES) {
      setError('Image must be between 1 byte and 10 MiB.');
      return;
    }

    setBusy(true);
    try {
      const raw = await file.arrayBuffer();
      const bytes = new Uint8Array(raw);
      const dimensions = headerDimensions(bytes, file.type);
      if (!dimensions) throw new Error('Could not safely read dimensions from this file header. Use a supported JPEG, PNG, GIF, or WebP image.');
      if (dimensions.width <= 0 || dimensions.height <= 0 || dimensions.width * dimensions.height > MAX_PIXELS) {
        throw new Error('Image dimensions are invalid or exceed the 40-megapixel safety limit.');
      }
      const bitmap = await createImageBitmap(file);
      try {
        if (bitmap.width <= 0 || bitmap.height <= 0 || bitmap.width * bitmap.height > MAX_PIXELS) {
          throw new Error('Image dimensions exceed the 40-megapixel safety limit.');
        }
        const digest = hex(await crypto.subtle.digest('SHA-256', raw));
        const forensics = await analyzeImageForensics(bitmap, bitmap.width, bitmap.height);
        const objectUrl = URL.createObjectURL(file);
        previewRef.current = objectUrl;
        setPreview(objectUrl);
        setInspection({
          name: file.name.slice(0, 180),
          mime: file.type,
          bytes: file.size,
          width: bitmap.width,
          height: bitmap.height,
          sha256: digest,
          lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : 'Unknown',
          metadataHints: metadataHints(bytes, file.type),
          elaMean: forensics?.elaMean ?? 0,
          elaStd: forensics?.elaStd ?? 0,
          lapMean: forensics?.lapMean ?? 0,
          flatRatio: forensics?.flatRatio ?? 0,
          elaPreview: forensics?.elaPreview ?? '',
          modelResult: forensics?.modelResult ?? null,
          qrPayload: forensics?.qrPayload ?? null,
          qrHostBand: forensics?.qrHostBand ?? null,
        });
      } finally {
        bitmap.close();
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not inspect this image in your browser.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <SiteHeader />
      <div className="container subpage" id="main-content" tabIndex={-1}>
        <ServiceReadiness />
        <div className="eyebrow">Image review</div>
        <h1>Inspect the image. Keep the file local.</h1>
        <p className="lead">Review image dimensions, basic metadata markers, and a SHA-256 fingerprint directly in your browser. No file upload or third-party image API is used.</p>
        <div className="notice-panel">
          <strong>Scope and limits</strong>
          <p>This is a metadata and integrity review, not a deepfake detector or proof of authenticity. Metadata can be removed, edited, or forged; a matching hash proves only that two byte sequences are identical.</p>
        </div>
        <section className="form-panel" aria-labelledby="image-upload-title">
          <h2 id="image-upload-title">Choose an image</h2>
          <p className="field-note">Supported: JPEG, PNG, WebP, and GIF · Maximum file size 10 MiB · Maximum decoded dimensions 40 megapixels.</p>
          <label htmlFor="image-file">Image file</label>
          <input id="image-file" type="file" accept="image/jpeg,image/png,image/webp,image/gif"
            onChange={event => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void inspectFile(file); }}
            disabled={busy} />
          <p className="hint">The file is read in this browser tab only. It is not sent to SATARK servers, stored in browser history, or saved to session storage.</p>
          {busy && <div className="analysis-progress" role="status">Reading image headers, decoding within the size limit, and calculating SHA-256…</div>}
          {error && <div className="result error" role="alert">{error}</div>}
        </section>
        {inspection && <section className="analysis-result" aria-live="polite" aria-labelledby="image-result-title">
          <div className="result-top"><span className="pill">Local review</span><strong id="image-result-title">Image inspection complete</strong></div>
          <div className="workspace-grid">
            <div className="info-panel">
              <h3>Preview</h3>
              {preview && <img className="image-preview" src={preview} alt={'Local preview of ' + inspection.name} loading="lazy" decoding="async" />}
            </div>
            <div className="info-panel">
              <h3>File facts</h3>
              <p><strong>Name:</strong> {inspection.name}</p>
              <p><strong>Format:</strong> {inspection.mime}</p>
              <p><strong>Size:</strong> {(inspection.bytes / 1024).toFixed(1)} KiB</p>
              <p><strong>Dimensions:</strong> {inspection.width} × {inspection.height} pixels</p>
              <p><strong>Pixel count:</strong> {(inspection.width * inspection.height).toLocaleString()}</p>
              <p><strong>Last modified:</strong> {inspection.lastModified}</p>
            </div>
          </div>
          <h3>SHA-256 fingerprint</h3>
          <p className="field-note hash-value">{inspection.sha256}</p>
          <button className="btn btn-secondary" onClick={() => {
            if (!navigator.clipboard?.writeText) {
              setError('Clipboard access is unavailable. Select and copy the fingerprint manually.');
              return;
            }
            void navigator.clipboard.writeText(inspection.sha256)
              .then(() => setCopied(true))
              .catch(() => setError('Clipboard access was blocked. Select and copy the fingerprint manually.'));
          }}>{copied ? 'Fingerprint copied' : 'Copy fingerprint'}</button>
          <h3>Metadata marker hints</h3>
          {inspection.metadataHints.length > 0
            ? <ul>{inspection.metadataHints.map(hint => <li key={hint}>{hint}</li>)}</ul>
            : <p>No common metadata marker was detected by this lightweight parser. This does not prove the image contains no metadata.</p>}
          <p className="hint">Metadata marker detection is best-effort and does not extract every tag or validate the image's origin.</p>
          <h3>Forensic &amp; trained-model advisory (satark-image-v1)</h3>
          <div className="workspace-grid">
            <div className="info-panel">
              <p><strong>Synthetic / forensic band:</strong> {inspection.modelResult ? inspection.modelResult.band.toUpperCase() : 'Unavailable'}</p>
              <p><strong>Error Level Analysis (ELA mean / std):</strong> {inspection.elaMean.toFixed(2)} / {inspection.elaStd.toFixed(2)}</p>
              <p><strong>High-frequency edge residual:</strong> {inspection.lapMean.toFixed(2)}</p>
              <p><strong>Flat-region ratio:</strong> {(inspection.flatRatio * 100).toFixed(1)}%</p>
              <p className="hint">Advisory signal trained on open-source AI-vs-Real image forensics (ELA + Laplacian + flatness). Not a standalone authenticity proof.</p>
            </div>
            {inspection.elaPreview && (
              <div className="info-panel">
                <p><strong>Error Level Analysis (10x residual map)</strong></p>
                <img className="image-preview" src={inspection.elaPreview} alt={'Error Level Analysis map for ' + inspection.name} />
              </div>
            )}
          </div>
          {inspection.qrPayload && (
            <div className="notice-panel" style={{ marginTop: '12px' }}>
              <strong>Embedded QR code detected</strong>
              <p>Decoded payload: <code>{inspection.qrPayload}</code>{inspection.qrHostBand ? ` · URL host risk: ${inspection.qrHostBand.toUpperCase()}` : ''}</p>
            </div>
          )}
        </section>}
      </div>
    </main>
  );
}
