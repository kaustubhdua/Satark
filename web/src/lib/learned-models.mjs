// Inference for SATARK's trained models (see ml/ and docs/MODEL_CARDS.md). Dependency-free and
// bit-for-bit compatible with the Python reference (ml/train_*.py); parity is enforced by tests.
import urlModel from './models/url-host-v1.json' with { type: 'json' };
import messageModel from './models/message-v1.json' with { type: 'json' };
import emailModel from './models/email-v1.json' with { type: 'json' };
import pdfModel from './models/pdf-v1.json' with { type: 'json' };
import imageModel from './models/image-v1.json' with { type: 'json' };

export const MODELS = { url: urlModel, message: messageModel, email: emailModel, pdf: pdfModel, image: imageModel };

// Messages shorter than this are scored by the SMS model, longer ones by the email model.
export const EMAIL_MIN_CHARS = 300;

const bucket = (n, edges) => { for (let i = 0; i < edges.length; i += 1) if (n <= edges[i]) return i; return edges.length; };
const codePoints = (s) => Array.from(s);

export function hostDoc(host) {
  const labels = host.split('.');
  const digits = [...host].filter((c) => c >= '0' && c <= '9').length;
  const hyphens = host.split('-').length - 1;
  const toks = [
    '@len' + bucket(host.length, [8, 12, 16, 20, 25, 32, 45]),
    '@labels' + Math.min(labels.length, 6),
    '@digits' + bucket(digits / Math.max(host.length, 1), [0, 0.1, 0.25, 0.5]),
    '@hyph' + Math.min(hyphens, 4),
    '@tld_' + labels[labels.length - 1],
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? '@ip' : '@noip',
  ];
  return '^' + host + '$ ' + toks.join(' ');
}

export function hostTokens(doc) {
  const space = doc.indexOf(' ');
  const main = codePoints(space < 0 ? doc : doc.slice(0, space));
  const rest = space < 0 ? '' : doc.slice(space + 1);
  const out = new Set();
  for (let n = 3; n <= 5; n += 1) for (let i = 0; i + n <= main.length; i += 1) out.add('c' + main.slice(i, i + n).join(''));
  for (const w of rest.split(' ')) if (w) out.add(w);
  return out;
}

export function messageTokens(text) {
  const t = text.toLowerCase();
  const out = new Set();
  const words = t.replace(/https?:\/\/\S+|www\.\S+/g, ' ').match(/[a-z0-9']+/g) || [];
  words.forEach((w, i) => {
    out.add('w' + w);
    if (i + 1 < words.length) out.add('b' + w + ' ' + words[i + 1]);
  });
  if (/https?:\/\/|www\./.test(t)) out.add('@url');
  if (/\b\d{5,}\b/.test(t)) out.add('@longnum');
  if (/[£$€]\s?\d|\d\s?(?:p|usd|gbp|eur)\b/.test(t)) out.add('@money');
  const letters = [...text].filter((c) => /\p{L}/u.test(c));
  if (letters.length && letters.filter((c) => /\p{Lu}/u.test(c)).length / letters.length > 0.3) out.add('@shouty');
  out.add('@len' + Math.min(Math.floor(codePoints(text).length / 40), 6));
  return out;
}

function decide(model, tokens) {
  let score = model.bias;
  for (const t of tokens) { const w = model.weights[t]; if (w !== undefined) score += w; }
  const band = score >= model.thresholds.high ? 'high' : score >= model.thresholds.elevated ? 'elevated' : 'low';
  return { score, band };
}

export function scoreHost(rawHost) {
  let host = String(rawHost || '').toLowerCase().replace(/\.$/, '');
  if (host.startsWith('www.')) host = host.slice(4);
  if (!host || host.length > 253 || !/^[a-z0-9._-]+$/.test(host)) return null;
  return decide(MODELS.url, hostTokens(hostDoc(host)));
}

export function scoreMessage(text) {
  const input = String(text || '');
  if (!input.trim()) return null;
  if (codePoints(input.trim()).length >= EMAIL_MIN_CHARS) {
    // Same tokenizer as the SMS model; the email model was trained on the first 3,000 characters.
    const clipped = codePoints(input.trim()).slice(0, MODELS.email.max_chars).join('');
    return { ...decide(MODELS.email, messageTokens(clipped)), model: 'email' };
  }
  return { ...decide(MODELS.message, messageTokens(input)), model: 'message' };
}

export function pdfTokens(stats) {
  const out = new Set();
  const num = (v, def = -1) => (typeof v === 'number' && Number.isFinite(v) ? v : def);
  const pdfsizeKb = num(stats.pdfsizeKb);
  const pages = num(stats.pages);
  const isEncrypted = num(stats.isEncrypted, 0);
  const obj = num(stats.obj);
  const endobj = num(stats.endobj);
  const stream = num(stats.stream);
  const endstream = num(stats.endstream);
  const xref = num(stats.xref);
  const trailer = num(stats.trailer);
  const startxref = num(stats.startxref);
  const objstm = num(stats.objstm, 0);
  const js = num(stats.js, 0);
  const javascript = num(stats.javascript, 0);
  const aa = num(stats.aa, 0);
  const openaction = num(stats.openaction, 0);
  const acroform = num(stats.acroform, 0);
  const jbig2 = num(stats.jbig2, 0);
  const richmedia = num(stats.richmedia, 0);
  const launch = num(stats.launch, 0);
  const embeddedfile = num(stats.embeddedfile, 0);
  const xfa = num(stats.xfa, 0);

  if (pdfsizeKb >= 0) out.add('@size' + bucket(pdfsizeKb, [10, 30, 80, 250, 1000]));
  if (pages >= 0) out.add('@pages' + bucket(pages, [0, 1, 2, 5, 15]));
  if (isEncrypted > 0) out.add('@encrypted');
  if (obj >= 0) out.add('@obj' + bucket(obj, [10, 25, 60, 150, 500]));
  if (stream >= 0) out.add('@stream' + bucket(stream, [2, 6, 15, 40, 150]));
  if (obj >= 0 && endobj >= 0 && Math.abs(obj - endobj) > 1) out.add('@obj_mismatch');
  if (stream >= 0 && endstream >= 0 && Math.abs(stream - endstream) > 1) out.add('@stream_mismatch');
  if (xref === 0) out.add('@no_xref');
  if (trailer === 0) out.add('@no_trailer');
  if (startxref === 0) out.add('@no_startxref');
  if (objstm > 0) out.add('@objstm');
  if (js > 0 || javascript > 0) out.add('@js');
  if (js + Math.max(javascript, 0) > 1) out.add('@js_multi');
  if (aa > 0) out.add('@aa');
  if (openaction > 0) out.add('@openaction');
  if (acroform > 0) out.add('@acroform');
  if (jbig2 > 0) out.add('@jbig2');
  if (richmedia > 0) out.add('@richmedia');
  if (launch > 0) out.add('@launch');
  if (embeddedfile > 0) out.add('@embedded');
  if (xfa > 0) out.add('@xfa');
  return out;
}

export function extractPdfStats(bytes, pages = -1) {
  const raw = new TextDecoder('latin1').decode(bytes);
  const count = (re) => (raw.match(re) || []).length;
  return {
    pdfsizeKb: bytes.byteLength / 1024,
    pages,
    isEncrypted: count(/\/Encrypt\b/g),
    obj: count(/\b\d+\s+\d+\s+obj\b/g),
    endobj: count(/\bendobj\b/g),
    stream: count(/\bstream\b/g),
    endstream: count(/\bendstream\b/g),
    xref: count(/\bxref\b/g),
    trailer: count(/\btrailer\b/g),
    startxref: count(/\bstartxref\b/g),
    objstm: count(/\/ObjStm\b/g),
    js: count(/\/JS\b/g),
    javascript: count(/\/JavaScript\b/g),
    aa: count(/\/AA\b/g),
    openaction: count(/\/OpenAction\b/g),
    acroform: count(/\/AcroForm\b/gi),
    jbig2: count(/\/JBIG2Decode\b/g),
    richmedia: count(/\/RichMedia\b/g),
    launch: count(/\/Launch\b/gi),
    embeddedfile: count(/\/EmbeddedFile\b/g),
    xfa: count(/\/XFA\b/g),
  };
}

export function scorePdf(stats) {
  if (!stats || typeof stats !== 'object') return null;
  const tokens = pdfTokens(stats);
  if (!tokens.size) return null;
  return { ...decide(MODELS.pdf, tokens), model: 'pdf' };
}

export function imageTokens(stats) {
  const out = new Set();
  const width = Number(stats.width || 0);
  const height = Number(stats.height || 0);
  out.add('@ela_m' + bucket(Number(stats.elaMean || 0), [2.0, 4.5, 8.0, 14.0]));
  out.add('@ela_s' + bucket(Number(stats.elaStd || 0), [2.5, 5.0, 9.0, 15.0]));
  out.add('@ela_h' + bucket(Number(stats.elaHighRatio || 0), [0.01, 0.05, 0.15, 0.35]));
  out.add('@lap_m' + bucket(Number(stats.lapMean || 0), [6.0, 14.0, 26.0, 45.0]));
  out.add('@lap_s' + bucket(Number(stats.lapStd || 0), [8.0, 18.0, 32.0, 55.0]));
  out.add('@flat' + bucket(Number(stats.flatRatio || 0), [0.05, 0.18, 0.40, 0.70]));
  out.add('@sat' + bucket(Number(stats.satMean || 0), [0.15, 0.30, 0.50, 0.72]));
  if (width > 0 && width === height) out.add('@square');
  if ([512, 768, 1024, 1536, 2048].includes(width) || [512, 768, 1024, 1536, 2048].includes(height)) out.add('@pow2_dim');
  if (Math.max(width, height) >= 1600) out.add('@high_res');
  else if (Math.max(width, height) > 0 && Math.max(width, height) <= 600) out.add('@low_res');
  return out;
}

export function scoreImage(stats) {
  if (!stats || typeof stats !== 'object') return null;
  return { ...decide(MODELS.image, imageTokens(stats)), model: 'image' };
}

export function modelSummary() {
  return ['url', 'message', 'email', 'pdf', 'image'].map((k) => ({
    name: MODELS[k].name, trained_on: MODELS[k].training.phishing_source || MODELS[k].training.source,
    test_roc_auc: Number(MODELS[k].metrics.test_roc_auc.toFixed(3)),
    recall_at_high: Number(MODELS[k].metrics.at_high_threshold.recall.toFixed(3)),
    false_positive_rate_at_high: Number(MODELS[k].metrics.at_high_threshold.false_positive_rate.toFixed(4)),
  }));
}
