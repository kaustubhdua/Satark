// Inference for SATARK's trained models (see ml/ and docs/MODEL_CARDS.md). Dependency-free and
// bit-for-bit compatible with the Python reference (ml/train_*.py); parity is enforced by tests.
import urlModel from './models/url-host-v1.json' with { type: 'json' };
import messageModel from './models/message-v1.json' with { type: 'json' };
import emailModel from './models/email-v1.json' with { type: 'json' };

export const MODELS = { url: urlModel, message: messageModel, email: emailModel };

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

export function modelSummary() {
  return ['url', 'message', 'email'].map((k) => ({
    name: MODELS[k].name, trained_on: MODELS[k].training.phishing_source || MODELS[k].training.source,
    test_roc_auc: Number(MODELS[k].metrics.test_roc_auc.toFixed(3)),
    recall_at_high: Number(MODELS[k].metrics.at_high_threshold.recall.toFixed(3)),
    false_positive_rate_at_high: Number(MODELS[k].metrics.at_high_threshold.false_positive_rate.toFixed(4)),
  }));
}
