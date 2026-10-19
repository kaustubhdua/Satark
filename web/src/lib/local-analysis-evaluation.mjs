import { performance } from 'node:perf_hooks';
import { analyzeLocally } from './local-analysis.mjs';

function isGrounded(signal, input) {
  const evidence = typeof signal?.evidence === 'string' ? signal.evidence.trim() : '';
  if (!evidence || evidence === '[URL redacted]') return false;
  if (signal.category === 'url') {
    const hostname = evidence.match(/^https?:\/\/([^/]+)/i)?.[1]?.toLowerCase();
    return Boolean(hostname && input.toLowerCase().includes(hostname));
  }
  return input.toLowerCase().includes(evidence.toLowerCase());
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)];
}

const round = value => Number(value.toFixed(4));

/**
 * Evaluate only the deterministic local heuristic path on an explicitly labeled
 * synthetic corpus. Metrics describe this corpus, not real-world prevalence.
 */
export function evaluateLocalAnalysis(cases, analyzer = analyzeLocally) {
  if (!Array.isArray(cases) || cases.length === 0) {
    throw new TypeError('At least one evaluation case is required.');
  }
  const seen = new Set();
  const durations = [];
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  let groundedSignals = 0;
  let totalSignals = 0;

  const results = cases.map(item => {
    if (!item || typeof item.id !== 'string' || !item.id.trim()
      || typeof item.input !== 'string' || !item.input.trim()
      || !['benign', 'suspicious'].includes(item.label)) {
      throw new TypeError('Each case needs a unique id, non-empty input, and benign/suspicious label.');
    }
    if (seen.has(item.id)) throw new TypeError('Evaluation case IDs must be unique.');
    seen.add(item.id);

    const start = performance.now();
    const result = analyzer(item.input);
    const duration = performance.now() - start;
    durations.push(duration);
    const predicted = Number(result?.risk_score) > 0 || result?.threat_category !== 'Needs review';
    if (item.label === 'suspicious' && predicted) tp += 1;
    else if (item.label === 'suspicious' && !predicted) fn += 1;
    else if (item.label === 'benign' && predicted) fp += 1;
    else tn += 1;

    const evidence = Array.isArray(result?.evidence) ? result.evidence : [];
    totalSignals += evidence.length;
    for (const signal of evidence) if (isGrounded(signal, item.input)) groundedSignals += 1;

    return {
      id: item.id,
      expected: item.label,
      predicted: predicted ? 'suspicious' : 'benign',
      correct: predicted === (item.label === 'suspicious'),
      risk_score: Number(result?.risk_score) || 0,
      signal_count: evidence.length,
      grounded_signal_count: evidence.filter(signal => isGrounded(signal, item.input)).length,
      latency_ms: round(duration),
    };
  });

  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    corpus_version: 1,
    corpus_scope: 'Small synthetic smoke corpus; not representative of real-world prevalence.',
    sample_count: cases.length,
    confusion_matrix: { true_positive: tp, false_positive: fp, true_negative: tn, false_negative: fn },
    metrics: {
      accuracy: round((tp + tn) / cases.length),
      precision: round(precision),
      recall: round(recall),
      f1: round(f1),
      median_latency_ms: round(percentile(durations, 0.5)),
      p95_latency_ms: round(percentile(durations, 0.95)),
      evidence_grounding_ratio: round(totalSignals ? groundedSignals / totalSignals : 1),
    },
    evidence_grounding: { grounded_signals: groundedSignals, total_signals: totalSignals },
    false_positives: results.filter(item => item.expected === 'benign' && item.predicted === 'suspicious').map(item => item.id),
    false_negatives: results.filter(item => item.expected === 'suspicious' && item.predicted === 'benign').map(item => item.id),
    results,
    limitations: [
      'Labels are synthetic and selected for regression coverage, not sampled from real traffic.',
      'Metrics are specific to this small corpus and must not be represented as production detection rates.',
      'Risk scores are heuristic triage priorities, not calibrated probabilities.',
      'Evidence grounding checks signal excerpts or URL hostnames against the submitted input; it does not prove a signal is correct or the content is malicious.',
    ],
  };
}
