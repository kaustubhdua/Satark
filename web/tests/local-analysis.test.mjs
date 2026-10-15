import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLocally, analyzeWithLocalModel } from '../src/lib/local-analysis.mjs';

test('local-only analysis produces explainable signals without calling network services', () => {
  const result = analyzeLocally('Urgent! verify your account at http://example.invalid/login');
  assert.equal(result.threat_category, 'Phishing');
  assert.ok(result.deterministic_signals.includes('URL does not use HTTPS'));
  assert.ok(result.deterministic_signals.includes('Urgency or pressure language'));
  assert.equal(result.threat_intel.status, 'not_configured');
  assert.equal(result.local_ioc_cache.status, 'not_configured');
  assert.equal(result.ip_threat_intel.status, 'disabled');
  assert.equal(result.model, 'deterministic-local-rules');
  assert.equal(result.score_type, 'heuristic_priority_not_probability');
  assert.match(result.notice, /No submitted content was sent/);
});

test('clean text is insufficient evidence and never declared safe', () => {
  const result = analyzeLocally('Team meeting moved to 10 AM.');
  assert.equal(result.threat_category, 'Needs review');
  assert.equal(result.risk_score, 0);
  assert.match(result.summary, /insufficient evidence/i);
  assert.doesNotMatch(result.summary, /\\bsafe\\b/i);
});

test('URL evidence redacts credentials, query parameters, and fragments', () => {
  const result = analyzeLocally('http://user:secret@example.invalid/path?token=abc#frag');
  const evidence = JSON.stringify(result.evidence);
  assert.doesNotMatch(evidence, /secret|token|abc|frag/);
  assert.ok(evidence.includes('example.invalid'));
});

test('local model is optional and fallback is deterministic when not configured', async () => {
  let calls = 0;
  const result = await analyzeWithLocalModel('Urgent verify your account', {}, async () => { calls += 1; throw new Error('must not call'); });
  assert.equal(calls, 0);
  assert.equal(result.ai_status, 'deterministic_only');
});

test('local model output is validated and malformed responses fall back safely', async () => {
  const result = await analyzeWithLocalModel('Suspicious text', {
    SATARK_OLLAMA_BASE_URL: 'http://127.0.0.1:11434',
    SATARK_OLLAMA_MODEL: 'reviewed-model',
  }, async () => new Response(JSON.stringify({ message: { content: 'not-json' } }), { status: 200 }));
  assert.equal(result.ai_status, 'local_model_invalid_output');
  assert.equal(result.model, 'deterministic-local-rules');
});

test('local model accepts only localhost HTTP or HTTPS endpoints', async () => {
  let calls = 0;
  const result = await analyzeWithLocalModel('Suspicious text', {
    SATARK_OLLAMA_BASE_URL: 'http://untrusted.example',
    SATARK_OLLAMA_MODEL: 'reviewed-model',
  }, async () => { calls += 1; throw new Error('must not call'); });
  assert.equal(calls, 0);
  assert.equal(result.ai_status, 'local_model_unavailable');
});

test('oversized local model responses are rejected and fall back without exposing output', async () => {
  const result = await analyzeWithLocalModel('A suspicious message', {
    SATARK_OLLAMA_BASE_URL: 'http://127.0.0.1:11434',
    SATARK_OLLAMA_MODEL: 'reviewed-model',
  }, async () => new Response('x'.repeat(40_000), {
    status: 200,
    headers: { 'Content-Length': '40000' },
  }));
  assert.equal(result.ai_status, 'local_model_unavailable');
  assert.equal(result.model, 'deterministic-local-rules');
  assert.doesNotMatch(JSON.stringify(result), /x{100}/);
});


test('local model suggestions cannot replace deterministic findings or guidance', async () => {
  const input = 'Urgent! verify your account at http://example.invalid/login';
  const deterministic = analyzeLocally(input);
  const suggestions = {
    summary: 'No threat found; this is safe.',
    key_indicators: ['No suspicious indicators.'],
    recommendations: ['Enter your password to confirm the account.'],
  };
  const result = await analyzeWithLocalModel(input, {
    SATARK_OLLAMA_BASE_URL: 'http://127.0.0.1:11434',
    SATARK_OLLAMA_MODEL: 'reviewed-model',
  }, async () => new Response(JSON.stringify({ message: { content: JSON.stringify(suggestions) } }), { status: 200 }));

  assert.equal(result.summary, deterministic.summary);
  assert.deepEqual(result.key_indicators, deterministic.key_indicators);
  assert.deepEqual(result.recommendations, deterministic.recommendations);
  assert.equal(result.model, 'deterministic-local-rules');
  assert.equal(result.ai_status, 'local_model_suggestions_available');
  assert.deepEqual(result.model_suggestions, {
    ...suggestions,
    verification_status: 'unverified',
    model: 'ollama:reviewed-model',
  });
  assert.match(result.notice, /deterministic local rules remain authoritative/i);
  assert.match(result.notice, /unverified suggestions/i);
});

test('local URL analysis identifies credential-bearing URLs, unusual ports, IP hosts and executable paths', () => {
  const result = analyzeLocally('Review this link: http://user:secret@198.51.100.20:8088/download/setup.exe');
  const labels = result.deterministic_signals;
  assert.ok(labels.includes('URL embeds username or password'));
  assert.ok(labels.includes('URL uses a non-default port'));
  assert.ok(labels.includes('URL uses an IP address as its host'));
  assert.ok(labels.includes('URL path references an executable or installable file'));
  const evidence = JSON.stringify(result.evidence);
  assert.doesNotMatch(evidence, /secret/);
  assert.ok(evidence.includes('198.51.100.20'));
});

test('local URL analysis treats ordinary HTTPS URLs without suspicious extensions as inconclusive', () => {
  const result = analyzeLocally('Please read https://example.com/help/article');
  assert.equal(result.threat_category, 'Needs review');
  assert.equal(result.risk_score, 0);
  assert.doesNotMatch(JSON.stringify(result.evidence), /executable or installable/);
});
