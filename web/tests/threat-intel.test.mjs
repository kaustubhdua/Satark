import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isPublicIpAddress } from '../src/lib/public-ip.mjs';

const route = readFileSync(new URL('../src/app/api/analyze/route.ts', import.meta.url), 'utf8');
const page = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
const investigatePage = readFileSync(new URL('../src/app/investigate/page.tsx', import.meta.url), 'utf8');
const envExample = readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
const localAnalysis = readFileSync(new URL('../src/lib/local-analysis.mjs', import.meta.url), 'utf8');

test('local-only analysis is the default and does not require a provider API key', () => {
  assert.match(route, /analyzeWithLocalModel/);
  assert.match(route, /analyzeWithLocalModel\(input\.trim\(\)\)/);
  assert.match(localAnalysis, /deterministic-local-rules/);
  assert.match(page, /No third-party AI key is required/i);
  assert.match(investigatePage, /No third-party AI or reputation API is called in local-only mode/i);
  assert.doesNotMatch(page, /checked=\{shareWithThreatIntel\}/);
  assert.doesNotMatch(investigatePage, /checked=\{shareIpWithThreatIntel\}/);
});

test('local mode labels external reputation as disabled and never calls those services', () => {
  assert.match(localAnalysis, /External lookups are disabled in local-only mode/);
  assert.match(localAnalysis, /No submitted content was sent to a third-party AI or threat-intelligence API/);
  assert.match(localAnalysis, /No exact match in the currently fresh local cache\. This is not a safety verdict\./);
  assert.doesNotMatch(page, /Local threat-intelligence cache/);
  assert.match(investigatePage, /Local threat-intelligence cache/);
  assert.doesNotMatch(route, /api\.groq\.com|urlhaus-api\.abuse\.ch|api\.abuseipdb\.com/);
  assert.match(route, /analyzeWithLocalModel\(input\.trim\(\)\)/);
});

test('default environment has no third-party analysis provider keys', () => {
  assert.match(envExample, /SATARK_OLLAMA_BASE_URL/);
  assert.match(envExample, /SATARK_OLLAMA_MODEL/);
  assert.doesNotMatch(envExample, /GROQ_API_KEY|URLHAUS_AUTH_KEY|ABUSEIPDB_API_KEY/);
  assert.match(envExample, /UPSTASH_REDIS_REST_URL/);
  assert.match(envExample, /UPSTASH_REDIS_REST_TOKEN/);
  assert.doesNotMatch(route, /api\.groq\.com|urlhaus-api\.abuse\.ch|api\.abuseipdb\.com/);
});

test('URL and IP heuristics do not claim no-match means safe', () => {
  assert.match(localAnalysis, /insufficient evidence, not a safety verdict/);
  assert.match(localAnalysis, /A review signal only/);
  assert.match(localAnalysis, /isPublicIpAddress\(candidate\)/);
});

test('public IP helper rejects private and documentation addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1']) assert.equal(isPublicIpAddress(ip), true);
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.1.1', '203.0.113.9', '2001:db8::1']) {
    assert.equal(isPublicIpAddress(ip), false, ip);
  }
});

test('homepage routes into the focused analysis page and describes local-first processing', () => {
  assert.match(page, /No third-party AI key is required/i);
  assert.match(page, /href=\"\/investigate\"/);
  assert.doesNotMatch(page, /result\.notice|Local threat-intelligence cache/);
  assert.match(investigatePage, /No third-party AI or reputation API is called in local-only mode/i);
  assert.match(investigatePage, /result\.notice/);
});
