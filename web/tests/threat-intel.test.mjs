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
  assert.match(route, /SATARK_ANALYSIS_MODE \|\| 'local'/);
  assert.match(route, /analyzeWithLocalModel\(input\)/);
  assert.match(localAnalysis, /deterministic-local-rules/);
  assert.match(page, /local-only rules/i);
  assert.match(investigatePage, /local-only rules/i);
  assert.doesNotMatch(page, /checked=\{shareWithThreatIntel\}/);
  assert.doesNotMatch(investigatePage, /checked=\{shareIpWithThreatIntel\}/);
});

test('local mode labels external reputation as disabled and never calls those services', () => {
  assert.match(localAnalysis, /External lookups are disabled in local-only mode/);
  assert.match(localAnalysis, /No third-party AI or threat-intelligence API was called/);
  assert.match(route, /if \(\(process\.env\.SATARK_ANALYSIS_MODE \|\| 'local'\) === 'local'\)/);
  assert.ok(route.indexOf('analyzeWithLocalModel(input)') < route.indexOf("fetch('https://urlhaus-api.abuse.ch/v1/url/'"));
});

test('legacy URLhaus and AbuseIPDB paths require explicit non-default provider mode and opt-in', () => {
  assert.match(route, /SATARK_ENABLE_THREAT_INTEL !== 'true'/);
  assert.match(route, /SATARK_ENABLE_ABUSEIPDB !== 'true'/);
  assert.match(route, /URLHAUS_AUTH_KEY/);
  assert.match(route, /ABUSEIPDB_API_KEY/);
  assert.match(envExample, /SATARK_ANALYSIS_MODE=local/);
  assert.doesNotMatch(route, /NEXT_PUBLIC_ABUSEIPDB_API_KEY/);
  assert.doesNotMatch(route, /NEXT_PUBLIC_URLHAUS_AUTH_KEY/);
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

test('both investigation entry points disclose the local-only privacy model', () => {
  assert.match(page, /No third-party AI or reputation API is called in local-only mode/i);
  assert.match(investigatePage, /No third-party AI or reputation API is called in local-only mode/i);
  assert.match(page, /result\.notice/);
  assert.match(investigatePage, /result\.notice/);
});
