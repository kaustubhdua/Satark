import test from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIpAddress } from '../src/lib/public-ip.mjs';
import { readJsonWithinLimit } from '../src/lib/bounded-json.mjs';

test('AbuseIPDB lookups accept only public IP literals', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPublicIpAddress(ip), true, `${ip} should be accepted`);
  }
  for (const ip of [
    'not-an-ip', '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1',
    '169.254.1.1', '100.64.0.1', '192.0.2.1', '198.51.100.2',
    '203.0.113.9', '224.0.0.1', '255.255.255.255', '::1',
    'fc00::1', 'fe80::1', '2001:db8::1', '2001:100::1', '2001:0::1', '3fff::1', '2002:c000:0201::1',
  ]) {
    assert.equal(isPublicIpAddress(ip), false, `${ip} must not be queried`);
  }
});

import { readFileSync } from 'node:fs';

const config = readFileSync(new URL('../next.config.ts', import.meta.url), 'utf8');
const analyze = readFileSync(new URL('../src/app/api/analyze/route.ts', import.meta.url), 'utf8');
const reports = readFileSync(new URL('../src/app/reports/page.tsx', import.meta.url), 'utf8');
const firstlight = readFileSync(new URL('../src/app/firstlight/page.tsx', import.meta.url), 'utf8');
const securityFollowup = readFileSync(new URL('../docs/SECURITY_AND_UX_FOLLOWUP.md', import.meta.url), 'utf8');
const versionRoute = readFileSync(new URL('../src/app/api/version/route.ts', import.meta.url), 'utf8');
const homePage = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
const investigatePage = readFileSync(new URL('../src/app/investigate/page.tsx', import.meta.url), 'utf8');

test('baseline security headers and CSP directives are configured', () => {
  for (const header of ['X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Strict-Transport-Security', 'Content-Security-Policy']) {
    assert.match(config, new RegExp(header));
  }
  assert.match(config, /base-uri 'none'/);
  assert.match(config, /object-src 'none'/);
  assert.match(config, /frame-ancestors 'none'/);
  assert.match(config, /form-action 'self'/);
});

test('independent reputation lookups execute concurrently', () => {
  assert.match(analyze, /Promise\.all\(\[/);
  assert.match(analyze, /checkUrlhaus\(input, shareWithThreatIntel\)/);
  assert.match(analyze, /checkAbuseIpDb\(input, shareIpWithThreatIntel\)/);
});

test('reports exports only user-authored notes in TXT and versioned JSON', () => {
  assert.match(reports, /satark-review-notes\.txt/);
  assert.match(reports, /satark-review-notes\.json/);
  assert.match(reports, /schema_version: 1/);
  assert.match(reports, /No analysis results or provider evidence are automatically included/);
});

test('FIRSTLIGHT explicitly marks response actions as simulation only', () => {
  assert.match(firstlight, /SYNTHETIC/);
  assert.match(firstlight, /no real system action executed/);
  assert.match(firstlight, /does not inspect the endpoint or file/);
});


test('per-instance throttling does not trust spoofable x-forwarded-for', () => {
  assert.match(analyze, /request\.headers\.get\('x-real-ip'\)/);
  assert.doesNotMatch(analyze, /request\.headers\.get\('x-forwarded-for'\)\?\.split\(', '\)\[0\]/);
  assert.match(analyze, /all requests share[\s\S]*?'unknown' bucket/);
});

test('all API responses have an explicit no-store cache policy', () => {
  assert.match(config, /source: '\/api\/:path\*'/);
  assert.match(config, /key: 'Cache-Control', value: 'no-store'/);
});

test('analysis API rejects unsupported media types before parsing bodies', () => {
  assert.match(analyze, /contentType !== 'application\/json'/);
  assert.match(analyze, /Content-Type must be application\/json/);
  assert.match(analyze, /return error\('Content-Type must be application\/json\.', 415\)/);
});

test('URLhaus URL sanitizer strips query and fragment values before sharing', async () => {
  const { extractFirstHttpUrl } = await import('../src/lib/urlhaus-url.mjs');
  assert.equal(
    extractFirstHttpUrl('Please check https://example.test/path?token=secret&email=user%40example.test#session-id'),
    'https://example.test/path',
    'query parameters and fragments must not reach URLhaus',
  );
  assert.equal(
    extractFirstHttpUrl('https://example.test/path?x=1).'),
    'https://example.test/path',
    'trailing sentence punctuation must not be included in the lookup URL',
  );
  assert.equal(extractFirstHttpUrl('https://user:password@example.test/private'), null,
    'URLs containing embedded credentials must not be shared');
  assert.equal(extractFirstHttpUrl('No URL was supplied'), null);
  const investigate = readFileSync(new URL('../src/app/investigate/page.tsx', import.meta.url), 'utf8');
  assert.match(investigate, /query strings and fragments are removed first/);
  assert.match(investigate, /Paths can still contain private identifiers/);
});

test('URLhaus provider references cannot create off-site or unsafe links', async () => {
  const { safeUrlhausReference } = await import('../src/lib/urlhaus-url.mjs');
  assert.equal(safeUrlhausReference('https://urlhaus.abuse.ch/url/123456/'), 'https://urlhaus.abuse.ch/url/123456/');
  for (const value of [
    'javascript:alert(1)',
    'https://attacker.example/url/123456/',
    'http://urlhaus.abuse.ch/url/123456/',
    'https://urlhaus.abuse.ch.evil.example/url/123456/',
    'https://user@urlhaus.abuse.ch/url/123456/',
    'https://urlhaus.abuse.ch/redirect?to=https://attacker.example/',
    'not a URL',
    null,
  ]) {
    assert.equal(safeUrlhausReference(value), undefined, `unsafe provider reference rejected: ${String(value)}`);
  }
});


test('provider JSON responses are parsed within a strict byte budget', async () => {
  const response = new Response(JSON.stringify({ choices: [{ message: { content: '{"risk_score":25}' } }] }));
  assert.deepEqual(await readJsonWithinLimit(response, 1024), {
    choices: [{ message: { content: '{"risk_score":25}' } }],
  });
  await assert.rejects(
    readJsonWithinLimit(new Response('x'.repeat(1025)), 1024),
    /Provider response exceeded the allowed size/,
  );
  await assert.rejects(
    readJsonWithinLimit(new Response('{"partial":'), 1024),
    SyntaxError,
  );
  await assert.rejects(
    readJsonWithinLimit(new Response('{}'), 0),
    RangeError,
  );
});

test('analysis route uses the bounded provider response reader', () => {
  assert.match(analyze, /MAX_PROVIDER_RESPONSE_BYTES = 64 \* 1024/);
  assert.match(analyze, /readJsonWithinLimit\(upstream, MAX_PROVIDER_RESPONSE_BYTES\)/);
  assert.doesNotMatch(analyze, /await upstream\.json\(\)/);
});


test('all external provider JSON responses are read within a strict byte budget', () => {
  assert.equal((analyze.match(/readJsonWithinLimit\(response, MAX_THREAT_INTEL_RESPONSE_BYTES\)/g) || []).length, 2,
    'AbuseIPDB and URLhaus responses must both use the bounded reader');
  assert.match(analyze, /MAX_THREAT_INTEL_RESPONSE_BYTES = 32 \* 1024/);
  assert.doesNotMatch(analyze, /await response\.json\(\)/);
});


test('developer privacy notice matches URLhaus URL sanitization behavior', () => {
  assert.match(securityFollowup, /URLhaus receives the first extracted HTTP\(S\) URL only when the user checks the opt-in control/);
  assert.match(securityFollowup, /removes query strings and fragments before sharing/);
  assert.match(securityFollowup, /path can still contain identifiers or other sensitive data/);
  assert.doesNotMatch(securityFollowup, /including its path and query string/);
});


test('version endpoint exposes only a validated build SHA with no-store caching', () => {
  assert.match(versionRoute, /process\.env\.VERCEL_GIT_COMMIT_SHA/);
  assert.match(versionRoute, /\^\[0-9a-f\]\{40\}\$/);
  assert.match(versionRoute, /'Cache-Control': 'no-store'/);
  assert.doesNotMatch(versionRoute, /process\.env\.(?:GROQ_API_KEY|URLHAUS_AUTH_KEY|ABUSEIPDB_API_KEY)/);
});

test('production smoke check fails closed when deployment revision is stale', () => {
  const smoke = readFileSync(new URL('../../.github/workflows/production-smoke.yml', import.meta.url), 'utf8');
  assert.match(smoke, /api\/version/);
  assert.match(smoke, /deployed_sha.*expected_sha|deployed_sha.*current main/);
  assert.match(smoke, /Deployment is stale/);
});


test('analysis pages disclose AI provider data sharing', () => {
  assert.match(homePage, /text you submit is sent to Groq/i);
  assert.match(investigatePage, /full text is sent to Groq/i);
  assert.match(homePage, /separate optional lookups/i);
  assert.match(investigatePage, /separate optional lookups/i);
});

test('homepage URLhaus consent describes query and fragment removal', () => {
  assert.match(homePage, /query strings and fragments are removed first/);
  assert.match(homePage, /Paths can still contain private identifiers/);
  assert.doesNotMatch(homePage, /full extracted URL, including its path and query string, is shared/i);
});
