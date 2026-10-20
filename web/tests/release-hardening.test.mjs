import test from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIpAddress } from '../src/lib/public-ip.mjs';
import { readJsonWithinLimit } from '../src/lib/bounded-json.mjs';

test('AbuseIPDB lookups accept only public IP literals', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2001:4860:4860::8888', '2001:4860:0000:0000::8888']) {
    assert.equal(isPublicIpAddress(ip), true, `${ip} should be accepted`);
  }
  for (const ip of [
    'not-an-ip', '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1',
    '169.254.1.1', '100.64.0.1', '192.0.2.1', '198.51.100.2',
    '203.0.113.9', '224.0.0.1', '255.255.255.255', '::1',
    'fc00::1', 'fe80::1', '2001:db8::1', '2001:0db8::1', '2001:0000::1',
    '2001:100::1', '2001:0::1', '3fff::1', '2002:c000:0201::1',
  ]) {
    assert.equal(isPublicIpAddress(ip), false, `${ip} must not be queried`);
  }
});

import { readFileSync } from 'node:fs';

const config = readFileSync(new URL('../next.config.ts', import.meta.url), 'utf8');
const securityHeaders = readFileSync(new URL('../src/lib/security-headers.mjs', import.meta.url), 'utf8');
const analyze = readFileSync(new URL('../src/app/api/analyze/route.ts', import.meta.url), 'utf8');
const rateLimit = readFileSync(new URL('../src/lib/rate-limit.mjs', import.meta.url), 'utf8');
const reports = readFileSync(new URL('../src/app/reports/page.tsx', import.meta.url), 'utf8');
const firstlight = readFileSync(new URL('../src/app/firstlight/page.tsx', import.meta.url), 'utf8');
const securityFollowup = readFileSync(new URL('../docs/SECURITY_AND_UX_FOLLOWUP.md', import.meta.url), 'utf8');
const versionRoute = readFileSync(new URL('../src/app/api/version/route.ts', import.meta.url), 'utf8');
const homePage = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
const investigatePage = readFileSync(new URL('../src/app/investigate/page.tsx', import.meta.url), 'utf8');

test('baseline security headers and CSP directives are configured', () => {
  for (const header of ['X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Strict-Transport-Security', 'Content-Security-Policy']) {
    assert.match(securityHeaders, new RegExp(header));
  }
  assert.match(securityHeaders, /base-uri 'none'/);
  assert.match(securityHeaders, /object-src 'none'/);
  assert.match(securityHeaders, /frame-ancestors 'none'/);
  assert.match(securityHeaders, /form-action 'self'/);
});

test('CSP allows the configured Supabase auth origin without broad external access', async () => {
  const { buildSecurityHeaders, supabaseConnectOrigin } = await import('../src/lib/security-headers.mjs');
  const production = buildSecurityHeaders({
    NODE_ENV: 'production',
    NEXT_PUBLIC_SUPABASE_URL: 'https://igqgtlmnwssjaoxkkzbm.supabase.co',
  }).find(header => header.key === 'Content-Security-Policy').value;
  assert.match(production, /connect-src 'self' https:\/\/igqgtlmnwssjaoxkkzbm\.supabase\.co/);
  assert.doesNotMatch(production, /connect-src[^;]*\*/);
  assert.equal(supabaseConnectOrigin('https://igqgtlmnwssjaoxkkzbm.supabase.co', 'production'), 'https://igqgtlmnwssjaoxkkzbm.supabase.co');
  assert.equal(supabaseConnectOrigin('https://evil.example', 'production'), '');
  assert.equal(supabaseConnectOrigin('http://127.0.0.1:54321', 'production'), '');
  assert.equal(supabaseConnectOrigin('http://127.0.0.1:54321', 'development'), 'http://127.0.0.1:54321');
});

test('analysis route uses only local analysis and has no third-party provider calls', () => {
  assert.match(analyze, /analyzeWithLocalModel\(input\.trim\(\)\)/);
  assert.doesNotMatch(analyze, /api\.groq\.com|urlhaus-api\.abuse\.ch|api\.abuseipdb\.com/);
  assert.match(homePage, /No third-party AI key is required/);
  assert.match(homePage, /href=\"\/investigate\"/);
});

test('reports exports notes with an optional validated session analysis snapshot', () => {
  assert.match(reports, /satark-review-notes\.txt/);
  assert.match(reports, /satark-review-notes\.json/);
  assert.match(reports, /schema_version: 1/);
  assert.match(reports, /analysis_snapshot: savedAnalysis/);
  assert.match(reports, /submitted_source_text_saved: false/);
  assert.match(reports, /sessionStorage/);
  assert.match(reports, /This export is not a certified forensic report or a verified chain-of-custody record/);
  assert.match(investigatePage, /satark:last-analysis:v1/);
});

test('FIRSTLIGHT explicitly marks response actions as simulation only', () => {
  assert.match(firstlight, /SYNTHETIC/);
  assert.match(firstlight, /no real system action executed/);
  assert.match(firstlight, /does not inspect the endpoint or file/);
});


test('per-instance throttling does not trust spoofable x-forwarded-for', () => {
  assert.match(rateLimit, /request\.headers\.get\('x-real-ip'\)/);
  assert.doesNotMatch(rateLimit, /request\.headers\.get\('x-forwarded-for'\)\?\.split\(', '\)\[0\]/);
  assert.match(analyze, /await checkAnalysisRateLimit\(request\)/);
  assert.match(rateLimit, /\|\| 'unknown'/);
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
  assert.match(investigate, /No third-party AI or reputation API is called in local-only mode/i);
  assert.doesNotMatch(investigate, /query strings and fragments are removed first/);
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

test('analysis route validates bounded local input and never calls a provider', () => {
  assert.match(analyze, /MAX_BODY_BYTES = 48 \* 1024/);
  assert.match(analyze, /MAX_INPUT_CHARS = 12_000/);
  assert.match(analyze, /analyzeWithLocalModel/);
  assert.doesNotMatch(analyze, /await upstream\.json\(\)/);
});


test('default analysis API contains no external provider response parsing', () => {
  assert.doesNotMatch(analyze, /MAX_THREAT_INTEL_RESPONSE_BYTES|readJsonWithinLimit/);
  assert.doesNotMatch(analyze, /await response\.json\(\)|fetch\(['"]https?:/);
});


test('local deployment guide documents no third-party analysis API dependency', () => {
  const localGuide = readFileSync(new URL('../../docs/LOCAL_ONLY_DEPLOYMENT.md', import.meta.url), 'utf8');
  assert.match(localGuide, /does not call Groq, URLhaus, AbuseIPDB/);
  assert.match(localGuide, /no API key is required/i);
  assert.match(localGuide, /not an antivirus/i);
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


test('analysis pages disclose local-only processing and no third-party AI sharing', () => {
  assert.match(homePage, /Local deterministic checks by default/i);
  assert.match(homePage, /No third-party AI key is required/i);
  assert.match(homePage, /href=\"\/investigate\"/);
  assert.doesNotMatch(homePage, /result\.notice|Local threat-intelligence cache/);
  assert.match(investigatePage, /No third-party AI or reputation API is called in local-only mode/i);
  assert.doesNotMatch(homePage, /text you submit is sent to Groq/i);
  assert.doesNotMatch(investigatePage, /full text is sent to Groq/i);
});


test('local analysis rate limits include a standards-based retry hint without enabling caching', () => {
  assert.match(analyze, /Too many requests\. Wait a minute and retry\.', 429, \{ 'Retry-After': '60' \}\)/);
  assert.match(analyze, /headers: \{ 'Cache-Control': 'no-store', \.\.\.extraHeaders \}/);
});

const approvalsRoute = readFileSync(new URL('../src/app/api/firstlight/approvals/route.ts', import.meta.url), 'utf8');
const approvalMigration = readFileSync(new URL('../../supabase/migrations/20261020035832_satark_simulation_only_approvals.sql', import.meta.url), 'utf8');
const approvalAclMigration = readFileSync(new URL('../../supabase/migrations/20261020040028_satark_approval_trigger_acl.sql', import.meta.url), 'utf8');

test('response approval API and database remain simulation-only and caller-inaccessible at trigger level', () => {
  assert.match(approvalsRoute, /\^simulation\\\./);
  assert.match(approvalsRoute, /mode!==['"]simulation['"]/);
  assert.match(approvalsRoute, /rpc\/satark_decide_approval/);
  assert.match(approvalMigration, /action_key like 'simulation\.%'/);
  assert.match(approvalMigration, /action_payload->>'mode' = 'simulation'/);
  assert.match(approvalAclMigration, /revoke all on function public\.satark_approvals_guard\(\) from public, anon, authenticated, service_role/i);
});
