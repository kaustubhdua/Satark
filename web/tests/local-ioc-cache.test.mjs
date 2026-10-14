import test from 'node:test';
import assert from 'node:assert/strict';
import { lookupLocalIocs } from '../src/lib/local-ioc-cache.mjs';

const now = Date.parse('2026-10-14T00:00:00.000Z');
const freshCache = {
  schema_version: 1,
  generated_at: '2026-10-13T23:00:00.000Z',
  sources: [{
    id: 'approved-test-feed',
    name: 'Approved test feed',
    version: 'test-v1',
    last_successful_sync: '2026-10-13T23:00:00.000Z',
    max_age_hours: 72,
  }],
  indicators: [
    { id: '1', type: 'url', value: 'https://bad.example/login?campaign=1', source_id: 'approved-test-feed' },
    { id: '2', type: 'domain', value: 'evil.example', source_id: 'approved-test-feed' },
  ],
};

test('empty cache is not reported as a clean no-match', () => {
  assert.equal(lookupLocalIocs('https://example.com', now, {
    schema_version: 1, generated_at: null, sources: [], indicators: [],
  }).status, 'not_configured');
});

test('fresh cache matches exact URLs and domains with source provenance', () => {
  const result = lookupLocalIocs('Please inspect https://bad.example/login?campaign=1', now, freshCache);
  assert.equal(result.status, 'match');
  assert.equal(result.matches[0].source, 'Approved test feed');
  assert.equal(result.matches[0].source_version, 'test-v1');
  assert.equal(result.matches[0].evidence, 'bad.example');
});

test('URL indicators are exact and do not match a different path', () => {
  const result = lookupLocalIocs('https://bad.example/other', now, freshCache);
  assert.equal(result.status, 'no_match');
});

test('stale feed never produces an active IOC match', () => {
  const stale = structuredClone(freshCache);
  stale.sources[0].last_successful_sync = '2026-10-01T00:00:00.000Z';
  assert.equal(lookupLocalIocs('https://bad.example/login?campaign=1', now, stale).status, 'stale');
});

test('invalid cache fails closed to unavailable', () => {
  assert.equal(lookupLocalIocs('https://bad.example', now, {}).status, 'unavailable');
});

test('domain indicators require an exact hostname match', () => {
  const result = lookupLocalIocs('https://evil.example/account', now, freshCache);
  assert.equal(result.status, 'match');
  assert.ok(result.matches.some(match => match.type === 'domain'));
  const subdomain = lookupLocalIocs('https://sub.evil.example/account', now, freshCache);
  assert.equal(subdomain.status, 'no_match');
});
