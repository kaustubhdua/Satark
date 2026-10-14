import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../scripts/import-local-ioc-cache.mjs', import.meta.url));

test('local IOC importer records provenance, deduplicates indicators, and does not need network access', () => {
  const dir = mkdtempSync(join(tmpdir(), 'satark-ioc-import-'));
  try {
    const input = join(dir, 'feed.txt');
    const output = join(dir, 'cache.json');
    writeFileSync(input, '# reviewed fixture\nhttps://bad.example/login\nhttps://bad.example/login\nhttps://evil.example/pay\n');
    const stdout = execFileSync(process.execPath, [
      script,
      '--input', input,
      '--source-id', 'test-feed',
      '--source-name', 'Approved test feed',
      '--source-url', 'https://feed.example.test/source',
      '--license', 'fixture-only test license',
      '--version', 'fixture-v1',
      '--max-age-hours', '24',
      '--output', output,
      '--retrieved-at', '2026-10-14T00:00:00.000Z',
    ], { encoding: 'utf8' });
    const manifest = JSON.parse(readFileSync(output, 'utf8'));
    assert.match(stdout, /No network request was made/);
    assert.equal(manifest.sources[0].id, 'test-feed');
    assert.equal(manifest.sources[0].license, 'fixture-only test license');
    assert.equal(manifest.sources[0].indicator_count, 2);
    assert.equal(manifest.indicators.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('local IOC importer rejects malformed indicators and unsupported source URLs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'satark-ioc-invalid-'));
  try {
    const input = join(dir, 'feed.txt');
    const output = join(dir, 'cache.json');
    writeFileSync(input, 'javascript:alert(1)\n');
    const result = spawnSync(process.execPath, [
      script,
      '--input', input,
      '--source-id', 'test-feed',
      '--source-name', 'Test feed',
      '--source-url', 'http://feed.example.test/source',
      '--license', 'fixture license',
      '--output', output,
    ], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /source-url must use HTTPS/);
    assert.equal(readFileSync(input, 'utf8'), 'javascript:alert(1)\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
