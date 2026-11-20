import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../../', import.meta.url);
const doc = readFileSync(new URL('docs/HOSTED_DEPLOYMENT.md', root), 'utf8');

test('every SATARK_/FIRSTLIGHT_ variable named in the hosted guide exists in the code', () => {
  const names = new Set([...doc.matchAll(/`((?:SATARK|FIRSTLIGHT)_[A-Z0-9_]+)`/g)].map((m) => m[1]));
  assert.ok(names.size > 15);
  for (const name of names) {
    const hit = execFileSync('git', ['grep', '-l', '-F', name, '--', '*.py', '*.ts', '*.tsx', '*.mjs', '*.example', 'docker-compose*.yml'], { cwd: root, encoding: 'utf8' }).trim();
    assert.ok(hit, `${name} appears in the guide but nowhere in the code`);
  }
});

test('the images the guide relies on install the S3 client', () => {
  for (const file of ['Dockerfile.firstlight-api', 'Dockerfile.firstlight-investigation-worker']) {
    assert.match(readFileSync(new URL(file, root), 'utf8'), /requirements-s3\.txt/, file);
  }
});
