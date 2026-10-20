import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const workflow = readFileSync(path.join(root, '.github/workflows/production-smoke.yml'), 'utf8');
const homepage = readFileSync(path.join(root, 'web/src/app/page.tsx'), 'utf8');
const versionRoute = readFileSync(path.join(root, 'web/src/app/api/version/route.ts'), 'utf8');

test('production homepage smoke marker stays aligned with the source hero', () => {
  assert.match(homepage, /Every second matters\. Every piece of evidence counts\./);
  assert.match(workflow, /check_route "\/" "Every second matters\\\. Every piece of evidence counts\\\."/);
});

test('production smoke checks the version endpoint and fails on a SHA mismatch', () => {
  assert.match(workflow, /check_route "\/api\/version"/);
  assert.match(workflow, /\$expected_sha/);
  assert.match(workflow, /deployed_sha/);
  assert.match(workflow, /production alias serves exact main SHA/);
});

test('version endpoint exposes a validated Vercel commit SHA without caching', () => {
  assert.match(versionRoute, /process\.env\.VERCEL_GIT_COMMIT_SHA/);
  assert.match(versionRoute, /\^\[0-9a-f\]\{40\}\$/i);
  assert.match(versionRoute, /Cache-Control': 'no-store'/);
});
