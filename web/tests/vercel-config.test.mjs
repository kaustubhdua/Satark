import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Vercel's Hobby plan allows 100 deployments per day and 100 builds per hour; a Git-connected project builds every
// pushed branch by default, which exhausted the budget and blocked production deploys. CI already builds and
// browser-tests every branch, so only `main` and opt-in `preview/**` branches are deployed.
const config = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));

test('only main and opt-in preview branches are deployed by Vercel', () => {
  const enabled = config.git.deploymentEnabled;
  assert.equal(enabled.main, true, 'production must keep deploying from main');
  assert.equal(enabled['preview/**'], true, 'a branch named preview/* must be previewable on demand');
  assert.equal(enabled['*'], false);
  assert.equal(enabled['**'], false, 'nested branch names such as feat/x must not deploy');
});

test('vercel.json sets nothing that could change the build', () => {
  assert.deepEqual(Object.keys(config).sort(), ['$schema', 'git']);
});
