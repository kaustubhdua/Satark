import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);

test('production startup uses the generated standalone server and prepares its static assets', async () => {
  const [packageText, preparationScript] = await Promise.all([
    readFile(new URL('package.json', root), 'utf8'),
    readFile(new URL('scripts/prepare-standalone.mjs', root), 'utf8'),
  ]);
  const pkg = JSON.parse(packageText);

  assert.equal(pkg.scripts.start, 'node .next/standalone/server.js');
  assert.equal(pkg.scripts.prestart, 'node scripts/prepare-standalone.mjs');
  assert.match(preparationScript, /\.next\/standalone/);
  assert.match(preparationScript, /resolve\(root, 'public'\)/);
  assert.match(preparationScript, /resolve\(root, '\.next\/static'\)/);
  assert.match(preparationScript, /Next\.js standalone server was not found/);
});
