import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const routes = [
  ['cases', '../src/app/api/cases/route.ts', 1],
  ['binary evidence upload and persistence', '../src/app/api/evidence/route.ts', 2],
  ['FIRSTLIGHT evidence records', '../src/app/api/evidence/records/route.ts', 1],
  ['evidence integrity verification', '../src/app/api/evidence/[id]/verify/route.ts', 2],
  ['findings persistence', '../src/app/api/findings/route.ts', 2],
  ['report persistence', '../src/app/api/reports/route.ts', 2],
  ['audit-chain verification', '../src/app/api/audit/verify/route.ts', 1],
];

for (const [name, path, expected] of routes) {
  test(name + ' bounds each outbound data request', async () => {
    const source = await readFile(new URL(path, import.meta.url), 'utf8');
    const count = source.match(/AbortSignal\.timeout\(8_000\)/g)?.length ?? 0;
    assert.ok(count >= expected, `expected at least ${expected} 8-second request timeout(s), found ${count}`);
  });
}

test('case API timeout can be overridden only by an explicit caller signal', async () => {
  const source = await readFile(new URL('../src/app/api/cases/route.ts', import.meta.url), 'utf8');
  assert.match(source, /signal: init\.signal \?\? AbortSignal\.timeout\(8_000\)/);
});
