import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const routes = [
  ['cases', '../src/app/api/cases/route.ts', /bearer\(request\)/, ['GET', 'POST', 'PATCH']],
  ['findings', '../src/app/api/findings/route.ts', /hasBearer\(request\)/, ['GET', 'POST']],
  ['reports', '../src/app/api/reports/route.ts', /hasBearer\(request\)/, ['GET', 'POST']],
];

for (const [name, relativePath, guard, methods] of routes) {
  test(`${name} API rejects requests without bearer credentials before checking storage configuration`, async () => {
    const source = await readFile(new URL(relativePath, import.meta.url), 'utf8');
    for (const method of methods) {
      const start = source.indexOf(`export async function ${method}(request: Request)`);
      assert.notEqual(start, -1, `${name} must implement ${method}`);
      const next = source.indexOf('\nexport async function ', start + 1);
      const handler = source.slice(start, next === -1 ? source.length : next);
      const guardMatch = handler.match(guard);
      assert.ok(guardMatch, `${name} ${method} must check bearer credentials`);
      const storageCheck = handler.search(/(?:configuration\(\)|config\(\))/);
      assert.ok(storageCheck >= 0, `${name} ${method} must check storage configuration`);
      assert.ok(guardMatch.index < storageCheck, `${name} ${method} must return 401 before a missing-config 503`);
    }
  });
}
