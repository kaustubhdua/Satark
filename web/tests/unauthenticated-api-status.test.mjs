import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const routes = [
  ['cases', '../src/app/api/cases/route.ts', ['GET', 'POST', 'PATCH']],
  ['findings', '../src/app/api/findings/route.ts', ['GET', 'POST']],
  ['reports', '../src/app/api/reports/route.ts', ['GET', 'POST']],
];

for (const [name, relativePath, methods] of routes) {
  test(`${name} API delegates identity and authorization to the self-hosted backend`, async () => {
    const source = await readFile(new URL(relativePath, import.meta.url), 'utf8');
    assert.match(source, /proxySatarkApi/);
    for (const method of methods) assert.match(source, new RegExp(`export const ${method} = proxySatarkApi`));
    assert.doesNotMatch(source, /SUPABASE|supabase\.co|service_role/i);
  });
}
