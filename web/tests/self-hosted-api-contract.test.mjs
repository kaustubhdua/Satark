import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const routes = [
  '../src/app/api/audit/verify/route.ts',
  '../src/app/api/auth/session/route.ts',
  '../src/app/api/cases/notes/route.ts',
  '../src/app/api/cases/route.ts',
  '../src/app/api/evidence/[id]/verify/route.ts',
  '../src/app/api/evidence/records/route.ts',
  '../src/app/api/evidence/route.ts',
  '../src/app/api/findings/route.ts',
  '../src/app/api/firstlight/approvals/route.ts',
  '../src/app/api/firstlight/evidence/source/route.ts',
  '../src/app/api/firstlight/investigate/route.ts',
  '../src/app/api/firstlight/jobs/route.ts',
  '../src/app/api/firstlight/wazuh/alerts/route.ts',
  '../src/app/api/reports/[id]/route.ts',
  '../src/app/api/reports/route.ts',
];

test('legacy application API routes are thin proxies with no Supabase SDK or REST dependency', async () => {
  for (const path of routes) {
    const source = await readFile(new URL(path, import.meta.url), 'utf8');
    assert.match(source, /proxySatarkApi/, path);
    assert.doesNotMatch(source, /SUPABASE|supabase\.co|\/auth\/v1|\/rest\/v1|\/storage\/v1/i, path);
  }
});

test('shared proxy uses only the SATARK internal API configuration', async () => {
  const source = await readFile(new URL('../src/lib/satark-api-proxy.ts', import.meta.url), 'utf8');
  assert.match(source, /SATARK_API_INTERNAL_URL/);
  assert.doesNotMatch(source, /SUPABASE|supabase\.co|service_role/i);
});
