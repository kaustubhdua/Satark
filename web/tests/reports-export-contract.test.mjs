import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The backend's GET /reports/{id} requires tenant_id; exporting a report
// without it fails with a validation error. Guard against regressing that.
test('persistent report export sends tenant_id and reads the saved digest from the API shape', () => {
  const source = readFileSync(new URL('../src/app/reports/persistent-reports.tsx', import.meta.url), 'utf8');
  assert.match(source, /'\/api\/reports\/'\+encodeURIComponent\(item\.id\)\+'\?tenant_id='/);
  assert.match(source, /data\.report\?\.snapshot_sha256/);
});
