import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const compose = await readFile(new URL('../../docker-compose.local.yml', import.meta.url), 'utf8');

test('local Compose uses SATARK-owned persistent database and evidence storage', () => {
  assert.match(compose, /SATARK_DATABASE_URL: \$\{SATARK_DATABASE_URL:-sqlite:\/\/\/\/data\/satark\.db\}/);
  assert.match(compose, /SATARK_EVIDENCE_DIR: \/data\/evidence/);
  assert.match(compose, /satark_data:\/data/);
  assert.doesNotMatch(compose, /SUPABASE|supabase\.co/i);
});

test('web container talks to the private self-hosted API service', () => {
  assert.match(compose, /SATARK_API_INTERNAL_URL: http:\/\/firstlight-api:8788/);
  assert.doesNotMatch(compose, /NEXT_PUBLIC_SUPABASE|SUPABASE_URL|SUPABASE_PUBLISHABLE_KEY/i);
});

test('Ollama is opt-in and does not block deterministic local startup', () => {
  assert.match(compose, /ollama:\n    profiles: \["ai"\]/);
  assert.doesNotMatch(compose, /depends_on:\n\s+ollama:/);
});
