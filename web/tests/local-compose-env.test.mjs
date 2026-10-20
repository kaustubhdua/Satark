import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const compose = await readFile(new URL('../../docker-compose.local.yml', import.meta.url), 'utf8');
const dockerfile = await readFile(new URL('../Dockerfile', import.meta.url), 'utf8');

test('local Compose passes server-side Supabase auth config to the web container', () => {
  assert.ok(compose.includes('SUPABASE_URL: ${SUPABASE_URL:-}'));
  assert.ok(compose.includes('SUPABASE_PUBLISHABLE_KEY: ${SUPABASE_PUBLISHABLE_KEY:-}'));
});

test('local Next.js image receives public Supabase config at build time', () => {
  assert.ok(compose.includes('NEXT_PUBLIC_SUPABASE_URL: ${NEXT_PUBLIC_SUPABASE_URL:-}'));
  assert.ok(compose.includes('NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: ${NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:-}'));
  assert.ok(dockerfile.includes('ARG NEXT_PUBLIC_SUPABASE_URL'));
  assert.ok(dockerfile.includes('ARG NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY'));
});
