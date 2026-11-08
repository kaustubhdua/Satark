import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = path => readFile(new URL(path, import.meta.url), 'utf8');
const [auth, nextConfig, backend, compose, requirements, dockerfile, migration, env] = await Promise.all([
  read('../src/lib/satark-auth.ts'),
  read('../next.config.ts'),
  read('../../satark_backend.py'),
  read('../../docker-compose.local.yml'),
  read('../../firstlight-api-requirements.txt'),
  read('../../Dockerfile.firstlight-api'),
  read('../../migrations/versions/20261109_0001_self_hosted_satark.py'),
  read('../../.env.example'),
]);

test('browser identity uses SATARK-owned same-origin endpoints and HttpOnly cookies', () => {
  assert.match(auth, /\/api\/auth\/login/);
  assert.match(auth, /\/api\/auth\/signup/);
  assert.match(auth, /credentials: 'same-origin'/);
  assert.doesNotMatch(auth, /SUPABASE|supabase\.co|\/auth\/v1|\/rest\/v1|localStorage\.setItem\([^,]*(SESSION|TOKEN)/i);
});

test('Next.js proxies the migrated application routes to the private FastAPI service', () => {
  assert.match(nextConfig, /SATARK_API_INTERNAL_URL/);
  assert.match(nextConfig, /beforeFiles/);
  assert.match(nextConfig, /\/api\/auth/);
  assert.match(nextConfig, /\/api\/cases/);
  assert.doesNotMatch(nextConfig, /SUPABASE|supabase\.co/i);
});

test('self-hosted backend owns password hashing, sessions, tenant authorization, and persistence', () => {
  assert.match(backend, /PasswordHasher/);
  assert.match(backend, /token_digest/);
  assert.match(backend, /HttpOnly|httponly=True/);
  assert.match(backend, /require_membership/);
  assert.match(backend, /satark_audit_events/);
  assert.match(backend, /MAX_UPLOAD = 4 \* 1024 \* 1024/);
  assert.match(backend, /source_sha256/);
  assert.doesNotMatch(backend, /supabase\.co|\/auth\/v1|\/rest\/v1|\/storage\/v1|SUPABASE_SERVICE_ROLE_KEY/i);
});

test('local stack provisions persistent self-hosted database and evidence storage', () => {
  assert.match(compose, /SATARK_DATABASE_URL/);
  assert.match(compose, /SATARK_EVIDENCE_DIR/);
  assert.match(compose, /satark_data:\/data/);
  assert.doesNotMatch(compose, /SUPABASE|supabase\.co/i);
});

test('container installs the independent persistence stack and applies migrations', () => {
  assert.match(requirements, /SQLAlchemy/);
  assert.match(requirements, /psycopg/);
  assert.match(requirements, /argon2-cffi/);
  assert.match(requirements, /python-multipart/);
  assert.match(dockerfile, /satark_backend\.py/);
  assert.match(dockerfile, /alembic upgrade head/);
  assert.match(migration, /Base\.metadata\.create_all/);
});

test('environment template contains no Supabase configuration', () => {
  assert.match(env, /SATARK_DATABASE_URL/);
  assert.doesNotMatch(env, /SUPABASE|supabase\.co/i);
});
