import { access, cp, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const standalone = resolve(root, '.next/standalone');

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return false;
    throw error;
  }
}

async function copyDirectoryIfPresent(source, destination) {
  if (!(await exists(source))) return;
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true, force: true });
}

if (!(await exists(resolve(standalone, 'server.js')))) {
  throw new Error('Next.js standalone server was not found. Run npm run build before npm run start.');
}

// Next.js standalone output intentionally omits these assets unless copied.
// Prepare the same directory layout expected by the generated standalone server.
await copyDirectoryIfPresent(resolve(root, 'public'), resolve(standalone, 'public'));
await copyDirectoryIfPresent(resolve(root, '.next/static'), resolve(standalone, '.next/static'));

process.stdout.write('[SATARK] Standalone server assets are ready.\n');
