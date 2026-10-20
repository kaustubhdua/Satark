#!/usr/bin/env node
/**
 * Generate a deterministic source inventory for SATARK/FIRSTLIGHT.
 * Static discovery is not runtime proof: every discovered feature starts unverified
 * unless the inventory can safely classify a missing configuration or explicit mock.
 */
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const exists = async p => { try { await readFile(path.join(root, p)); return true; } catch { return false; } };
async function walk(dir) {
  try {
    const entries = await readdir(path.join(root, dir), { withFileTypes: true });
    const out = [];
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.next' || entry.name === '.git') continue;
      const relative = path.posix.join(dir, entry.name);
      if (entry.isDirectory()) out.push(...await walk(relative));
      else out.push(relative);
    }
    return out.sort();
  } catch { return []; }
}
const all = await walk('.');
const read = async p => { try { return await readFile(path.join(root, p), 'utf8'); } catch { return ''; } };
const by = (label, predicate) => all.filter(predicate).map(file => ({ label, file, status: 'unverified', evidence: 'source discovery only; runtime behavior not proven' }));

const pages = by('page', p => /^web\/src\/app\/.*\/page\.(tsx|ts|jsx|js)$/.test(p) || /^web\/src\/app\/page\.(tsx|ts|jsx|js)$/.test(p));
const apis = by('api', p => /^web\/src\/app\/api\/.*\/route\.(tsx|ts|js)$/.test(p));
const migrations = by('migration', p => /^supabase\/migrations\/.*\.sql$/.test(p));
const databaseTests = by('database-test', p => /^supabase\/tests\/.*\.sql$/.test(p));
const workflows = by('workflow', p => /^\.github\/workflows\/.*\.ya?ml$/.test(p));
const workers = by('worker', p => /(^|\/)([^/]*worker[^/]*\.(py|ts|tsx|js|mjs))$/i.test(p));
const adapters = by('provider-adapter', p => /(^|\/)(integrations\/|.*wazuh.*\.(py|ts|js|mjs)$|ai_provider\.py$|threat_intel\.py$)/i.test(p));
const tests = by('test', p => /(^|\/)(tests?|__tests__)\/.*\.(py|ts|tsx|js|mjs)$/.test(p));

const uiFiles = pages.concat(all.filter(file => /^web\/src\/app\/.*\.(tsx|ts|jsx|js)$/.test(file) && !pages.some(p => p.file === file))
  .map(file => ({ label: 'ui-module', file, status: 'unverified', evidence: 'source discovery only; runtime behavior not proven' })));
const actionMap = [];
for (const item of uiFiles) {
  const source = await read(item.file);
  const endpoints = [...new Set([
    ...[...source.matchAll(/fetch\(\s*[`'"]([^ `'"]*\/api\/[^ `'"]*)/g)].map(m => m[1]),
    ...[...source.matchAll(/authenticatedFetch\(\s*[`'"]([^ `'"]*)/g)].map(m => m[1]),
  ])];
  const actions = [...new Set([...source.matchAll(/\bon(?:Click|Submit|Change)=\{([^}]{1,160})\}/g)].map(m => m[1].trim()))];
  if (actions.length || endpoints.length) actionMap.push({
    source: item.file,
    actions: actions.length ? actions : ['handler not statically resolved'],
    endpoints: endpoints.length ? endpoints : ['no literal API endpoint found'],
    persistentWrite: 'requires handler/backend inspection',
    externalSideEffect: 'requires handler/backend inspection',
    tests: tests.filter(t => t.file.startsWith('web/tests/')).map(t => t.file).filter(p => {
      const base = path.basename(item.file).replace(/\.(tsx|ts|jsx|js)$/, '').toLowerCase();
      return path.basename(p).toLowerCase().includes(base) || /contract|persistent|tenant|api/.test(path.basename(p));
    }).slice(0, 12),
    status: 'unverified',
  });
}

const tableNames = new Set();
const rpcNames = new Set();
for (const item of migrations) {
  const source = await read(item.file);
  for (const match of source.matchAll(/\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:public|satark_private)\.([a-zA-Z0-9_]+)/ig)) tableNames.add(match[1]);
  for (const match of source.matchAll(/\bcreate\s+(?:or\s+replace\s+)?function\s+(?:public|satark_private)\.([a-zA-Z0-9_]+)/ig)) rpcNames.add(match[1]);
}
const envExamples = all.filter(p => /(^|\/)(\.env.*example|.*\.env\.example)$/.test(p));
const manifest = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  disclaimer: 'Static inventory, not proof of runtime health, deployed schema, integration credentials or production behavior.',
  counts: {
    trackedFiles: all.length, pages: pages.length, apiRoutes: apis.length,
    migrations: migrations.length, discoveredTables: tableNames.size,
    discoveredFunctions: rpcNames.size, databaseTests: databaseTests.length,
    workflows: workflows.length, workers: workers.length, providerAdapters: adapters.length,
    tests: tests.length, uiActionSources: actionMap.length,
  },
  pages, apis, migrations, databaseTests, workflows, workers, providerAdapters: adapters,
  tests, envExamples: envExamples.map(file => ({ file, status: 'unverified', evidence: 'example file does not prove deployment configuration' })),
  databaseObjects: { tables: [...tableNames].sort(), functions: [...rpcNames].sort(), status: 'unverified', note: 'Discovered from migration SQL; not compared with a live database.' },
  uiActionMap: actionMap,
  migrationSafety: {
    sharedSupabaseWrites: 'FROZEN',
    reason: 'Known migration-ledger mismatch; require project-ref confirmation, ledger reconciliation and exact reviewed dry-run before any write.',
  },
};
const output = process.argv[2] || 'docs/generated/phase0-inventory.json';
await import('node:fs/promises').then(fs => fs.mkdir(path.dirname(path.join(root, output)), { recursive: true }));
await writeFile(path.join(root, output), JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify({ output, counts: manifest.counts, tableNames: manifest.databaseObjects.tables.length, functions: manifest.databaseObjects.functions.length }, null, 2));
