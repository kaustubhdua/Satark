#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i];
  const value = process.argv[i + 1];
  if (!key?.startsWith('--') || !value || value.startsWith('--')) {
    throw new Error('Arguments must be supplied as --name value pairs.');
  }
  args.set(key.slice(2), value);
}

function required(name) {
  const value = args.get(name)?.trim();
  if (!value) throw new Error('Missing required argument --' + name);
  return value;
}

const inputPath = resolve(required('input'));
const sourceId = required('source-id');
const sourceName = required('source-name');
const sourceUrl = required('source-url');
const license = required('license');
const type = args.get('type') || 'url';
const maxAgeHours = Number(args.get('max-age-hours') || 72);
const outputPath = resolve(args.get('output') || 'web/src/data/local-ioc-cache.json');
const retrievedAt = args.get('retrieved-at') || new Date().toISOString();

if (!/^[a-z0-9][a-z0-9._-]{1,79}$/i.test(sourceId)) throw new Error('--source-id must be a short stable identifier.');
const sourceUrlParsed = new URL(sourceUrl);
if (sourceUrlParsed.protocol !== 'https:') throw new Error('--source-url must use HTTPS.');
if (!['url', 'domain'].includes(type)) throw new Error('--type must be url or domain.');
if (!Number.isFinite(maxAgeHours) || maxAgeHours < 1 || maxAgeHours > 8760) throw new Error('--max-age-hours must be between 1 and 8760.');
if (!Number.isFinite(Date.parse(retrievedAt))) throw new Error('--retrieved-at must be a valid timestamp.');

const raw = await readFile(inputPath, 'utf8');
if (Buffer.byteLength(raw, 'utf8') > 10 * 1024 * 1024) throw new Error('Input feed exceeds 10 MiB.');
const values = new Set();
for (const line of raw.split(/\r?\n/)) {
  const value = line.trim();
  if (!value || value.startsWith('#')) continue;
  if (type === 'url') {
    let parsed;
    try { parsed = new URL(value); } catch { throw new Error('Invalid URL indicator on input line: ' + (values.size + 1)); }
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
      throw new Error('Only credential-free HTTP(S) URL indicators are accepted.');
    }
    parsed.hash = '';
    parsed.hostname = parsed.hostname.toLowerCase();
    values.add(parsed.origin + parsed.pathname + parsed.search);
  } else {
    const domain = value.toLowerCase().replace(/\.$/, '');
    if (domain.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
      throw new Error('Invalid domain indicator on input line: ' + (values.size + 1));
    }
    values.add(domain);
  }
}
if (!values.size) throw new Error('Feed contains no valid indicators.');
if (values.size > 250000) throw new Error('Feed exceeds the 250,000 indicator limit.');

const manifest = {
  schema_version: 1,
  generated_at: new Date().toISOString(),
  sources: [{
    id: sourceId,
    name: sourceName.slice(0, 120),
    url: sourceUrlParsed.toString(),
    license: license.slice(0, 240),
    version: args.get('version') || retrievedAt,
    last_successful_sync: new Date(retrievedAt).toISOString(),
    max_age_hours: maxAgeHours,
    indicator_count: values.size,
  }],
  indicators: [...values].map(value => ({ id: randomUUID(), type, value, source_id: sourceId })),
};
await writeFile(outputPath, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
process.stdout.write('Imported ' + values.size + ' indicators from one operator-supplied local feed. No network request was made.\n');
process.stdout.write('Review the feed license and source provenance before committing or deploying ' + outputPath + '.\n');
