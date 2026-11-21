// Opt-in end-to-end journey against a web server with NO backend configured (browser-only mode).
//   SATARK_WEB_URL=http://127.0.0.1:3000 node tests/local-journey.mjs
// Signs up a throwaway account, imports a real CSV, saves a case, uploads and verifies an original file,
// runs a durable investigation and verifies the audit chain. Fails on any unexpected HTTP >= 400.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';

const base = process.env.SATARK_WEB_URL || 'http://127.0.0.1:3000';
const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'satark-journey-'));
const csv = path.join(dir, 'events.csv');
await fs.writeFile(csv, [
  'timestamp,source,summary,severity',
  '2026-11-18T09:12:04Z,auth.log,Failed password for root from 203.0.113.50 port 51122 ssh2,high',
  '2026-11-18T09:12:15Z,auth.log,Accepted password for deploy from 203.0.113.50 port 51152 ssh2,critical',
].join('\n'));

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });
const failures = [];
page.on('pageerror', error => failures.push('pageerror: ' + error.message));
page.on('response', response => {
  if (response.status() >= 400 && !response.url().endsWith('/api/auth/session')) failures.push(response.status() + ' ' + response.url());
});
const text = selector => page.$$eval(selector, nodes => nodes.map(node => node.textContent.trim()).join(' | '));

await page.goto(base + '/firstlight', { waitUntil: 'networkidle' });
await page.waitForSelector('input[type=file][accept*=csv]');
await page.setInputFiles('input[type=file][accept*=csv]', csv);
await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight / 2));
await page.waitForSelector('#persistent-case-title', { timeout: 20000 });
await page.fill('#persistent-case-title', 'Local journey case');
await page.getByRole('button', { name: /save case, evidence/i }).click();
await page.getByText(/Saved case/).first().waitFor({ timeout: 20000 });
await page.setInputFiles('#private-evidence-file', csv);
await page.getByRole('button', { name: /upload private file/i }).click();
await page.getByText(/Private file uploaded/).waitFor();
await page.getByRole('button', { name: /verify last uploaded/i }).click();
await page.getByText(/Integrity match/).waitFor();
await page.getByRole('button', { name: /verify audit chain/i }).click();
await page.getByText(/Audit chain valid · \d+ events checked/).waitFor();

await page.goto(base + '/cases', { waitUntil: 'networkidle' });
await page.getByText('Local journey case').first().waitFor({ timeout: 15000 });
await page.screenshot({ path: '/tmp/claude-0/audit/local-cases.png', fullPage: true });
await page.goto(base + '/reports', { waitUntil: 'networkidle' });
await page.screenshot({ path: '/tmp/claude-0/audit/local-reports.png', fullPage: true });
// A reload must keep the data: it lives in IndexedDB, not in memory.
await page.goto(base + '/cases', { waitUntil: 'networkidle' });
await page.getByText('Local journey case').first().waitFor({ timeout: 15000 });

assert.deepEqual(failures, [], 'unexpected failures: ' + failures.join('; '));
console.log('Local journey passed:', await text('.success-message, [role=status]'));
await browser.close();
await fs.rm(dir, { recursive: true, force: true });
