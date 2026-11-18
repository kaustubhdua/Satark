// Opt-in end-to-end journey against a running web server + SATARK API + investigation worker.
//   SATARK_WEB_URL=http://127.0.0.1:3000 node tests/live-journey.mjs
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

await page.goto(base + '/login', { waitUntil: 'networkidle' });
await page.getByRole('button', { name: 'Create an account' }).click();
await page.fill('#email', `journey+${Date.now()}@example.com`);
await page.fill('#password', 'Correct-Horse-Battery-9');
await page.getByRole('button', { name: 'Create account' }).click();
await page.fill('#workspace', 'Journey Team');
await page.getByRole('button', { name: /create workspace/i }).click();
await page.waitForURL('**/firstlight');
await page.locator('.nav-cta', { hasText: 'Account' }).waitFor({ timeout: 15000 }); // header reflects the signed-in state

await page.waitForSelector('input[type=file][accept*=csv]');
await page.setInputFiles('input[type=file][accept*=csv]', csv);
// The persistent workspace mounts lazily when it nears the viewport.
await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight / 2));
await page.waitForSelector('#persistent-case-title', { timeout: 20000 });
await page.fill('#persistent-case-title', 'Journey case');
await page.getByRole('button', { name: /save case, evidence/i }).click();
await page.getByText(/Saved case/).waitFor();
await page.setInputFiles('#private-evidence-file', csv);
await page.getByRole('button', { name: /upload private file/i }).click();
await page.getByText(/Private file uploaded/).waitFor();
await page.getByRole('button', { name: /verify last uploaded/i }).click();
await page.getByText(/Integrity match/).waitFor();
await page.getByRole('button', { name: /run durable investigation/i }).click();
await page.getByText(/Durable investigation completed/).waitFor({ timeout: 60000 });
await page.getByRole('button', { name: /verify audit chain/i }).click();
await page.getByText(/Audit chain valid · \d+ events checked/).waitFor();

await page.goto(base + '/cases', { waitUntil: 'networkidle' });
await page.getByText('Journey case').first().waitFor({ timeout: 15000 });
await page.screenshot({ path: process.env.SATARK_JOURNEY_SHOT || '/tmp/claude-0/audit/cases.png', fullPage: true });
await page.goto(base + '/reports', { waitUntil: 'networkidle' });
await page.screenshot({ path: '/tmp/claude-0/audit/reports.png', fullPage: true });

assert.deepEqual(failures, [], 'unexpected failures: ' + failures.join('; '));
console.log('Live journey passed:', await text('.success-message, [role=status]'));
await browser.close();
await fs.rm(dir, { recursive: true, force: true });
