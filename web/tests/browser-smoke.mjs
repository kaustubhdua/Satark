import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';

const baseURL = process.env.SATARK_WEB_URL || 'http://127.0.0.1:3000';
const artifactDir = process.env.SATARK_WEB_ARTIFACTS || 'artifacts/web';
await fs.mkdir(artifactDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const failures = [];
const routes = [
  { path: '/', heading: /SATARK|SENTINEL/i },
  { path: '/investigate', heading: /investigate|analysis|suspicious/i },
  { path: '/firstlight', heading: /FIRSTLIGHT/i },
  { path: '/reports', heading: /report/i },
  { path: '/learn', heading: /learn|safety/i },
];

async function inspectViewport(viewport, label) {
  const page = await browser.newPage({ viewport });
  page.setDefaultTimeout(12_000);
  page.on('pageerror', error => failures.push(`${label}: uncaught browser error: ${error.message}`));
  for (const route of routes) {
    const response = await page.goto(baseURL + route.path, { waitUntil: 'networkidle' });
    assert.ok(response && response.status() < 400, `${label}: ${route.path} returned ${response?.status()}`);
    await page.locator('body').waitFor();
    const bodyText = await page.locator('body').innerText();
    assert.match(bodyText, route.heading, `${label}: expected route content missing at ${route.path}`);
    const dimensions = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
    }));
    assert.ok(dimensions.document <= dimensions.viewport + 1,
      `${label}: horizontal overflow at ${route.path}: ${JSON.stringify(dimensions)}`);
    if (route.path === '/firstlight') {
      await page.screenshot({ path: path.join(artifactDir, `firstlight-${label}.png`), fullPage: true });
      const launch = page.getByRole('button', { name: /launch training case/i });
      if (await launch.count()) {
        await launch.click();
        await page.getByText(/synthetic records hashed|evidence ledger|artifacts & integrity/i).first().waitFor();
        await page.getByRole('button', { name: /findings & gaps/i }).click();
        await page.getByRole('heading', { name: /findings & evidence gaps/i }).waitFor();
        await page.getByRole('button', { name: /timeline/i }).click();
        await page.getByRole('heading', { name: /put observations in context/i }).waitFor();
        await page.getByRole('button', { name: /response review/i }).click();
        await page.getByRole('button', { name: /approve/i }).first().click();
        await page.getByText(/recorded decisions/i).waitFor();
      }
    }
  }
  await page.close();
}

try {
  await inspectViewport({ width: 1440, height: 900 }, 'desktop');
  await inspectViewport({ width: 390, height: 844 }, 'mobile');

  const malformed = await fetch(baseURL + '/api/analyze', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not-json',
  });
  assert.equal(malformed.status, 400, 'API should reject malformed JSON with 400');
  const empty = await fetch(baseURL + '/api/analyze', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ input: '   ' }),
  });
  assert.equal(empty.status, 400, 'API should reject empty input with 400');

  if (process.env.GROQ_API_KEY) {
    const response = await fetch(baseURL + '/api/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: 'Training-only example: "Your account will be closed today; verify your password at example.invalid". Assess cautiously; do not visit the domain.' }),
    });
    assert.equal(response.status, 200, `configured provider request returned ${response.status}: ${(await response.text()).slice(0, 500)}`);
    const result = await response.json();
    assert.ok(result && typeof result === 'object', 'provider response should be JSON');
    assert.ok(typeof result.risk_score === 'number', 'provider response should include a numeric risk_score');
    assert.ok(typeof result.summary === 'string', 'provider response should include a summary');
    console.log('Provider smoke test: passed with synthetic non-sensitive input.');
  } else {
    console.warn('Provider smoke test skipped: GROQ_API_KEY is not configured in this CI run.');
  }

  assert.deepEqual(failures, [], failures.join('\n'));
  console.log('SATARK web browser smoke tests passed at desktop and mobile viewports.');
} finally {
  await browser.close();
}
