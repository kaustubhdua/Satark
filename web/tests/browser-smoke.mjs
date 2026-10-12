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

    // Catch structural accessibility regressions on every route and viewport.
    const semantics = await page.evaluate(() => ({
      language: document.documentElement.lang,
      mainLandmarks: document.querySelectorAll('main').length,
      primaryHeadings: document.querySelectorAll('h1').length,
      imagesWithoutAlt: document.querySelectorAll('img:not([alt])').length,
    }));
    assert.equal(semantics.language, 'en', `${label}: document language must be declared on ${route.path}`);
    assert.equal(semantics.mainLandmarks, 1, `${label}: expected one main landmark on ${route.path}: ${JSON.stringify(semantics)}`);
    assert.equal(semantics.primaryHeadings, 1, `${label}: expected one primary heading on ${route.path}: ${JSON.stringify(semantics)}`);
    assert.equal(semantics.imagesWithoutAlt, 0, `${label}: every image needs an alt attribute on ${route.path}`);

    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement?.classList.contains('skip-link')), true,
      `${label}: skip link should be the first keyboard focus target on ${route.path}`);
    const bodyText = await page.locator('body').innerText();
    assert.match(bodyText, route.heading, `${label}: expected route content missing at ${route.path}`);
    if (route.path !== '/') {
      assert.equal(await page.locator('.nav-links a[aria-current="page"]').count(), 1,
        `${label}: exactly one current navigation link expected at ${route.path}`);
    }
    const dimensions = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
    }));
    assert.ok(dimensions.document <= dimensions.viewport + 1,
      `${label}: horizontal overflow at ${route.path}: ${JSON.stringify(dimensions)}`);
    if (route.path === '/') {
      const start = page.getByRole('link', { name: /start an investigation/i });
      await start.click();
      await page.waitForURL(/#investigate$/);
      assert.equal(await page.getByRole('button', { name: /analyze with satark/i }).isDisabled(), true,
        'homepage analysis should stay disabled until content is entered');
    }
    if (route.path === '/investigate') {
      const analyzeButton = page.getByRole('button', { name: /analyze content/i });
      assert.equal(await analyzeButton.isDisabled(), true, 'investigation should be disabled for empty input');
      const input = page.getByLabel('Suspicious URL or message');
      await input.fill('Synthetic training example: urgent password verification at example.invalid');
      assert.equal(await analyzeButton.isDisabled(), false, 'investigation should enable for non-empty input');
      assert.match(await page.locator('#content-hint').innerText(), /\d+ \/ 12,000 characters/);
      await input.fill('');
      assert.equal(await analyzeButton.isDisabled(), true, 'investigation should disable again when cleared');
    }
    if (route.path === '/reports') {
      const notes = page.getByLabel('Review notes');
      const exportButton = page.getByRole('button', { name: /export notes/i });
      assert.equal(await exportButton.isDisabled(), true, 'export should be disabled for empty notes');
      await notes.fill('Synthetic review note: verify sender through official channel.');
      assert.equal(await exportButton.isDisabled(), false, 'export should enable after notes are entered');
      const downloadPromise = page.waitForEvent('download');
      await exportButton.click();
      const download = await downloadPromise;
      assert.equal(download.suggestedFilename(), 'satark-review-notes.txt');
      await page.getByRole('status').filter({ hasText: /download manager/i }).waitFor();
      await page.getByRole('button', { name: /clear notes/i }).click();
      assert.equal(await notes.inputValue(), '');
      assert.equal(await exportButton.isDisabled(), true);
    }
    if (route.path === '/learn') {
      for (const name of ['q0', 'q1', 'q2']) await page.locator(`input[name="${name}"]`).nth(name === 'q0' ? 1 : name === 'q1' ? 2 : 1).check();
      await page.getByRole('button', { name: /check answers/i }).click();
      await page.getByRole('heading', { name: '3 / 3 correct' }).waitFor();
      await page.getByRole('button', { name: /reset quiz/i }).click();
      assert.equal(await page.locator('input[type="radio"]:checked').count(), 0);
      assert.equal(await page.getByRole('button', { name: /check answers/i }).isDisabled(), true);
      const demoInput = page.getByRole('textbox', { name: /demo code entry/i });
      await demoInput.fill('123456');
      await page.getByText(/demo interaction complete/i).waitFor();
      await page.getByRole('button', { name: /reset code demo/i }).click();
      assert.equal(await demoInput.inputValue(), '', 'reset should clear the code demo input');
      await demoInput.fill('654321');
      await page.getByText(/demo interaction complete/i).waitFor();
    }
    if (route.path === '/firstlight') {
      await page.screenshot({ path: path.join(artifactDir, `firstlight-${label}.png`), fullPage: true });
      const launch = page.getByRole('button', { name: /launch training case/i });
      await launch.waitFor();
      await launch.click();
      await page.getByRole('heading', { name: /artifacts & integrity/i }).waitFor();
      assert.equal(await page.locator('.evidence-table tbody tr').count(), 5, 'training case should load five evidence records');

      const tamper = page.getByRole('button', { name: /simulate tamper/i }).first();
      await tamper.click();
      await page.getByText('MISMATCH').first().waitFor();
      await page.getByRole('button', { name: /restore demo/i }).first().click();
      await page.getByText('HASHED').first().waitFor();

      await page.getByRole('button', { name: /findings & gaps/i }).click();
      await page.getByRole('heading', { name: /findings & evidence gaps/i }).waitFor();
      await page.getByRole('button', { name: /timeline/i }).click();
      await page.getByRole('heading', { name: /put observations in context/i }).waitFor();
      await page.getByRole('button', { name: /response review/i }).click();
      await page.getByRole('button', { name: /approve/i }).first().click();
      await page.getByRole('button', { name: /reject/i }).nth(1).click();
      await page.getByText(/recorded decisions/i).waitFor();
      await page.getByRole('button', { name: /audit trail/i }).click();
      await page.getByRole('heading', { name: /decision trail/i }).waitFor();
      await page.getByText(/SIMULATED_RESPONSE_APPROVED/i).waitFor();
      await page.getByText(/SIMULATED_RESPONSE_REJECTED/i).waitFor();

      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles({
        name: 'training-events.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify([{ id: 'QA-001', timestamp: '2026-10-11T10:00:00Z', source: 'QA test', kind: 'message', summary: 'Urgent account verification request' }])),
      });
      await page.getByRole('status').filter({ hasText: /Imported and hashed locally/i }).waitFor();
      await page.getByText('QA-001').waitFor();

      await fileInput.setInputFiles({
        name: 'training-events.csv',
        mimeType: 'text/csv',
        buffer: Buffer.from('id,timestamp,source,kind,summary\nQA-CSV-001,2026-10-11T10:05:00Z,QA test,message,Unexpected login notice\n'),
      });
      await page.getByRole('status').filter({ hasText: /Imported and hashed locally/i }).waitFor();
      await page.getByText('QA-CSV-001').waitFor();

      await fileInput.setInputFiles({
        name: 'invalid-events.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify([{ timestamp: 'not-a-date', summary: 'Invalid timestamp case' }])),
      });
      await page.getByRole('status').filter({ hasText: /Invalid timestamp in event 1/i }).waitFor();
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
