import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
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
    const responseHeaders = await response.allHeaders();
    assert.match(responseHeaders['content-security-policy'] || '', /object-src 'none'/,
      `${label}: CSP must deny object embeds on ${route.path}`);
    assert.match(responseHeaders['content-security-policy'] || '', /frame-ancestors 'none'/,
      `${label}: CSP must prevent framing on ${route.path}`);
    assert.match(responseHeaders['strict-transport-security'] || '', /max-age=31536000/,
      `${label}: HSTS must be present on ${route.path}`);
    await page.locator('body').waitFor();

    // Catch structural accessibility regressions on every route and viewport.
    const semantics = await page.evaluate(() => ({
      language: document.documentElement.lang,
      mainLandmarks: document.querySelectorAll('main').length,
      primaryHeadings: document.querySelectorAll('h1').length,
      imagesWithoutAlt: document.querySelectorAll('img:not([alt])').length,
      duplicateIds: [...document.querySelectorAll('[id]')].map(element => element.id)
        .filter((id, index, ids) => ids.indexOf(id) !== index).filter((id, index, ids) => ids.indexOf(id) === index),
      unnamedVisibleControls: [...document.querySelectorAll('button, a[href], input:not([type="hidden"]), select, textarea')]
        .filter(element => {
          const style = getComputedStyle(element);
          if (style.display === 'none' || style.visibility === 'hidden' || element.getClientRects().length === 0) return false;
          const labelledBy = (element.getAttribute('aria-labelledby') || '').split(/\s+/)
            .map(id => document.getElementById(id)?.innerText || '').join(' ').trim();
          const nativeLabel = element.labels ? [...element.labels].map(label => label.innerText).join(' ').trim() : '';
          const text = (element.innerText || element.textContent || '').trim();
          const imageAlt = element.getAttribute('alt') || '';
          return ![
            element.getAttribute('aria-label') || '',
            labelledBy,
            nativeLabel,
            imageAlt,
            element.getAttribute('title') || '',
            text,
          ].some(name => name.trim().length > 0);
        })
        .map(element => ({ tag: element.tagName.toLowerCase(), type: element.getAttribute('type'), id: element.id, html: element.outerHTML.slice(0, 180) })),
    }));
    assert.equal(semantics.language, 'en', `${label}: document language must be declared on ${route.path}`);
    assert.equal(semantics.mainLandmarks, 1, `${label}: expected one main landmark on ${route.path}: ${JSON.stringify(semantics)}`);
    assert.equal(semantics.primaryHeadings, 1, `${label}: expected one primary heading on ${route.path}: ${JSON.stringify(semantics)}`);
    assert.equal(semantics.imagesWithoutAlt, 0, `${label}: every image needs an alt attribute on ${route.path}`);
    assert.deepEqual(semantics.duplicateIds, [], `${label}: duplicate IDs break label and landmark references on ${route.path}: ${JSON.stringify(semantics.duplicateIds)}`);
    assert.deepEqual(semantics.unnamedVisibleControls, [], `${label}: visible interactive controls need accessible names on ${route.path}: ${JSON.stringify(semantics.unnamedVisibleControls)}`);

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
      offenders: [...document.querySelectorAll('body *')]
        .map(element => {
          const rect = element.getBoundingClientRect();
          return {
            tag: element.tagName.toLowerCase(),
            className: typeof element.className === 'string' ? element.className.slice(0, 90) : '',
            text: (element.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 50),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
          };
        })
        .filter(element => element.right > document.documentElement.clientWidth + 1)
        .slice(0, 8),
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
      const exportButton = page.getByRole('button', { name: /export notes.*txt/i });
      assert.equal(await exportButton.isDisabled(), true, 'export should be disabled for empty notes');
      await notes.fill('Synthetic review note: verify sender through official channel.');
      assert.equal(await exportButton.isDisabled(), false, 'export should enable after notes are entered');
      const downloadPromise = page.waitForEvent('download');
      await exportButton.click();
      const download = await downloadPromise;
      assert.equal(download.suggestedFilename(), 'satark-review-notes.txt');
      const jsonExportButton = page.getByRole('button', { name: /export notes.*json/i });
      assert.equal(await jsonExportButton.isDisabled(), false, 'JSON export should enable after notes are entered');
      const jsonDownloadPromise = page.waitForEvent('download');
      await jsonExportButton.click();
      const jsonDownload = await jsonDownloadPromise;
      assert.equal(jsonDownload.suggestedFilename(), 'satark-review-notes.json');
      const jsonPath = await jsonDownload.path();
      assert.ok(jsonPath, 'JSON export should produce a readable download');
      const jsonPayload = JSON.parse(await fs.readFile(jsonPath, 'utf8'));
      assert.equal(jsonPayload.schema_version, 1);
      assert.equal(jsonPayload.report_type, 'user-authored-review-notes');
      assert.equal(jsonPayload.notes, await notes.inputValue().then(value => value.trim()));
      assert.ok(Array.isArray(jsonPayload.limitations) && jsonPayload.limitations.length > 0,
        'JSON export should explain its evidence and certification limitations');
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
      const jsonBuffer = Buffer.from(JSON.stringify([{ id: 'QA-001', timestamp: '2026-10-11T10:00:00Z', source: 'QA test', kind: 'message', summary: 'Urgent account verification request' }]));
      const originalFileHash = createHash('sha256').update(jsonBuffer).digest('hex');
      await fileInput.setInputFiles({
        name: 'training-events.json',
        mimeType: 'application/json',
        buffer: jsonBuffer,
      });
      await page.getByRole('status').filter({ hasText: /Imported locally/i }).waitFor();
      await page.getByText('QA-001').waitFor();
      const [evidenceDownload] = await Promise.all([
        page.waitForEvent('download'),
        page.getByRole('button', { name: /export evidence json/i }).click(),
      ]);
      const evidenceExportPath = path.join(artifactDir, `firstlight-evidence-${label}.json`);
      await evidenceDownload.saveAs(evidenceExportPath);
      const evidenceExport = JSON.parse(await fs.readFile(evidenceExportPath, 'utf8'));
      assert.equal(evidenceExport.schema_version, 1, 'evidence export should be versioned');
      assert.equal(evidenceExport.case_type, 'imported-events');
      assert.equal(evidenceExport.source_file_sha256, originalFileHash, 'export should include the original byte hash');
      assert.equal(evidenceExport.evidence[0].id, 'QA-001');
      assert.ok(evidenceExport.limitations.some(item => /not a certified forensic report or chain-of-custody/i.test(item)),
        'export must disclose its forensic and custody limitations');
      await page.getByRole('button', { name: /audit trail/i }).click();
      await page.getByText(originalFileHash, { exact: false }).waitFor();
      await page.getByText(/no external anchor or custody log/i).waitFor();

      await page.getByRole('button', { name: /load synthetic case/i }).click();
      await page.getByText('TRAINING CASE', { exact: true }).waitFor();
      assert.equal(await page.locator('.evidence-table tbody tr').count(), 5,
        'switching from imported data to the synthetic case should reset the evidence source label and rows');

      await fileInput.setInputFiles({
        name: 'training-events.csv',
        mimeType: 'text/csv',
        buffer: Buffer.from('id,timestamp,source,kind,summary\nQA-CSV-001,2026-10-11T10:05:00Z,QA test,message,Unexpected login notice\n'),
      });
      await page.getByRole('status').filter({ hasText: /Imported locally/i }).waitFor();
      await page.getByText('QA-CSV-001').waitFor();

      await fileInput.setInputFiles({
        name: 'invalid-events.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify([{ timestamp: 'not-a-date', summary: 'Invalid timestamp case' }])),
      });
      await page.getByRole('status').filter({ hasText: /Invalid timestamp in event 1/i }).waitFor();

      await fileInput.setInputFiles({
        name: 'missing-timestamp.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify([{ id: 'NO-TIME-1', summary: 'Timestamp must not be fabricated' }])),
      });
      await page.getByRole('status').filter({ hasText: /Missing timestamp in event 1/i }).waitFor();

      await fileInput.setInputFiles({
        name: 'duplicate-events.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify([
          { id: 'DUP-1', timestamp: '2026-10-11T10:00:00Z', summary: 'First event' },
          { id: 'DUP-1', timestamp: '2026-10-11T10:01:00Z', summary: 'Second event' },
        ])),
      });
      await page.getByRole('status').filter({ hasText: /Duplicate evidence ID/i }).waitFor();
    }
  }
  await page.close();
}

try {
  await inspectViewport({ width: 1440, height: 900 }, 'desktop');
  await inspectViewport({ width: 390, height: 844 }, 'mobile');
  await inspectViewport({ width: 320, height: 720 }, 'small-mobile');

  const reducedMotionPage = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await reducedMotionPage.emulateMedia({ reducedMotion: 'reduce' });
  await reducedMotionPage.goto(baseURL + '/firstlight', { waitUntil: 'networkidle' });
  const motion = await reducedMotionPage.evaluate(() => {
    const transition = getComputedStyle(document.querySelector('button')).transitionDuration.split(',')[0].trim();
    const numericDuration = Number.parseFloat(transition);
    return {
      shellAnimation: getComputedStyle(document.querySelector('.shell')).animationName,
      buttonTransitionSeconds: transition.endsWith('ms') ? numericDuration / 1000 : numericDuration,
      buttonTransition: transition,
    };
  });
  assert.equal(motion.shellAnimation, 'none', 'FIRSTLIGHT must disable decorative animation for reduced-motion users');
  assert.ok(motion.buttonTransitionSeconds <= 0.001,
    `interactive transitions should be effectively disabled for reduced-motion users, got ${motion.buttonTransition}`);
  await reducedMotionPage.close();

  const unsupportedMethod = await fetch(baseURL + '/api/analyze');
  assert.equal(unsupportedMethod.status, 405, 'API should reject unsupported methods');
  assert.equal(unsupportedMethod.headers.get('cache-control'), 'no-store',
    'framework-generated 405 responses must not inherit cacheable defaults');

  const unsupportedContentType = await fetch(baseURL + '/api/analyze', {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: JSON.stringify({ input: 'synthetic non-sensitive test input' }),
  });
  assert.equal(unsupportedContentType.status, 415, 'API should reject unsupported request media types');
  assert.equal(unsupportedContentType.headers.get('cache-control'), 'no-store');

  const malformed = await fetch(baseURL + '/api/analyze', {
    method: 'POST', headers: { 'content-type': 'application/json; charset=utf-8' }, body: '{not-json',
  });
  assert.equal(malformed.status, 400, 'API should reject malformed JSON with 400');
  assert.equal(malformed.headers.get('cache-control'), 'no-store', 'API errors must not be cached');
  const empty = await fetch(baseURL + '/api/analyze', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ input: '   ' }),
  });
  assert.equal(empty.status, 400, 'API should reject empty input with 400');
  assert.equal(empty.headers.get('cache-control'), 'no-store', 'empty-input errors must not be cached');

  const oversizedBody = await fetch(baseURL + '/api/analyze', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'x'.repeat(49 * 1024) }),
  });
  assert.equal(oversizedBody.status, 413, 'API should reject bodies above the 48 KiB limit');
  assert.equal(oversizedBody.headers.get('cache-control'), 'no-store');

  const oversizedInput = await fetch(baseURL + '/api/analyze', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'x'.repeat(12_001) }),
  });
  assert.equal(oversizedInput.status, 413, 'API should reject input above 12,000 characters');
  assert.equal(oversizedInput.headers.get('cache-control'), 'no-store');

  // Use a dedicated test IP so this deterministic in-process check does not
  // depend on the unknown bucket consumed by earlier malformed/empty requests.
  const limited = await Promise.all(Array.from({ length: 9 }, () => fetch(baseURL + '/api/analyze', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.91' },
    body: '{not-json',
  })));
  assert.equal(limited.filter(response => response.status === 400).length, 8,
    'the first eight requests should reach JSON validation');
  assert.equal(limited.filter(response => response.status === 429).length, 1,
    'the ninth request from one client should be rate-limited');
  assert.ok(limited.every(response => response.headers.get('cache-control') === 'no-store'),
    'rate-limit and validation errors must not be cached');

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
