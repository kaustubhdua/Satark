import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const page = await readFile(new URL('../src/app/reports/page.tsx', import.meta.url), 'utf8');
const css = await readFile(new URL('../src/app/globals.css', import.meta.url), 'utf8');

test('reports provide a browser-native print-to-PDF flow', () => {
  assert.match(page, /function printPdf\(\)/);
  assert.match(page, /window\.print\(\)/);
  assert.match(page, /Print \/ Save as PDF/);
  assert.match(page, /print-report-sheet/);
  assert.match(page, /Prepared for export from the current review session/);
  assert.doesNotMatch(page, /Generated \{new Date\(\)\.toISOString\(\)\}/);
  assert.match(page, /Triage output is not independently verified evidence/);
});

test('print stylesheet hides interactive UI and keeps the report sheet readable', () => {
  assert.match(css, /@media print/);
  assert.match(css, /\.report-print-page \.topbar/);
  assert.match(css, /\.report-print-page \.print-report-sheet \{ display: block !important/);
  assert.match(css, /@page \{ size: A4/);
});
