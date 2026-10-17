import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const page = fs.readFileSync(new URL('../src/app/cases/page.tsx', import.meta.url), 'utf8');
const navigation = fs.readFileSync(new URL('../src/app/site-header.tsx', import.meta.url), 'utf8');
const homepage = fs.readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
const browserSmoke = fs.readFileSync(new URL('./browser-smoke.mjs', import.meta.url), 'utf8');
const api = fs.readFileSync(new URL('../src/app/api/cases/route.ts', import.meta.url), 'utf8');
const firstlightCasePanel = fs.readFileSync(new URL('../src/app/firstlight/persistent-case-panel.tsx', import.meta.url), 'utf8');

test('case workspace reads and creates cases through tenant-scoped authenticated helpers', () => {
  assert.ok(page.includes('loadCaseList(selected.id)'));
  assert.ok(page.includes('listCases(tenantId)'));
  assert.match(page, /createCase\(tenant\.id, title\.trim\(\), severity\)/);
  assert.match(page, /tenant_id: tenant\.id/);
  assert.match(api, /created_by: user\.id/);
  assert.match(api, /redirect: 'error'/);
});

test('case field changes go through the authenticated case API and validate returned tenant', () => {
  assert.match(page, /method: 'PATCH'/);
  assert.match(page, /\[field\]: value/);
  assert.match(page, /updated\.tenant_id !== tenant\.id/);
  assert.match(api, /export async function PATCH/);
  assert.match(api, /At least one case field must be provided for update/);
});

test('case workspace includes useful filtering and read-only handling for viewer role', () => {
  assert.match(page, /id="case-search"/);
  assert.match(page, /id="case-status-filter"/);
  assert.match(page, /const readOnly = tenant\?\.role\.toLowerCase\(\) === 'viewer'/);
  assert.match(page, /disabled=\{readOnly \|\| busyCase === item\.id\}/);
  assert.match(page, /No cases in this workspace yet/);
});

test('case workspace is discoverable and included in browser acceptance', () => {
  assert.match(navigation, /href: '\/cases', label: 'Cases'/);
  assert.match(homepage, /title: 'Persistent case workspace'/);
  assert.match(page, /\/firstlight\?case_id=/);
  assert.match(firstlightCasePanel, /get\('case_id'\)/);
  assert.match(firstlightCasePanel, /That case is not available in the currently selected workspace/);
  assert.match(browserSmoke, /path: '\/cases', heading: \/manage saved cases\|case management\/i/);
});
