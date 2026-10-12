import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCsv } from '../src/lib/firstlight-import.mjs';

test('parses ordinary CSV rows and normalizes headers', () => {
  const rows = parseCsv('id,timestamp,source,summary\n1,2026-10-10T10:00:00Z,mail,Check message');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].id, '1');
  assert.equal(rows[0].source, 'mail');
  assert.equal(rows[0].summary, 'Check message');
});

test('supports BOM, quoted commas, escaped quotes, and multiline fields', () => {
  const rows = parseCsv('\uFEFFid,timestamp,source,summary\n1,2026-10-10T10:00:00Z,mail,"hello, ""world""\nand next line"');
  assert.equal(rows[0].id, '1');
  assert.equal(rows[0].summary, 'hello, "world"\nand next line');
});

test('rejects unclosed quotes and quotes embedded in unquoted fields', () => {
  assert.throws(() => parseCsv('id,summary\n1,"unfinished'), /unclosed quoted field/i);
  assert.throws(() => parseCsv('id,summary\n1,hello"there'), /unexpected quote/i);
});

test('rejects empty and duplicate headers', () => {
  assert.throws(() => parseCsv('id,,summary\n1,x,y'), /headers cannot be empty/i);
  assert.throws(() => parseCsv('id,ID,summary\n1,2,y'), /duplicate column headers/i);
});

test('rejects CSV rows without source timestamps instead of inventing current time', () => {
  assert.throws(
    () => parseCsv('id,source,summary\nEV-1,mail,Message with no timestamp'),
    /missing a timestamp\/time value/i
  );
});

test('rejects duplicate evidence IDs in CSV imports', () => {
  assert.throws(
    () => parseCsv('id,timestamp,summary\nEV-1,2026-10-10T10:00:00Z,First\nEV-1,2026-10-10T10:01:00Z,Second'),
    /duplicate evidence IDs/i
  );
});

test('rejects records with more cells than the header', () => {
  assert.throws(() => parseCsv('id,summary\n1,hello,extra'), /more columns than its header/i);
});

test('rejects header-only CSV and unsupported headers', () => {
  assert.throws(() => parseCsv('id,summary'), /header and at least one event row/i);
  assert.throws(() => parseCsv('name,notes\na,b'), /must include event fields/i);
});
