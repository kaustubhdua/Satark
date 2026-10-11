import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../src/components/react-bits.tsx', import.meta.url), 'utf8');
const styles = await readFile(new URL('../src/components/react-bits.css', import.meta.url), 'utf8');

test('all five visual components are exported and styled', () => {
  for (const name of ['SplitFlapText', 'LatticeLoader', 'ThoughtLine', 'Radar', 'CodeSlots']) {
    assert.match(source, new RegExp('export function ' + name + '\\b'), name + ' export exists');
  }
  assert.match(source, /prefers-reduced-motion/);
  assert.ok(styles.includes('@media(prefers-reduced-motion:reduce)'));
});

test('components expose expected interaction and accessibility hooks', () => {
  for (const prop of ['onChange', 'onComplete', 'ariaLabel', 'showTimer', 'mouseInteraction', 'settleAfter', 'padTo']) {
    assert.ok(source.includes(prop), 'expected prop or behavior: ' + prop);
  }
  assert.match(source, /aria-live="polite"/);
  assert.match(source, /aria-hidden="true"/);
});

test('code-slot demo and loading visuals remain explicitly present', () => {
  assert.match(source, /data-status=\{status\}/);
  assert.match(source, /lattice-grid/);
  assert.match(source, /split-flap-tile/);
  assert.match(source, /radar-canvas/);
  assert.match(source, /code-slot-success/);
});
