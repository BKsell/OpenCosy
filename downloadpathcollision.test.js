'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const collision = require('./downloadpathcollision');

const DIR = path.resolve('/downloads');

test('first free name is used when nothing collides', () => {
  const plan = collision.planUniquePath({ dir: DIR, filename: 'report.pdf', taken: [] });
  assert.strictEqual(plan.ok, true);
  assert.strictEqual(plan.name, 'report.pdf');
  assert.strictEqual(plan.path, path.join(DIR, 'report.pdf'));
  assert.strictEqual(plan.attempts, 1);
});

test('collisions append numeric suffixes before the extension', () => {
  const plan = collision.planUniquePath({ dir: DIR, filename: 'report.pdf', taken: ['report.pdf', 'report (1).pdf'] });
  assert.strictEqual(plan.ok, true);
  assert.strictEqual(plan.name, 'report (2).pdf');
  assert.strictEqual(plan.attempts, 3);
});

test('case-insensitive collisions are detected by default', () => {
  const plan = collision.planUniquePath({ dir: DIR, filename: 'Report.PDF', taken: ['report.pdf'] });
  assert.strictEqual(plan.name, 'Report (1).PDF');
  const sensitive = collision.planUniquePath({
    dir: DIR, filename: 'Report.PDF', taken: ['report.pdf'], caseInsensitive: false,
  });
  assert.strictEqual(sensitive.name, 'Report.PDF');
});

test('taken sets accept absolute paths and object keys', () => {
  const fromPaths = collision.planUniquePath({
    dir: DIR, filename: 'a.txt', taken: new Set([path.join(DIR, 'a.txt')]),
  });
  assert.strictEqual(fromPaths.ok, true);
  assert.strictEqual(fromPaths.name, 'a (1).txt');
  const fromNames = collision.planUniquePath({ dir: DIR, filename: 'a.txt', taken: new Set(['A.TXT']) });
  assert.strictEqual(fromNames.name, 'a (1).txt');
  const fromObject = collision.planUniquePath({ dir: DIR, filename: 'b.txt', taken: { 'B.TXT': true } });
  assert.strictEqual(fromObject.name, 'b (1).txt');
});

test('invalid filenames and directories are rejected', () => {
  for (const filename of ['', '.', '..', 'a/b', 'a\\b', '   ']) {
    const plan = collision.planUniquePath({ dir: DIR, filename, taken: [] });
    assert.strictEqual(plan.ok, false);
    assert.strictEqual(plan.reason, collision.REASON.INVALID_NAME);
  }
  for (const dir of ['', 'relative/dir', '.']) {
    const plan = collision.planUniquePath({ dir, filename: 'a.txt', taken: [] });
    assert.strictEqual(plan.ok, false);
    assert.strictEqual(plan.reason, collision.REASON.INVALID_DIR);
  }
});

test('exhaustion is reported instead of looping forever', () => {
  const taken = ['x.txt', 'x (1).txt', 'x (2).txt'];
  const plan = collision.planUniquePath({ dir: DIR, filename: 'x.txt', taken, maxAttempts: 3 });
  assert.strictEqual(plan.ok, false);
  assert.strictEqual(plan.reason, collision.REASON.EXHAUSTED);
  assert.strictEqual(plan.attempts, 3);
});

test('overlong names are truncated on byte boundaries', () => {
  const filename = `${'字'.repeat(100)}.png`;
  const plan = collision.planUniquePath({ dir: DIR, filename, taken: [] });
  assert.strictEqual(plan.ok, true);
  assert.ok(collision.nameBytes(plan.name) <= collision.MAX_NAME_BYTES);
  assert.ok(plan.name.endsWith('.png'));
  assert.strictEqual(plan.truncated, true);
});

test('suffix growth still respects the byte ceiling', () => {
  const stem = 'a'.repeat(collision.MAX_STEM_BYTES);
  const taken = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((index) => {
    if (index === 0) return `${stem}.bin`;
    return `${stem} (${index}).bin`;
  });
  const plan = collision.planUniquePath({ dir: DIR, filename: `${stem}.bin`, taken });
  assert.strictEqual(plan.ok, true);
  assert.ok(collision.nameBytes(plan.name) <= collision.MAX_NAME_BYTES);
  assert.ok(/ \(\d+\)\.bin$/.test(plan.name));
});

test('extension splitting keeps long suffixes as part of the stem', () => {
  assert.deepStrictEqual(collision.splitExtension('archive.tar.gz'), { stem: 'archive.tar', ext: '.gz' });
  assert.deepStrictEqual(collision.splitExtension('noext'), { stem: 'noext', ext: '' });
  assert.deepStrictEqual(collision.splitExtension('.hidden'), { stem: '.hidden', ext: '' });
  assert.deepStrictEqual(collision.splitExtension('trailing.'), { stem: 'trailing.', ext: '' });
  const longExt = `.${'x'.repeat(30)}`;
  assert.deepStrictEqual(collision.splitExtension(`name${longExt}`), { stem: `name${longExt}`, ext: '' });
});

test('unicode folding preserves non-ASCII names', () => {
  const plan = collision.planUniquePath({ dir: DIR, filename: '发票.pdf', taken: ['发票.pdf'] });
  assert.strictEqual(plan.name, '发票 (1).pdf');
  assert.strictEqual(collision.foldName('ÄÖÜ'), 'äöü');
});

test('reserveIndex registers only new names', () => {
  const taken = ['Report.pdf'];
  assert.strictEqual(collision.reserveIndex(taken, 'report.pdf'), false);
  assert.strictEqual(collision.reserveIndex(taken, 'other.pdf'), true);
  assert.strictEqual(collision.reserveIndex(taken, 'other.pdf'), false);
});

test('describeAllocation explains each outcome', () => {
  assert.match(collision.describeAllocation({ reason: collision.REASON.OK, name: 'a.txt', attempts: 1 }), /保存为/);
  assert.match(collision.describeAllocation({ reason: collision.REASON.OK, name: 'a (1).txt', attempts: 2 }), /避开重名/);
  assert.match(collision.describeAllocation({ reason: collision.REASON.EXHAUSTED, attempts: 5 }), /同名文件过多/);
  assert.match(collision.describeAllocation({ reason: collision.REASON.INVALID_NAME }), /路径分隔符/);
  assert.match(collision.describeAllocation({ reason: collision.REASON.INVALID_DIR }), /绝对路径/);
  assert.match(collision.describeAllocation(null), /缺失/);
});
