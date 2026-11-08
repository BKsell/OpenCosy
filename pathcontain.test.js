'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const pathcontain = require('./pathcontain');

function realpathFn(p) {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return null;
  }
}

test('normalize rejects empty input and NUL bytes', () => {
  assert.strictEqual(pathcontain.normalize('').reason, 'empty');
  assert.strictEqual(pathcontain.normalize(null).reason, 'empty');
  assert.strictEqual(pathcontain.normalize(undefined).reason, 'empty');
  const nul = 'C:\\Users\\x\\Downloads\\a' + '\u0000' + '.txt';
  assert.strictEqual(pathcontain.normalize(nul).reason, 'nul-byte');
});

test('normalize rejects NTFS alternate data streams', () => {
  const ads = 'C:\\Users\\x\\Downloads\\report.pdf:payload.exe';
  assert.strictEqual(pathcontain.normalize(ads).reason, 'alt-stream');
  assert.strictEqual(pathcontain.normalize('C:\\Users\\x\\Downloads\\report.pdf').ok, true);
});

test('normalize strips extended-length and device prefixes', () => {
  const plain = pathcontain.normalize('C:\\Temp\\work');
  assert.strictEqual(plain.ok, true);
  const extended = pathcontain.normalize('\\\\?\\C:\\Temp\\work');
  const unc = pathcontain.normalize('\\\\?\\UNC\\server\\share\\x');
  assert.strictEqual(extended.value, plain.value);
  assert.strictEqual(unc.ok, true);
  assert.strictEqual(unc.value.startsWith('\\\\server\\share'), true);
});

test('within rejects sibling directories sharing a name prefix', () => {
  assert.strictEqual(pathcontain.within('C:\\Users\\x\\Downloads', 'C:\\Users\\x\\Downloads\\a.txt'), true);
  assert.strictEqual(pathcontain.within('C:\\Users\\x\\Downloads', 'C:\\Users\\x\\Downloads-evil\\a.txt'), false);
  assert.strictEqual(pathcontain.within('C:\\Users\\x\\Downloads', 'C:\\Users\\x\\Downloads'), true);
  assert.strictEqual(pathcontain.within('C:\\Users\\x\\Downloads', 'C:\\Users\\x\\a.txt'), false);
});

test('isContained blocks traversal outside the base directory', () => {
  const r = pathcontain.isContained('C:\\Users\\x\\Downloads', 'C:\\Users\\x\\Downloads\\..\\Windows\\System32\\calc.exe');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'outside');
});

test('isContained blocks alternate data streams before opening', () => {
  const r = pathcontain.isContained('C:\\Users\\x\\Downloads', 'C:\\Users\\x\\Downloads\\a.txt:malware.exe');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'alt-stream');
});

test('isContained tolerates a not-yet-created file inside the base directory', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'cosy-path-'));
  const target = path.join(base, 'nested', 'missing.txt');
  const r = pathcontain.isContained(base, target, { realpath: realpathFn });
  assert.strictEqual(r.ok, true);
  fs.rmSync(base, { recursive: true, force: true });
});

test('isContained blocks escaping through a directory junction', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'cosy-link-'));
  const safe = path.join(base, 'Downloads');
  const outside = path.join(base, 'Outside');
  fs.mkdirSync(safe);
  fs.mkdirSync(outside);
  const link = path.join(safe, 'escape');
  let linked = true;
  try {
    fs.symlinkSync(outside, link, 'junction');
  } catch {
    linked = false;
  }
  if (!linked) {
    fs.rmSync(base, { recursive: true, force: true });
    return;
  }
  const hit = pathcontain.isContained(safe, path.join(link, 'payload.exe'), { realpath: realpathFn });
  assert.strictEqual(hit.ok, false);
  assert.strictEqual(hit.reason, 'symlink-escape');
  const clean = pathcontain.isContained(safe, path.join(safe, 'payload.exe'), { realpath: realpathFn });
  assert.strictEqual(clean.ok, true);
  fs.rmSync(base, { recursive: true, force: true });
});

test('hasAltStream only exempts a leading drive letter', () => {
  assert.strictEqual(pathcontain.hasAltStream('C:\\tmp\\a.txt'), false);
  assert.strictEqual(pathcontain.hasAltStream('C:\\tmp\\a.txt:b.exe'), true);
  assert.strictEqual(pathcontain.hasAltStream('\\\\server\\share\\a.txt:b.exe'), true);
  assert.strictEqual(pathcontain.hasAltStream('a.txt:b.exe'), true);
});

test('foldCase follows the host platform', () => {
  const upper = pathcontain.foldCase('C:\\Temp');
  if (pathcontain.IS_WIN) {
    assert.strictEqual(upper, 'c:\\temp');
  } else {
    assert.strictEqual(upper, 'C:\\Temp');
  }
});
