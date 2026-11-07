'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./downloadpathguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows pdf inside target dir', () => {
  const result = guard.evaluateDownloadPath(path.join(root, 'report.pdf'), { targetDir: root, allowTemp: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks system directory', () => {
  const result = guard.evaluateDownloadPath('/etc/report.pdf', { targetDir: root });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.SYSTEM_DIR);
});

test('blocks temp directory', () => {
  const result = guard.evaluateDownloadPath('/tmp/report.pdf', { targetDir: root });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TEMP_DIR);
});

test('blocks relative path', () => {
  const result = guard.evaluateDownloadPath('report.pdf', { targetDir: root });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.NOT_ABSOLUTE);
});

test('blocks path outside target', () => {
  const result = guard.evaluateDownloadPath('/opt/other/report.pdf', { targetDir: root });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.OUTSIDE_TARGET);
});

test('blocks startup folder', () => {
  const result = guard.evaluateDownloadPath('/opt/x/Start Menu/Programs/Startup/a.exe', { targetDir: root });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.EXECUTABLE_DIR);
});

