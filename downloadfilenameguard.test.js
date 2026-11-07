'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./downloadfilenameguard');

test('普通文件名保持不变', () => {
  const r = guard.sanitizeFilename('report-2024.pdf');
  assert.strictEqual(r.name, 'report-2024.pdf');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('路径分隔符被剥离', () => {
  const r = guard.sanitizeFilename('../../etc/passwd');
  assert.strictEqual(r.name, 'passwd');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.PATH_TRAVERSAL);
});

test('Windows 反斜杠路径被剥离', () => {
  const r = guard.sanitizeFilename('C:\\Users\\x\\evil.exe');
  assert.strictEqual(r.name, 'evil.exe');
  assert.strictEqual(r.reason, guard.REASON.PATH_TRAVERSAL);
});

test('控制字符被移除', () => {
  const r = guard.sanitizeFilename('bad\u0000name.txt');
  assert.strictEqual(r.name, 'badname.txt');
});

test('保留设备名被改写', () => {
  const r = guard.sanitizeFilename('CON.txt');
  assert.strictEqual(r.name.includes('CON_'), true);
  assert.strictEqual(r.reason, guard.REASON.RESERVED);
});

test('尾部点与空格被去除', () => {
  const r = guard.sanitizeFilename('name.  ');
  assert.strictEqual(r.name, 'name');
  assert.strictEqual(r.reason, guard.REASON.TRAILING_DOT);
});

test('双向覆盖字符被移除', () => {
  const r = guard.sanitizeFilename('invoice\u202egnp.exe');
  assert.strictEqual(r.name.includes('\u202e'), false);
  assert.strictEqual(r.reason, guard.REASON.BIDI_OVERRIDE);
});

test('超长文件名被截断并保留扩展名', () => {
  const r = guard.sanitizeFilename('a'.repeat(200) + '.tar.gz', { maxLength: 24 });
  assert.ok(r.name.length <= 24);
  assert.ok(r.name.endsWith('.gz'));
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('空文件名退化为 download', () => {
  const r = guard.sanitizeFilename('   ');
  assert.strictEqual(r.name, 'download');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('危险扩展名要求确认', () => {
  const r = guard.applyDownloadFilenameGuard({ filename: 'setup.exe' });
  assert.strictEqual(r.riskyExtension, true);
  assert.strictEqual(r.forceConfirm, true);
});

test('批量审计统计重写数', () => {
  const report = guard.auditFilenameBatch(['ok.txt', '../evil.js', 'CON']);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.rewritten, 2);
});
