'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const finishGuard = require('./downloadfinishguard');

const root = path.resolve('/downloads');

function audit(extra) {
  return finishGuard.auditDownloadResult(Object.assign({
    rootDir: root,
    savePath: path.join(root, 'a.zip'),
    expectedName: 'a.zip',
    expectedBytes: 1024,
    actualBytes: 1024,
    isSymlink: false,
    isRegular: true,
  }, extra));
}

test('正常落盘通过', () => {
  const result = audit();
  assert.strictEqual(result.action, finishGuard.ACTION.OK);
  assert.strictEqual(result.reason, finishGuard.REASON.OK);
});

test('缺少保存路径阻断', () => {
  const result = audit({ savePath: '' });
  assert.strictEqual(result.reason, finishGuard.REASON.NO_PATH);
});

test('路径逃出根目录阻断', () => {
  const result = audit({ savePath: path.join(root, '..', 'evil.zip') });
  assert.strictEqual(result.action, finishGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, finishGuard.REASON.OUTSIDE_ROOT);
});

test('前缀相似的兄弟目录阻断', () => {
  const result = audit({ savePath: `${root}-evil${path.sep}a.zip` });
  assert.strictEqual(result.reason, finishGuard.REASON.OUTSIDE_ROOT);
});

test('符号链接阻断', () => {
  const result = audit({ isSymlink: true });
  assert.strictEqual(result.reason, finishGuard.REASON.SYMLINK);
});

test('非普通文件阻断', () => {
  const result = audit({ isRegular: false });
  assert.strictEqual(result.reason, finishGuard.REASON.NOT_REGULAR);
});

test('0 字节阻断', () => {
  const result = audit({ actualBytes: 0 });
  assert.strictEqual(result.reason, finishGuard.REASON.EMPTY_FILE);
});

test('文件明显偏小阻断', () => {
  const result = audit({ actualBytes: 100, expectedBytes: 2048 });
  assert.strictEqual(result.action, finishGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, finishGuard.REASON.SHORT_BYTES);
});

test('文件略大告警', () => {
  const result = audit({ actualBytes: 4096, expectedBytes: 1024 });
  assert.strictEqual(result.action, finishGuard.ACTION.WARN);
  assert.strictEqual(result.reason, finishGuard.REASON.OVERSIZE);
});

test('容忍尾部字节误差', () => {
  const result = audit({ actualBytes: 1000, expectedBytes: 1024 });
  assert.strictEqual(result.reason, finishGuard.REASON.OK);
});

test('文件名不一致阻断', () => {
  const result = audit({ expectedName: 'a.zip', savePath: path.join(root, 'b.zip') });
  assert.strictEqual(result.reason, finishGuard.REASON.NAME_MISMATCH);
});

test('未知期望大小时仅做结构校验', () => {
  const result = audit({ expectedBytes: undefined, actualBytes: 10 });
  assert.strictEqual(result.reason, finishGuard.REASON.OK);
});

test('isContained 正确判定边界', () => {
  assert.strictEqual(finishGuard.isContained(root, path.join(root, 'x', 'y.zip')), true);
  assert.strictEqual(finishGuard.isContained(root, root), true);
  assert.strictEqual(finishGuard.isContained(root, path.join(root, '..', 'y.zip')), false);
});

test('描述函数输出原因', () => {
  const result = audit({ isSymlink: true });
  assert.ok(finishGuard.describeDownloadAudit(result).includes(finishGuard.REASON.SYMLINK));
});
