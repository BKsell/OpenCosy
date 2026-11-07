'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./mimetypepolicyguard');

test('标准文本类型通过', () => {
  const r = guard.applyMimeTypePolicyGuard('text/html; charset=utf-8');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.essence, 'text/html');
});

test('空值被拒', () => {
  const r = guard.inspectContentType('');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('缺少子类型被拒', () => {
  const r = guard.inspectContentType('text/');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('通配类型被拒', () => {
  const r = guard.inspectContentType('*/*');
  assert.strictEqual(r.reason, guard.REASON.WILDCARD);
});

test('非 UTF-8 字符集被拒', () => {
  const r = guard.inspectContentType('text/html; charset=gbk');
  assert.strictEqual(r.reason, guard.REASON.BAD_CHARSET);
});

test('us-ascii 允许', () => {
  const r = guard.inspectContentType('text/plain; charset=us-ascii');
  assert.strictEqual(r.ok, true);
});

test('重复参数被拒', () => {
  const r = guard.inspectContentType('text/html; charset=utf-8; charset=utf-8');
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_PARAM);
});

test('禁止 HTML 时被拒', () => {
  const r = guard.inspectContentType('text/html; charset=utf-8', { allowHtml: false });
  assert.strictEqual(r.reason, guard.REASON.HTML_DISALLOWED);
});

test('下载通用类型被拒', () => {
  const r = guard.inspectContentType('application/octet-stream', { download: true });
  assert.strictEqual(r.reason, guard.REASON.SNIFFABLE);
});

test('图片类型通过', () => {
  const r = guard.inspectContentType('image/png');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.isText, false);
});

test('缺等号的参数被拒', () => {
  const r = guard.inspectContentType('text/plain; charset');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
