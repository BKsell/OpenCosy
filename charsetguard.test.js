'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./charsetguard');

function h(value) {
  return { 'content-type': [value] };
}

test('普通 UTF-8 不改动', () => {
  const headers = h('text/html; charset=utf-8');
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(headers['content-type'][0], 'text/html; charset=utf-8');
});

test('缺少 Content-Type 返回 missing', () => {
  const r = guard.applyCharsetGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('UTF-7 被剥除并回落 UTF-8', () => {
  const headers = h('text/html; charset=UTF-7');
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARSET);
  assert.strictEqual(headers['content-type'][0], 'text/html; charset=utf-8');
});

test('非 HTML 的 UTF-7 只剥 charset', () => {
  const headers = h('text/plain; charset=utf-7');
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARSET);
  assert.strictEqual(headers['content-type'][0], 'text/plain');
});

test('CESU-8 与 SCSU 均判不安全', () => {
  for (const cs of ['cesu-8', 'scsu', 'bocu-1', 'hz-gb-2312']) {
    const r = guard.inspectCharset(h(`text/html; charset=${cs}`));
    assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARSET);
  }
});

test('重复 charset 保留首个', () => {
  const headers = h('text/html; charset=utf-8; charset=iso-8859-1');
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_CHARSET);
  assert.strictEqual(headers['content-type'][0], 'text/html; charset=utf-8');
});

test('非法 token 的 charset 被丢弃', () => {
  const headers = h('text/html; charset="utf 8"');
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_CHARSET_TOKEN);
  assert.strictEqual(headers['content-type'][0], 'text/html; charset=utf-8');
});

test('非法结构整条剥离', () => {
  const headers = h('text/html;;charset=utf-8');
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['content-type'], undefined);
});

test('超长头整条剥离', () => {
  const headers = h('text/html; charset=utf-8; x=' + 'a'.repeat(300));
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['content-type'], undefined);
});

test('保留其它参数', () => {
  const headers = h('text/html; boundary="a;b"; charset=utf-7');
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_CHARSET);
  assert.strictEqual(headers['content-type'][0], 'text/html; boundary=a;b; charset=utf-8');
});

test('大小写键名与大小写字符集都识别', () => {
  const headers = { 'Content-Type': ['TEXT/HTML; Charset="UtF-7"'] };
  const r = guard.applyCharsetGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['Content-Type'][0], 'text/html; charset=utf-8');
});

test('带引号的合法值被去引号', () => {
  const r = guard.inspectCharset(h('text/html; charset="utf-8"'));
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.header, 'text/html; charset="utf-8"');
});

test('parseMediaType 拒绝空类型', () => {
  assert.strictEqual(guard.parseMediaType(''), null);
  assert.strictEqual(guard.parseMediaType('; charset=utf-8'), null);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
