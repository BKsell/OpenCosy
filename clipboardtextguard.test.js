'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./clipboardtextguard');

test('普通文本不变更', () => {
  const r = guard.applyClipboardTextGuard('hello\nworld');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.text, 'hello\nworld');
});

test('空字节被清除', () => {
  const r = guard.applyClipboardTextGuard('a\u0000b');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.NUL_STRIPPED);
  assert.strictEqual(r.text, 'ab');
});

test('控制字符替换为空格', () => {
  const r = guard.sanitizeClipboardText('a\u0007b');
  assert.strictEqual(r.reason, guard.REASON.CONTROL_STRIPPED);
  assert.strictEqual(r.text, 'a b');
});

test('保留制表符与换行', () => {
  const r = guard.sanitizeClipboardText('a\tb\nc');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.text, 'a\tb\nc');
});

test('CRLF 归一化为 LF', () => {
  const r = guard.applyClipboardTextGuard('a\r\nb');
  assert.strictEqual(r.text, 'a\nb');
});

test('非文本被拒', () => {
  const r = guard.sanitizeClipboardText(42);
  assert.strictEqual(r.reason, guard.REASON.NOT_TEXT);
  assert.strictEqual(r.ok, false);
});

test('空文本被拒', () => {
  const r = guard.sanitizeClipboardText('');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('超体积被拒', () => {
  const r = guard.sanitizeClipboardText('x'.repeat(guard.MAX_BYTES + 1));
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('行数过多被拒', () => {
  const r = guard.sanitizeClipboardText('\n'.repeat(guard.MAX_LINES + 1));
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY_LINES);
});

test('超出输出上限被截断', () => {
  const text = 'a'.repeat(guard.MAX_OUTPUT_BYTES + 10) + '\u0007';
  const r = guard.sanitizeClipboardText(text);
  assert.strictEqual(r.reason, guard.REASON.CONTROL_STRIPPED);
  assert.ok(r.text.length <= guard.MAX_OUTPUT_BYTES);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
