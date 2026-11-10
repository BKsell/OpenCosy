'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { stripControlChars, sanitizeDisplayTitle } = require('./modutil');

test('双向覆盖与零宽格式字符被清除，标题不再能被视觉反转', () => {
  const raw = '\u202e' + 'spj.exe' + '\u202c';
  assert.strictEqual(stripControlChars(raw), 'spj.exe');
  assert.strictEqual(sanitizeDisplayTitle(raw, 300), 'spj.exe');
});

test('隔离符与零宽连接符一并清除', () => {
  const raw = 'a\u2066b\u2069\u200b\u200d\u200e\u200fc\u2060\uFEFFd';
  assert.strictEqual(stripControlChars(raw), 'abcd');
});

test('C1 控制区被清除，正常拉丁与 RTL 字母保留', () => {
  assert.strictEqual(stripControlChars('a\u0085b\u009fc'), 'abc');
  assert.strictEqual(stripControlChars('مرحبا שלום'), 'مرحبا שלום');
});
