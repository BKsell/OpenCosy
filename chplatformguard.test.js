'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./chplatformguard');

test('缺头不改动', () => {
  const r = guard.applyChPlatformGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('带引号平台合规', () => {
  const headers = { 'sec-ch-ua-platform': '"Windows"' };
  const r = guard.applyChPlatformGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('无引号被拒', () => {
  const headers = { 'sec-ch-ua-platform': 'Windows' };
  const r = guard.applyChPlatformGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['sec-ch-ua-platform'], undefined);
});

test('注入字符被拒', () => {
  const headers = { 'sec-ch-ua-platform': '"Win\\"dows"' };
  const r = guard.applyChPlatformGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('超长被拒', () => {
  const headers = { 'sec-ch-ua-platform': `"${'a'.repeat(80)}"` };
  const r = guard.applyChPlatformGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('多值被拒', () => {
  const headers = { 'sec-ch-ua-platform': ['"Windows"', '"macOS"'] };
  const r = guard.applyChPlatformGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
});

test('空值删除', () => {
  const headers = { 'sec-ch-ua-platform': '' };
  const r = guard.applyChPlatformGuard(headers);
  assert.strictEqual(headers['sec-ch-ua-platform'], undefined);
});
