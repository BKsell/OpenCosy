'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./publickeypinsguard');

const PIN_A = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const PIN_B = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

function h(value) {
  return { 'public-key-pins': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyPublicKeyPinsGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('任何取值都被整头剥除', () => {
  const headers = h(`max-age=60; pin-sha256="${PIN_A}"`);
  const r = guard.applyPublicKeyPinsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DEPRECATED);
  assert.strictEqual(headers['public-key-pins'], undefined);
});

test('缺备份钉被识别', () => {
  const r = guard.inspectPublicKeyPins(`max-age=60; pin-sha256="${PIN_A}"`);
  assert.strictEqual(r.reason, guard.REASON.NO_BACKUP_PIN);
  assert.deepStrictEqual(r.pins, [PIN_A]);
});

test('双钉合规', () => {
  const r = guard.inspectPublicKeyPins(`max-age=60; pin-sha256="${PIN_A}"; pin-sha256="${PIN_B}"`);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.pins.length, 2);
});

test('超长缓存时长被识别', () => {
  const r = guard.inspectPublicKeyPins(`max-age=9999999; pin-sha256="${PIN_A}"; pin-sha256="${PIN_B}"`);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_MAX_AGE);
});

test('上报地址被识别', () => {
  const r = guard.inspectPublicKeyPins(`max-age=60; pin-sha256="${PIN_A}"; pin-sha256="${PIN_B}"; report-uri="https://example.com/r"`);
  assert.strictEqual(r.reason, guard.REASON.REPORT_URI);
});

test('非法缓存时长被识别', () => {
  const r = guard.inspectPublicKeyPins('max-age=forever');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('未知指令被识别', () => {
  const r = guard.inspectPublicKeyPins(`max-age=60; made-up; pin-sha256="${PIN_A}"`);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('空值返回 malformed', () => {
  const r = guard.inspectPublicKeyPins('   ');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长返回 overlong', () => {
  const r = guard.inspectPublicKeyPins('a'.repeat(1200));
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('头键大小写被正确处理', () => {
  const headers = { 'Public-Key-Pins': ['max-age=0'] };
  const r = guard.applyPublicKeyPinsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['Public-Key-Pins'], undefined);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
