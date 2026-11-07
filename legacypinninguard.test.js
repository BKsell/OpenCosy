'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./legacypinninguard');

test('无废弃安全头时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyLegacyPinninguard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('Expect-CT 被剥离', () => {
  const headers = { 'expect-ct': ['max-age=86400, enforce'] };
  const r = guard.applyLegacyPinninguard(headers);
  assert.strictEqual(r.reason, guard.REASON.DEPRECATED);
  assert.strictEqual(headers['expect-ct'], undefined);
});

test('HPKP 被剥离', () => {
  const headers = { 'public-key-pins': ['pin-sha256="AAAA"; max-age=600'] };
  const r = guard.applyLegacyPinninguard(headers);
  assert.strictEqual(r.reason, guard.REASON.DEPRECATED);
  assert.strictEqual(headers['public-key-pins'], undefined);
});

test('HPKP 缺少 max-age 判不安全固定', () => {
  const headers = { 'public-key-pins': ['pin-sha256="AAAA"'] };
  const r = guard.applyLegacyPinninguard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_PIN);
  assert.strictEqual(headers['public-key-pins'], undefined);
});

test('Report-Only 变体同样剥离', () => {
  const headers = { 'public-key-pins-report-only': ['pin-sha256="AAAA"; max-age=60'] };
  const r = guard.applyLegacyPinninguard(headers);
  assert.strictEqual(headers['public-key-pins-report-only'], undefined);
});

test('超长取值判格式非法', () => {
  const headers = { 'expect-ct': [`max-age=${'9'.repeat(guard.MAX_VALUE_LENGTH)}`] };
  const r = guard.applyLegacyPinninguard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('大小写不敏感键名被识别', () => {
  const headers = { 'Expect-CT': ['max-age=0'] };
  const r = guard.applyLegacyPinninguard(headers);
  assert.strictEqual(r.reason, guard.REASON.DEPRECATED);
  assert.strictEqual(headers['Expect-CT'], undefined);
});

test('pinLooksUnsafe 语义', () => {
  assert.strictEqual(guard.pinLooksUnsafe('pin-sha256="x"; max-age=60'), false);
  assert.strictEqual(guard.pinLooksUnsafe('pin-sha256="x"'), true);
  assert.strictEqual(guard.pinLooksUnsafe(''), false);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
