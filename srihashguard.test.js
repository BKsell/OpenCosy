'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const guard = require('./srihashguard');

function sri(algorithm, buffer) {
  return algorithm + '-' + crypto.createHash(algorithm).update(buffer).digest('base64');
}

const BODY = Buffer.from('console.log("cosy")');

test('合法 SHA-256 校验值通过', () => {
  const r = guard.applySriGuard(BODY, sri('sha256', BODY));
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.matched, true);
  assert.deepStrictEqual(r.algorithms, ['sha256']);
});

test('多算法中任一匹配即通过', () => {
  const value = sri('sha512', BODY) + ' ' + sri('sha384', BODY);
  const r = guard.applySriGuard(BODY, value);
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.algorithms.sort(), ['sha384', 'sha512']);
});

test('内容被篡改被拒', () => {
  const r = guard.applySriGuard(Buffer.from('console.log("evil")'), sri('sha256', BODY));
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MISMATCH);
});

test('仅 SHA-1 被拒', () => {
  const value = 'sha1-' + crypto.createHash('sha1').update(BODY).digest('base64');
  const r = guard.parseSri(value);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, guard.REASON.NO_STRONG);
});

test('MD5 被拒', () => {
  const value = 'md5-' + crypto.createHash('md5').update(BODY).digest('base64');
  const r = guard.parseSri(value);
  assert.strictEqual(r.reason, guard.REASON.NO_STRONG);
});

test('摘要长度不符被拒', () => {
  const r = guard.parseSri('sha256-' + Buffer.alloc(16).toString('base64'));
  assert.strictEqual(r.reason, guard.REASON.DIGEST_LENGTH);
});

test('格式非法被拒', () => {
  const r = guard.parseSri('sha256');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('空值被拒', () => {
  const r = guard.parseSri('');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('非 Buffer 内容被拒', () => {
  const r = guard.verifyIntegrity('text', sri('sha256', BODY));
  assert.strictEqual(r.reason, guard.REASON.NOT_BUFFER);
});

test('带选项符号的校验值被拒', () => {
  const r = guard.parseSri('?' + sri('sha256', BODY));
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
