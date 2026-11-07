'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./contentmd5guard');

const VALID_MD5_BASE64 = '1B2M2Y8AsgTpgAmY7PhCfg==';

test('缺省头不动作', () => {
  const headers = {};
  const result = guard.applyContentMd5Guard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('合法 MD5 仍被移除', () => {
  const headers = { 'Content-MD5': VALID_MD5_BASE64 };
  const result = guard.applyContentMd5Guard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.WEAK_MD5);
  assert.equal(headers['Content-MD5'], undefined);
});

test('大小写键位移除', () => {
  const headers = { 'content-md5': VALID_MD5_BASE64 };
  const result = guard.applyContentMd5Guard(headers);
  assert.equal(Object.keys(headers).length, 0);
});

test('非法摘要标记格式错误', () => {
  const headers = { 'Content-MD5': 'deadbeef' };
  const result = guard.applyContentMd5Guard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED_DIGEST);
  assert.equal(headers['Content-MD5'], undefined);
});

test('超长取值标记超长', () => {
  const headers = { 'Content-MD5': 'A'.repeat(80) };
  const result = guard.applyContentMd5Guard(headers);
  assert.equal(result.reason, guard.REASON.OVERLONG);
});

test('非字符串取值标记格式错误', () => {
  const headers = { 'Content-MD5': ['a', 'b'] };
  const result = guard.applyContentMd5Guard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED_DIGEST);
});

test('空值标记格式错误', () => {
  const headers = { 'Content-MD5': '' };
  const result = guard.applyContentMd5Guard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED_DIGEST);
});

test('描述文本覆盖全部分支', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.equal(typeof guard.describeReason(reason), 'string');
  }
});
