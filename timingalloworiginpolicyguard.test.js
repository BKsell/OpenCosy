'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./timingalloworiginpolicyguard');

test('缺失时不改动', () => {
  const headers = {};
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.MISSING);
});

test('单一 https 源保留', () => {
  const headers = { 'Timing-Allow-Origin': 'https://example.com' };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('带端口源保留', () => {
  const headers = { 'Timing-Allow-Origin': 'https://example.com:8443' };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('http 源保留', () => {
  const headers = { 'Timing-Allow-Origin': 'http://localhost:3000' };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('非法源被移除', () => {
  const headers = { 'Timing-Allow-Origin': 'example.com' };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.MALFORMED);
  assert.strictEqual('Timing-Allow-Origin' in headers, false);
});

test('通配无凭据保留', () => {
  const headers = { 'Timing-Allow-Origin': '*' };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('通配搭配凭据被移除', () => {
  const headers = {
    'Timing-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true',
  };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.WILDCARD_CREDENTIALED);
  assert.strictEqual('Timing-Allow-Origin' in headers, false);
});

test('凭据为 false 时通配保留', () => {
  const headers = {
    'Timing-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'false',
  };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('条目过多被移除', () => {
  const origins = [];
  for (let i = 0; i < guard.MAX_ORIGINS + 1; i += 1) {
    origins.push('https://a' + i + '.example.com');
  }
  const headers = { 'Timing-Allow-Origin': origins.join(', ') };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.TOO_MANY);
});

test('超长取值被移除', () => {
  const headers = { 'Timing-Allow-Origin': 'x'.repeat(guard.MAX_VALUE_LENGTH + 1) };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.reason, guard.REASON.OVERLONG);
});

test('大小写与尾斜杠归一', () => {
  const parsed = guard.parseTimingAllowOrigin('HTTPS://Example.COM/');
  assert.strictEqual(parsed.reason, guard.REASON.OK);
  assert.deepStrictEqual(parsed.origins, ['https://example.com']);
});

test('数组取首值', () => {
  const headers = { 'Timing-Allow-Origin': ['https://a.example.com', 'https://b.example.com'] };
  const result = guard.applyTimingAllowOriginGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
