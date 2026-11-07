'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./acceptchpolicyguard');

function h(accept, critical) {
  const headers = {};
  if (accept !== undefined) headers['Accept-CH'] = accept;
  if (critical !== undefined) headers['Critical-CH'] = critical;
  return headers;
}

test('缺失两个头返回 missing', () => {
  const r = guard.applyAcceptChGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
  assert.strictEqual(r.changed, false);
});

test('一致声明不改动', () => {
  const headers = h('sec-ch-ua, sec-ch-ua-mobile', 'sec-ch-ua');
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.deepStrictEqual(r.missing, []);
});

test('只有 Accept-CH 不改动', () => {
  const headers = h('sec-ch-ua');
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('Critical-CH 不在 Accept-CH 中被剥除', () => {
  const headers = h('sec-ch-ua', 'sec-ch-ua-mobile');
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.CRITICAL_UNKNOWN);
  assert.deepStrictEqual(r.missing, ['sec-ch-ua-mobile']);
  assert.strictEqual(headers['Critical-CH'], undefined);
});

test('Critical-CH 存在但 Accept-CH 为空被剥除', () => {
  const headers = h(undefined, 'sec-ch-ua');
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.CRITICAL_EMPTY);
});

test('非法提示词被剥除', () => {
  const headers = h('Sec_CH_UA');
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('大写提示词按小写归一', () => {
  const headers = h('SEC-CH-UA');
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('提示数量超限被剥除', () => {
  const tokens = [];
  for (let i = 0; i < guard.MAX_HINTS + 1; i += 1) {
    tokens.push(`hint-${i}`);
  }
  const headers = h(tokens.join(', '));
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('单提示超长被剥除', () => {
  const headers = h(`a${'-b'.repeat(guard.MAX_HINT_LENGTH)}`);
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('整字段超长被剥除', () => {
  const headers = h('sec-ch-ua,'.padEnd(guard.MAX_FIELD_LENGTH + 10, 'x'));
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('小写键名命中', () => {
  const headers = { 'accept-ch': 'sec-ch-ua', 'critical-ch': 'sec-ch-ua-mobile' };
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.CRITICAL_UNKNOWN);
  assert.strictEqual(headers['critical-ch'], undefined);
});

test('数组取值拼接后判定', () => {
  const headers = { 'Accept-CH': ['sec-ch-ua'], 'Critical-CH': ['sec-ch-ua'] };
  const r = guard.applyAcceptChGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /非法/);
  assert.match(guard.describeReason(guard.REASON.TOO_MANY), /上限/);
  assert.match(guard.describeReason(guard.REASON.CRITICAL_UNKNOWN), /未在/);
  assert.match(guard.describeReason(guard.REASON.CRITICAL_EMPTY), /为空/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /超长/);
  assert.match(guard.describeReason(guard.REASON.OK), /一致/);
});
