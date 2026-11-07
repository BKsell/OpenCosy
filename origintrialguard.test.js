'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./origintrialguard');

function token(payload) {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
}

function h(value) {
  return { 'origin-trial': [value] };
}

function future() {
  return Math.floor(Date.now() / 1000) + 3600;
}

function past() {
  return Math.floor(Date.now() / 1000) - 3600;
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('同源合规令牌不改动', () => {
  const headers = h(token({ origin: 'https://example.com', feature: 'ExampleFeature', expiry: future() }));
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('外站来源声明被剔除', () => {
  const headers = h(token({ origin: 'https://evil.example', feature: 'ExampleFeature', expiry: future() }));
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.FOREIGN_ORIGIN);
});

test('过期令牌被剔除', () => {
  const headers = h(token({ origin: 'https://example.com', feature: 'ExampleFeature', expiry: past() }));
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.EXPIRED);
});

test('高风险特性被剔除', () => {
  const headers = h(token({ origin: 'https://example.com', feature: 'Fledge', expiry: future() }));
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.HIGH_RISK_FEATURE);
});

test('子域覆盖声明被剔除', () => {
  const headers = h(token({ origin: 'https://example.com', feature: 'ExampleFeature', expiry: future(), isSubdomain: true }));
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.SUBDOMAIN_GRANT);
});

test('无法解码令牌被识别', () => {
  const r = guard.inspectOriginTrial('not-a-valid-token-at-all-but-long-enough', 'https://example.com');
  assert.strictEqual(r.reason, guard.REASON.UNDECODABLE);
});

test('令牌数量超限整头剥除', () => {
  const one = token({ origin: 'https://example.com', feature: 'ExampleFeature', expiry: future() });
  const headers = h(Array.from({ length: 9 }, () => one).join(', '));
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
});

test('空值整头剥除', () => {
  const headers = h('   ');
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长取值整头剥除', () => {
  const headers = h('a'.repeat(4200));
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('多令牌混合只保留合规项', () => {
  const good = token({ origin: 'https://example.com', feature: 'ExampleFeature', expiry: future() });
  const bad = token({ origin: 'https://evil.example', feature: 'OtherFeature', expiry: future() });
  const headers = h(`${good}, ${bad}`);
  const r = guard.applyOriginTrialGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.FOREIGN_ORIGIN);
});

test('缺少来源声明被识别', () => {
  const r = guard.inspectOriginTrial(token({ feature: 'ExampleFeature', expiry: future() }), 'https://example.com');
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
