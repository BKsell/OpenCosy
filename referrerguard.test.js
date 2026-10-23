'use strict';

// referrerguard.test.js —— 各策略在同源/跨源/降级下的 Referer 取值，强度比较，追踪参数剔除。

const test = require('node:test');
const assert = require('node:assert/strict');
const rf = require('./referrerguard');
const {
  resolveReferrer, REF_POLICY, REF_OUTCOME, parseOrigin, sameOrigin,
  policyStrength, stripTrackingParams,
} = rf;

const PAGE = 'https://shop.example.com/list?q=phone&page=2';
const SAME_SITE = 'https://shop.example.com/item/9';
const CROSS = 'https://ads.other.net/pixel.gif';
const HTTP_CROSS = 'http://legacy.example.net/x';

test('origin 解析', () => {
  assert.equal(parseOrigin(PAGE), 'https://shop.example.com');
  assert.equal(sameOrigin(PAGE, SAME_SITE), true);
  assert.equal(sameOrigin(PAGE, CROSS), false);
});

test('no-referrer 总是空', () => {
  assert.equal(resolveReferrer(REF_POLICY.NO_REFERRER, PAGE, CROSS).outcome, REF_OUTCOME.EMPTY);
});

test('unsafe-url 总是完整', () => {
  assert.equal(resolveReferrer(REF_POLICY.UNSAFE_URL, PAGE, HTTP_CROSS).value, PAGE);
});

test('origin 策略只给 origin', () => {
  const r = resolveReferrer(REF_POLICY.ORIGIN, PAGE, CROSS);
  assert.equal(r.outcome, REF_OUTCOME.ORIGIN_ONLY);
  assert.equal(r.value, 'https://shop.example.com');
});

test('same-origin 跨源为空，同源完整', () => {
  assert.equal(resolveReferrer(REF_POLICY.SAME_ORIGIN, PAGE, CROSS).outcome, REF_OUTCOME.EMPTY);
  assert.equal(resolveReferrer(REF_POLICY.SAME_ORIGIN, PAGE, SAME_SITE).outcome, REF_OUTCOME.FULL);
});

test('strict-origin 降级为空，非降级给 origin', () => {
  assert.equal(resolveReferrer(REF_POLICY.STRICT_ORIGIN, PAGE, HTTP_CROSS).outcome, REF_OUTCOME.EMPTY);
  assert.equal(resolveReferrer(REF_POLICY.STRICT_ORIGIN, PAGE, CROSS).outcome, REF_OUTCOME.ORIGIN_ONLY);
});

test('strict-origin-when-cross-origin：同源完整/跨源origin/降级空', () => {
  const p = REF_POLICY.STRICT_ORIGIN_WHEN_CROSS_ORIGIN;
  assert.equal(resolveReferrer(p, PAGE, SAME_SITE).outcome, REF_OUTCOME.FULL);
  assert.equal(resolveReferrer(p, PAGE, CROSS).outcome, REF_OUTCOME.ORIGIN_ONLY);
  assert.equal(resolveReferrer(p, PAGE, HTTP_CROSS).outcome, REF_OUTCOME.EMPTY);
});

test('origin-when-cross-origin：跨源给 origin，不防降级', () => {
  const p = REF_POLICY.ORIGIN_WHEN_CROSS_ORIGIN;
  assert.equal(resolveReferrer(p, PAGE, CROSS).outcome, REF_OUTCOME.ORIGIN_ONLY);
  assert.equal(resolveReferrer(p, PAGE, HTTP_CROSS).outcome, REF_OUTCOME.ORIGIN_ONLY);
});

test('强度排序 no-referrer 最严 unsafe-url 最宽', () => {
  assert.ok(policyStrength(REF_POLICY.NO_REFERRER) > policyStrength(REF_POLICY.STRICT_ORIGIN_WHEN_CROSS_ORIGIN));
  assert.ok(policyStrength(REF_POLICY.UNSAFE_URL) < policyStrength(REF_POLICY.NO_REFERRER_WHEN_DOWNGRADE));
});

test('剔除 utm/gclid 追踪参数，保留业务参数', () => {
  const out = stripTrackingParams('https://s.com/p?id=7&utm_source=x&gclid=abc');
  assert.ok(out.indexOf('id=7') >= 0);
  assert.ok(out.indexOf('utm_source') < 0);
  assert.ok(out.indexOf('gclid') < 0);
});

test('无查询串时原样返回', () => {
  assert.equal(stripTrackingParams('https://s.com/p'), 'https://s.com/p');
});
