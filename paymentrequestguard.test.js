'use strict';

// paymentrequestguard.test.js —— PaymentRequest：支付方式/网关、basic-card、币种金额、收货过度收集、show 超时、探测频率。

const test = require('node:test');
const assert = require('node:assert/strict');
const p = require('./paymentrequestguard');
const { PaymentRequestGuard, PR_REASON, parseAmount } = p;

let now = 1_700_000_000_000;
const clock = () => now;
function ctx(over) { return Object.assign({ origin: 'https://shop.example.com' }, over || {}); }
function md() { return [{ supportedMethods: 'https://google.com/pay', data: { environment: 'production', gateway: 'stripe' } }]; }
function details(value) { return { total: { amount: { currency: 'USD', value: value || '19.99' } } }; }

test('合规支付放行并解析金额', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  const r = g.decideConstruct(ctx(), md(), details());
  assert.equal(r.decision, 'allow');
  assert.equal(r.amountCents, 1999);
});

test('非 https/无 methodData 拒绝', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  assert.equal(g.decideConstruct(ctx({ origin: 'http://x' }), md(), details()).reason, PR_REASON.INSECURE_ORIGIN);
  assert.equal(g.decideConstruct(ctx(), [], details()).reason, PR_REASON.NO_METHOD_DATA);
});

test('basic-card 默认拒绝', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  assert.equal(g.decideConstruct(ctx(), [{ supportedMethods: 'basic-card' }], details()).reason, PR_REASON.BASIC_CARD_DISABLED);
});

test('未知支付方式/未授权网关拒绝', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  assert.equal(g.decideConstruct(ctx(), [{ supportedMethods: 'https://evil.com/pay' }], details()).reason, PR_REASON.UNKNOWN_PAYMENT_METHOD);
  const bad = [{ supportedMethods: 'https://google.com/pay', data: { environment: 'production', gateway: 'evilgw' } }];
  assert.equal(g.decideConstruct(ctx(), bad, details()).reason, PR_REASON.GATEWAY_NOT_ALLOWED);
});

test('币种非法拒绝', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  assert.equal(g.decideConstruct(ctx(), md(), { total: { amount: { currency: 'US', value: '1' } } }).reason, PR_REASON.BAD_CURRENCY);
  assert.equal(g.decideConstruct(ctx(), md(), { total: { amount: { currency: 'US1', value: '1' } } }).reason, PR_REASON.BAD_CURRENCY);
});

test('金额负数/零/非法/超大拒绝', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  assert.equal(g.decideConstruct(ctx(), md(), details('-1')).reason, PR_REASON.BAD_AMOUNT);
  assert.equal(g.decideConstruct(ctx(), md(), details('0')).reason, PR_REASON.BAD_AMOUNT);
  assert.equal(g.decideConstruct(ctx(), md(), details('1.234')).reason, PR_REASON.BAD_AMOUNT);
  assert.equal(g.decideConstruct(ctx(), md(), details('999999999')).reason, PR_REASON.BAD_AMOUNT);
});

test('数字商品索取收货拒绝', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  assert.equal(g.decideConstruct(ctx({ goodsType: 'digital' }), md(), details(), { requestShipping: true }).reason,
    PR_REASON.SHIPPING_OVERCOLLECTION);
});

test('show 超时拒绝', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  assert.equal(g.decideShow(99999).reason, PR_REASON.SHOW_TIMEOUT);
  assert.equal(g.decideShow(1000).decision, 'allow');
});

test('持卡探测频率上限', () => {
  const g = new PaymentRequestGuard(undefined, clock);
  for (let i = 0; i < 4; i++) assert.equal(g.decideEnrollmentProbe().decision, 'allow');
  assert.equal(g.decideEnrollmentProbe().reason, PR_REASON.ENROLLMENT_PROBE);
  now += 61000;
  assert.equal(g.decideEnrollmentProbe().decision, 'allow');
});

test('parseAmount 纯字符', () => {
  assert.equal(parseAmount('1'), 100);
  assert.equal(parseAmount('1.5'), 150);
  assert.equal(parseAmount('1.05'), 105);
  assert.equal(parseAmount('abc'), null);
});
