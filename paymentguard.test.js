'use strict';

// paymentguard.test.js —— PaymentRequest：上下文门、basic-card、URL 方法白名单、币种金额、联系人过度收集、canMake 探测、节流。

const test = require('node:test');
const assert = require('node:assert/strict');
const pg = require('./paymentguard');
const { PaymentGuard, PG_REASON, validCurrency, parseAmount, defaultPaymentPolicy } = pg;

function ctx(over) {
  return Object.assign({
    origin: 'https://shop.example.com', isSecureContext: true, blocked: false,
    isBackground: false, hasUserGesture: true, now: 0,
  }, over || {});
}

const methods = [{ supportedMethods: 'https://pay.gateway.com/checkout' }];
const details = { total: { label: '合计', amount: { currency: 'CNY', value: '99.00' } } };

test('币种校验', () => {
  assert.ok(validCurrency('CNY'));
  assert.ok(!validCurrency('cn'));
  assert.ok(!validCurrency('CNYY'));
  assert.ok(!validCurrency('12X'));
});

test('金额解析', () => {
  assert.equal(parseAmount('99.00'), 99);
  assert.ok(Number.isNaN(parseAmount('-1')));
  assert.ok(Number.isNaN(parseAmount('abc')));
  assert.ok(Number.isNaN(parseAmount('1.2.3')));
});

test('非安全/后台/无手势拒绝', () => {
  const g = new PaymentGuard();
  assert.equal(g.decideShow(ctx({ isSecureContext: false }), methods, details, {}).reason, PG_REASON.INSECURE_CONTEXT);
  assert.equal(g.decideShow(ctx({ isBackground: true }), methods, details, {}).reason, PG_REASON.BACKGROUND);
  assert.equal(g.decideShow(ctx({ hasUserGesture: false }), methods, details, {}).reason, PG_REASON.NO_GESTURE);
});

test('默认无 URL 方法白名单：支付方法拒绝', () => {
  const g = new PaymentGuard();
  assert.equal(g.decideShow(ctx({ now: 0 }), methods, details, {}).reason, PG_REASON.PAYMENT_METHOD_NOT_ALLOWED);
});

test('白名单网关放行', () => {
  const pol = defaultPaymentPolicy();
  pol.allowedMethodHostSuffixes = ['pay.gateway.com'];
  const g = new PaymentGuard(pol);
  assert.equal(g.decideShow(ctx({ now: 0 }), methods, details, {}).decision, 'prompt');
});

test('basic-card 默认拒绝', () => {
  const g = new PaymentGuard();
  assert.equal(g.decideShow(ctx({ now: 0 }), [{ supportedMethods: 'basic-card' }], details, {}).reason, PG_REASON.PAYMENT_METHOD_NOT_ALLOWED);
});

test('币种/金额非法拒绝', () => {
  const pol = defaultPaymentPolicy();
  pol.allowedMethodHostSuffixes = ['pay.gateway.com'];
  const g = new PaymentGuard(pol);
  const badCur = { total: { amount: { currency: 'CN', value: '10' } } };
  assert.equal(g.decideShow(ctx({ now: 0 }), methods, badCur, {}).reason, PG_REASON.BAD_CURRENCY);
  const badAmt = { total: { amount: { currency: 'CNY', value: '0' } } };
  assert.equal(g.decideShow(ctx({ now: 100 }), methods, badAmt, {}).reason, PG_REASON.BAD_AMOUNT);
  const negAmt = { total: { amount: { currency: 'CNY', value: '-5' } } };
  assert.equal(g.decideShow(ctx({ now: 200 }), methods, negAmt, {}).reason, PG_REASON.BAD_AMOUNT);
});

test('联系人字段过度收集拒绝', () => {
  const pol = defaultPaymentPolicy();
  pol.allowedMethodHostSuffixes = ['pay.gateway.com'];
  const g = new PaymentGuard(pol);
  const opt = { requestPayerName: true, requestPayerEmail: true, requestPayerPhone: true };
  assert.equal(g.decideShow(ctx({ now: 0 }), methods, details, opt).reason, PG_REASON.EXCESSIVE_CONTACT_REQUEST);
});

test('canMakePayment 探测默认拒绝', () => {
  const g = new PaymentGuard();
  assert.equal(g.decideCanMake(ctx()).reason, PG_REASON.CANMAKE_FINGERPRINT);
});

test('show 节流', () => {
  const pol = defaultPaymentPolicy();
  pol.allowedMethodHostSuffixes = ['pay.gateway.com'];
  const g = new PaymentGuard(pol);
  assert.equal(g.decideShow(ctx({ now: 0 }), methods, details, {}).decision, 'prompt');
  assert.equal(g.decideShow(ctx({ now: 1000 }), methods, details, {}).reason, PG_REASON.SHOW_THROTTLED);
});
