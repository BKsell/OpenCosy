'use strict';

// clipboardguard.test.js —— 异步读门、节流、敏感分级（Luhn/私钥/助记词/验证码）、危险富文本。

const test = require('node:test');
const assert = require('node:assert/strict');
const cb = require('./clipboardguard');
const {
  ClipboardGuard, CB_REASON, SENS, classifySensitivity, luhnValid,
  containsDangerousHtmlScheme, byteLen,
} = cb;

const ORIGIN = 'https://app.example.com';
function ctx(over) {
  return Object.assign({
    origin: ORIGIN, isSecureContext: true, hasUserGesture: true, hasFocus: true,
    isBackground: false, blocked: false, now: 0,
  }, over || {});
}

test('Luhn 卡号校验', () => {
  assert.ok(luhnValid('4111111111111111')); // Visa 测试号
  assert.ok(luhnValid('79927398713'));
  assert.ok(!luhnValid('4111111111111112'));
});

test('私钥分级', () => {
  assert.equal(classifySensitivity('-----BEGIN PRIVATE KEY-----\nMII...'), SENS.PRIVATE_KEY);
  assert.equal(classifySensitivity('-----BEGIN OPENSSH PRIVATE KEY-----'), SENS.PRIVATE_KEY);
});

test('bearer token 分级', () => {
  assert.equal(classifySensitivity('Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig'), SENS.BEARER_TOKEN);
});

test('信用卡号分级', () => {
  assert.equal(classifySensitivity('4111 1111 1111 1111'), SENS.NONE); // 含空格，非连续
  assert.equal(classifySensitivity('4111111111111111'), SENS.CREDIT_CARD);
});

test('助记词分级', () => {
  const mn = 'abandon abandon ability able about above absent absorb abstract absurd abuse access';
  assert.equal(classifySensitivity(mn), SENS.MNEMONIC);
});

test('验证码与长 hex 分级', () => {
  assert.equal(classifySensitivity('483920'), SENS.OTP_CODE);
  assert.equal(classifySensitivity('a'.repeat(40)), SENS.LONG_HEX_SECRET);
});

test('普通文本不分级', () => {
  assert.equal(classifySensitivity('明天一起吃饭吗'), SENS.NONE);
  assert.equal(classifySensitivity('https://example.com/article?id=12'), SENS.NONE);
});

test('非安全/后台/失焦/无手势拒绝读取', () => {
  const g = new ClipboardGuard();
  assert.equal(g.decideRead(ctx({ isSecureContext: false }), 'x').reason, CB_REASON.INSECURE_CONTEXT);
  assert.equal(g.decideRead(ctx({ isBackground: true }), 'x').reason, CB_REASON.BACKGROUND_READ);
  assert.equal(g.decideRead(ctx({ hasFocus: false }), 'x').reason, CB_REASON.NOT_FOCUSED);
  assert.equal(g.decideRead(ctx({ hasUserGesture: false }), 'x').reason, CB_REASON.NO_GESTURE);
});

test('读取节流', () => {
  const g = new ClipboardGuard();
  assert.equal(g.decideRead(ctx({ now: 0 }), 'hello').decision, 'allow');
  assert.equal(g.decideRead(ctx({ now: 500 }), 'hello').reason, CB_REASON.READ_THROTTLED);
});

test('读到敏感内容要求确认', () => {
  const g = new ClipboardGuard();
  const r = g.decideRead(ctx({ now: 0 }), '4111111111111111');
  assert.equal(r.decision, 'confirm');
  assert.equal(r.sensitivity, SENS.CREDIT_CARD);
});

test('危险富文本写入拒绝', () => {
  const g = new ClipboardGuard();
  assert.equal(g.decideWrite(ctx({ now: 0 }), { html: '<a href="javascript:x">click</a>' }).reason, CB_REASON.DANGEROUS_HTML);
  assert.equal(g.decideWrite(ctx({ now: 0 }), { html: '<iframe src="data:text/html,x"></iframe>' }).reason, CB_REASON.DANGEROUS_HTML);
});

test('正常写入放行并节流', () => {
  const g = new ClipboardGuard();
  assert.equal(g.decideWrite(ctx({ now: 0 }), { text: 'hello' }).decision, 'allow');
  assert.equal(g.decideWrite(ctx({ now: 100 }), { text: 'again' }).reason, CB_REASON.WRITE_THROTTLED);
});

test('超大写入拒绝；字节长度统计', () => {
  const g = new ClipboardGuard();
  assert.ok(byteLen('abc') === 3);
  assert.ok(byteLen('中') >= 2);
  const big = 'x'.repeat(1024 * 1024 + 1);
  assert.equal(g.decideWrite(ctx({ now: 10000 }), { text: big }).reason, CB_REASON.WRITE_TOO_LARGE);
});

test('危险 scheme 检测函数', () => {
  assert.ok(containsDangerousHtmlScheme('JAVASCRIPT:alert(1)'));
  assert.ok(containsDangerousHtmlScheme('<img src=vbscript:x>'));
  assert.ok(!containsDangerousHtmlScheme('<b>hi</b>'));
});
