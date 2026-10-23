'use strict';

// webotpguard.test.js —— WebOTP：短信解析、realm 与 origin 核对、验证码格式、可见性、频率、App 绑定。

const test = require('node:test');
const assert = require('node:assert/strict');
const o = require('./webotpguard');
const { WebOtpGuard, OTP_REASON, parseSms, defaultWebOtpPolicy } = o;

let now = 1_700_000_000_000;
const clock = () => now;
function ctx(over) { return Object.assign({ origin: 'https://bank.example.com', visible: true }, over || {}); }
const sms = 'Your code is:\n@bank.example.com #482913 APPBIND';

test('合规短信放行', () => {
  const g = new WebOtpGuard(undefined, clock);
  const r = g.decideRead(ctx(), sms);
  assert.equal(r.decision, 'allow');
  assert.equal(r.code, '482913');
});

test('realm 与 origin 不符拒绝', () => {
  const g = new WebOtpGuard(undefined, clock);
  assert.equal(g.decideRead(ctx({ origin: 'https://evil.net' }), sms).reason, OTP_REASON.REALM_MISMATCH);
});

test('子域匹配放行', () => {
  const g = new WebOtpGuard(undefined, clock);
  assert.equal(g.decideRead(ctx({ origin: 'https://m.bank.example.com' }), sms).decision, 'allow');
});

test('短信体畸形拒绝', () => {
  const g = new WebOtpGuard(undefined, clock);
  assert.equal(g.decideRead(ctx(), 'no code here').reason, OTP_REASON.MALFORMED_SMS);
});

test('验证码格式非法拒绝', () => {
  const g = new WebOtpGuard(undefined, clock);
  assert.equal(g.decideRead(ctx(), '@bank.example.com #12').reason, OTP_REASON.OTP_BAD_FORMAT);
  assert.equal(g.decideRead(ctx(), '@bank.example.com #abcdef').reason, OTP_REASON.OTP_BAD_FORMAT);
});

test('不可见/非 https 拒绝', () => {
  const g = new WebOtpGuard(undefined, clock);
  assert.equal(g.decideRead(ctx({ visible: false }), sms).reason, OTP_REASON.NOT_VISIBLE);
  assert.equal(g.decideRead(ctx({ origin: 'http://x' }), sms).reason, OTP_REASON.INSECURE_ORIGIN);
});

test('频率上限', () => {
  const pol = defaultWebOtpPolicy();
  pol.maxRequestsPerMinute = 2;
  const g = new WebOtpGuard(pol, clock);
  assert.equal(g.decideRead(ctx(), sms).decision, 'allow');
  assert.equal(g.decideRead(ctx(), sms).decision, 'allow');
  assert.equal(g.decideRead(ctx(), sms).reason, OTP_REASON.RATE_LIMIT);
});

test('要求 App 绑定码时缺失拒绝', () => {
  const pol = defaultWebOtpPolicy();
  pol.requireAppBindingCode = true;
  const g = new WebOtpGuard(pol, clock);
  assert.equal(g.decideRead(ctx(), 'code\n@bank.example.com #482913').reason, OTP_REASON.APP_BINDING_REQUIRED);
});

test('parseSms 纯字符', () => {
  assert.deepEqual(parseSms('x\n@a.b #123 y').realm, 'a.b');
  assert.equal(parseSms('nothing'), null);
});
