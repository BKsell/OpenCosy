'use strict';

// credentialguard.test.js —— 密码/联合/OTP 凭据读取与写入（投毒）裁决。

const test = require('node:test');
const assert = require('node:assert/strict');
const cr = require('./credentialguard');
const { CredentialGuard, CR_REASON, KIND, defaultCredentialPolicy } = cr;

function ctx(over) {
  return Object.assign({
    origin: 'https://bank.example.com', isSecureContext: true, blocked: false,
    isBackground: false, hasUserGesture: true, isTopFrame: true, now: 0,
  }, over || {});
}

test('非安全上下文拒绝', () => {
  const g = new CredentialGuard();
  assert.equal(g.decideGet(ctx({ isSecureContext: false }), { password: true }).reason, CR_REASON.INSECURE_CONTEXT);
});

test('后台拒绝', () => {
  const g = new CredentialGuard();
  assert.equal(g.decideGet(ctx({ isBackground: true }), { password: true }).reason, CR_REASON.BACKGROUND);
});

test('主动读取需手势', () => {
  const g = new CredentialGuard();
  assert.equal(g.decideGet(ctx({ hasUserGesture: false }), { password: true }).reason, CR_REASON.NO_GESTURE_GET);
});

test('silent mediation 默认拒绝', () => {
  const g = new CredentialGuard();
  assert.equal(g.decideGet(ctx(), { password: true, mediation: 'silent' }).reason, CR_REASON.SILENT_MEDIATION_FORBIDDEN);
});

test('合法密码读取放行', () => {
  const g = new CredentialGuard();
  const r = g.decideGet(ctx({ now: 0 }), { password: true, mediation: 'optional' });
  assert.equal(r.decision, 'allow');
  assert.ok(r.kinds.includes(KIND.PASSWORD));
});

test('读取节流', () => {
  const g = new CredentialGuard();
  g.decideGet(ctx({ now: 0 }), { password: true, mediation: 'optional' });
  assert.equal(g.decideGet(ctx({ now: 500 }), { password: true, mediation: 'optional' }).reason, CR_REASON.GET_THROTTLED);
});

test('默认禁止写入密码凭据（投毒）', () => {
  const g = new CredentialGuard();
  assert.equal(g.decideStore(ctx({ now: 5000 }), { kind: 'password', id: 'u', password: 'p' }).reason, CR_REASON.STORE_FORBIDDEN);
});

test('开启写入后空 id 拒绝', () => {
  const pol = defaultCredentialPolicy();
  pol.allowStorePassword = true;
  const g = new CredentialGuard(pol);
  assert.equal(g.decideStore(ctx({ now: 5000 }), { kind: 'password', id: '   ' }).reason, CR_REASON.EMPTY_ID_FIELD);
  assert.equal(g.decideStore(ctx({ now: 9000 }), { kind: 'password', id: 'u' }).decision, 'allow');
});

test('联合登录 provider 白名单', () => {
  const pol = defaultCredentialPolicy();
  pol.allowedFederatedProviders = ['accounts.google.com'];
  const g = new CredentialGuard(pol);
  const ok = g.decideGet(ctx({ now: 0 }), { federated: { providers: ['https://accounts.google.com'] }, mediation: 'optional' });
  assert.equal(ok.decision, 'allow');
  const bad = g.decideGet(ctx({ now: 5000 }), { federated: { providers: ['https://idp.evil.com'] }, mediation: 'optional' });
  assert.equal(bad.reason, CR_REASON.FEDERATED_PROVIDER_NOT_ALLOWED);
});

test('WebOTP 非顶层框架拒绝，顶层放行', () => {
  const g = new CredentialGuard();
  assert.equal(g.decideGet(ctx({ isTopFrame: false, now: 0 }), { otp: true, mediation: 'optional' }).reason, CR_REASON.WEBOTP_PERMISSION_DENIED);
  assert.equal(g.decideGet(ctx({ now: 3000 }), { otp: true, mediation: 'optional' }).decision, 'allow');
});

test('未知凭据类型拒绝', () => {
  const g = new CredentialGuard();
  assert.equal(g.decideGet(ctx({ now: 9000 }), { mediation: 'optional' }).reason, CR_REASON.UNKNOWN_CREDENTIAL_KIND);
});
