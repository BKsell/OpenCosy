'use strict';

// webauthnguard.test.js —— rp.id 后缀边界、UV、attestation、超时、条件式、excludeCredentials。

const test = require('node:test');
const assert = require('node:assert/strict');
const wa = require('./webauthnguard');
const { WebauthnGuard, WA_REASON, hostMatchesRpId, originHost, defaultWebauthnPolicy } = wa;

function ctx(over) {
  return Object.assign({ origin: 'https://login.example.com', isSecureContext: true, blocked: false, now: 0 }, over || {});
}

test('host 提取', () => {
  assert.equal(originHost('https://login.example.com:8443/path?q=1'), 'login.example.com');
  assert.equal(originHost('http://a.test/'), 'a.test');
  assert.equal(originHost('notaurl'), '');
});

test('rpId 后缀边界：拒绝 com.cn 后缀误配', () => {
  assert.ok(hostMatchesRpId('login.example.com', 'example.com'));
  assert.ok(hostMatchesRpId('example.com', 'example.com'));
  assert.ok(!hostMatchesRpId('notexample.com', 'example.com'));
  assert.ok(!hostMatchesRpId('example.com.cn', 'example.com'));
});

test('非安全上下文拒绝', () => {
  const g = new WebauthnGuard();
  assert.equal(g.decideCreate(ctx({ isSecureContext: false }), {}).reason, WA_REASON.INSECURE_CONTEXT);
});

test('create：rpId 不匹配拒绝', () => {
  const g = new WebauthnGuard();
  const opt = { publicKey: { rp: { id: 'evil.com' }, userVerification: 'required', timeout: 30000 } };
  assert.equal(g.decideCreate(ctx({ now: 0 }), opt).reason, WA_REASON.RP_ID_MISMATCH);
});

test('create：UV discouraged 拒绝', () => {
  const g = new WebauthnGuard();
  const opt = { publicKey: { rp: { id: 'example.com' }, userVerification: 'discouraged', timeout: 30000 } };
  assert.equal(g.decideCreate(ctx({ now: 0 }), opt).reason, WA_REASON.UV_DISCOURAGED);
});

test('create：direct attestation 默认拒绝', () => {
  const g = new WebauthnGuard();
  const opt = { publicKey: { rp: { id: 'example.com' }, userVerification: 'required', attestation: 'direct', timeout: 30000 } };
  assert.equal(g.decideCreate(ctx({ now: 0 }), opt).reason, WA_REASON.ATTESTATION_DIRECT_FORBIDDEN);
});

test('create：超时过长拒绝', () => {
  const g = new WebauthnGuard();
  const opt = { publicKey: { rp: { id: 'example.com' }, userVerification: 'required', timeout: 999999 } };
  assert.equal(g.decideCreate(ctx({ now: 0 }), opt).reason, WA_REASON.TIMEOUT_TOO_LONG);
});

test('create：合法请求放行 prompt', () => {
  const g = new WebauthnGuard();
  const opt = { publicKey: { rp: { id: 'example.com' }, userVerification: 'required', attestation: 'none', timeout: 30000, excludeCredentials: [{ id: 'x' }] } };
  assert.equal(g.decideCreate(ctx({ now: 0 }), opt).decision, 'prompt');
});

test('get：空 allowCredentials 拒绝', () => {
  const g = new WebauthnGuard();
  const opt = { publicKey: { rpId: 'example.com', userVerification: 'required', timeout: 30000, allowCredentials: [] }, mediation: 'optional' };
  assert.equal(g.decideGet(ctx({ now: 0 }), opt).reason, WA_REASON.EMPTY_ALLOW_CREDENTIALS);
});

test('get：条件式被策略关闭时拒绝', () => {
  const pol = defaultWebauthnPolicy();
  pol.allowConditionalMediation = false;
  const g = new WebauthnGuard(pol);
  const opt = { publicKey: { rpId: 'example.com', userVerification: 'required', timeout: 30000, allowCredentials: [{ id: 'a' }] }, mediation: 'conditional' };
  assert.equal(g.decideGet(ctx({ now: 0 }), opt).reason, WA_REASON.CONDITIONAL_WITHOUT_ALLOWED);
});

test('请求节流', () => {
  const g = new WebauthnGuard();
  const opt = { publicKey: { rp: { id: 'example.com' }, userVerification: 'required', timeout: 30000 } };
  assert.equal(g.decideGet(ctx({ now: 0 }), { publicKey: { rpId: 'example.com', userVerification: 'required', timeout: 30000, allowCredentials: [{ id: 'a' }] }, mediation: 'optional' }).decision, 'prompt');
  assert.equal(g.decideGet(ctx({ now: 500 }), { publicKey: { rpId: 'example.com', userVerification: 'required', timeout: 30000, allowCredentials: [{ id: 'a' }] }, mediation: 'optional' }).reason, WA_REASON.REQUEST_THROTTLED);
});
