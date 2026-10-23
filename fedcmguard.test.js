'use strict';

// fedcmguard.test.js —— FedCM：手势/可见、provider 数量、configURL https、IdP 主机自洽、clientId、loginHint 拼接、auto 续登。

const test = require('node:test');
const assert = require('node:assert/strict');
const f = require('./fedcmguard');
const { FedCMGuard, FC_REASON, defaultFedCMPolicy, hostOf } = f;

function ctx(over) {
  return Object.assign({ origin: 'https://rp.example.com', userGesture: true, visible: true }, over || {});
}
function identity(over) {
  return Object.assign({
    providers: [{
      configURL: 'https://idp.example.net/fedcm.json',
      clientId: 'rp-client-123',
      idpHost: 'idp.example.net',
    }],
  }, over || {});
}

test('合规 FedCM 登录放行', () => {
  const g = new FedCMGuard();
  assert.equal(g.decideGet(ctx(), identity()).decision, 'allow');
});

test('无手势/不可见/非 https 拒绝', () => {
  const g = new FedCMGuard();
  assert.equal(g.decideGet(ctx({ userGesture: false }), identity()).reason, FC_REASON.NO_GESTURE);
  assert.equal(g.decideGet(ctx({ visible: false }), identity()).reason, FC_REASON.NOT_VISIBLE);
  assert.equal(g.decideGet(ctx({ origin: 'http://x' }), identity()).reason, FC_REASON.INSECURE_ORIGIN);
});

test('无 provider / 多 provider 拒绝', () => {
  const g = new FedCMGuard();
  assert.equal(g.decideGet(ctx(), { providers: [] }).reason, FC_REASON.NO_PROVIDERS);
  const two = identity();
  two.providers.push(two.providers[0]);
  assert.equal(g.decideGet(ctx(), two).reason, FC_REASON.TOO_MANY_PROVIDERS);
});

test('configURL 非 https 拒绝', () => {
  const g = new FedCMGuard();
  const id = identity();
  id.providers[0].configURL = 'http://idp.example.net/fedcm.json';
  assert.equal(g.decideGet(ctx(), id).reason, FC_REASON.BAD_CONFIG_URL);
});

test('config 主机与声明 IdP 不一致拒绝', () => {
  const g = new FedCMGuard();
  const id = identity();
  id.providers[0].configURL = 'https://evil.attacker.com/fedcm.json';
  assert.equal(g.decideGet(ctx(), id).reason, FC_REASON.CONFIG_HOST_MISMATCH);
});

test('clientId 缺失拒绝', () => {
  const g = new FedCMGuard();
  const id = identity();
  delete id.providers[0].clientId;
  assert.equal(g.decideGet(ctx(), id).reason, FC_REASON.BAD_CLIENT_ID);
});

test('loginHint 与当前账号不一致拒绝（账号拼接）', () => {
  const g = new FedCMGuard();
  const id = identity();
  id.providers[0].loginHint = 'victim@example.net';
  assert.equal(g.decideGet(ctx({ currentAccountHint: 'attacker@example.net' }), id).reason,
    FC_REASON.HINT_CROSS_USER);
});

test('loginHint 脏值拒绝', () => {
  const g = new FedCMGuard();
  const id = identity();
  id.providers[0].loginHint = 'a b@c d';
  assert.equal(g.decideGet(ctx(), id).reason, FC_REASON.BAD_LOGIN_HINT);
});

test('自动续登默认拒绝', () => {
  const g = new FedCMGuard();
  assert.equal(g.decideGet(ctx(), identity({ auto: true })).reason, FC_REASON.AUTO_REAUTHN_DISABLED);
});

test('未知 mode 拒绝', () => {
  const g = new FedCMGuard();
  assert.equal(g.decideGet(ctx(), identity({ mode: 'silent' })).reason, FC_REASON.UNKNOWN_MODE);
});

test('要求 nonce 时复用/过短拒绝', () => {
  const pol = defaultFedCMPolicy();
  pol.requireFreshNonce = true;
  const g = new FedCMGuard(pol);
  assert.equal(g.decideGet(ctx(), identity({ nonce: 'short' })).reason, FC_REASON.NONCE_BAD_OR_REUSED);
  assert.equal(g.decideGet(ctx(), identity({ nonce: 'n'.repeat(40) })).decision, 'allow');
  assert.equal(g.decideGet(ctx(), identity({ nonce: 'n'.repeat(40) })).reason, FC_REASON.NONCE_BAD_OR_REUSED);
});

test('hostOf 纯字符', () => {
  assert.equal(hostOf('https://idp.example.net:8443/p'), 'idp.example.net');
});
