'use strict';

// digitalcredentialguard.test.js —— 数字证件：手势/可见性、协议、docType/字段白名单、年龄谓词、provider、nonce。

const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('./digitalcredentialguard');
const { DigitalCredentialGuard, DC_REASON, defaultDigitalCredentialPolicy } = d;

function ctx(over) {
  return Object.assign({ origin: 'https://shop.example.com', userGesture: true, visible: true }, over || {});
}
function opts(over) {
  return Object.assign({
    digital: {
      requests: [{ protocol: 'mdoc', docType: 'org.idms.age.1', requestedFields: ['age_over_18'], purpose: 'age_verification' }],
      nonce: '0123456789abcdef0123456789abcdef',
    },
  }, over || {});
}

test('年龄谓词最小请求放行', () => {
  const g = new DigitalCredentialGuard();
  assert.equal(g.decideGet(ctx(), opts()).decision, 'allow');
});

test('无手势/不可见/非 https 拒绝', () => {
  const g = new DigitalCredentialGuard();
  assert.equal(g.decideGet(ctx({ userGesture: false }), opts()).reason, DC_REASON.NO_GESTURE);
  assert.equal(g.decideGet(ctx({ visible: false }), opts()).reason, DC_REASON.NOT_VISIBLE);
  assert.equal(g.decideGet(ctx({ origin: 'http://x' }), opts()).reason, DC_REASON.INSECURE_ORIGIN);
});

test('空请求拒绝', () => {
  const g = new DigitalCredentialGuard();
  assert.equal(g.decideGet(ctx(), { digital: { requests: [], nonce: 'x'.repeat(20) } }).reason, DC_REASON.NO_REQUEST);
});

test('未知协议拒绝', () => {
  const g = new DigitalCredentialGuard();
  const o = opts();
  o.digital.requests[0].protocol = 'bogus';
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.UNKNOWN_PROTOCOL);
});

test('docType 不在允许清单拒绝', () => {
  const g = new DigitalCredentialGuard();
  const o = opts();
  o.digital.requests[0].docType = 'org.gov.passport';
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.DOC_TYPE_NOT_ALLOWED);
});

test('年龄场景索取真实生日拒绝', () => {
  const g = new DigitalCredentialGuard();
  const o = opts();
  o.digital.requests[0].docType = 'org.iso.18013.5.1';
  o.digital.requests[0].requestedFields = ['birth_date'];
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.AGE_SHOULD_USE_PREDICATE);
});

test('白名单外字段拒绝', () => {
  const g = new DigitalCredentialGuard();
  const o = opts();
  o.digital.requests[0].docType = 'org.iso.18013.5.1';
  o.digital.requests[0].requestedFields = ['document_number'];
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.FIELD_NOT_ALLOWED);
});

test('字段总数过多拒绝', () => {
  const g = new DigitalCredentialGuard();
  const o = opts();
  o.digital.requests[0].docType = 'org.iso.18013.5.1';
  o.digital.requests[0].requestedFields = ['family_name', 'given_name', 'issue_date', 'expiry_date', 'age_over_18', 'age_over_21', 'age_in_years'];
  o.digital.requests[0].purpose = 'kyc';
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.TOO_MANY_FIELDS);
});

test('凭证请求数过多拒绝', () => {
  const g = new DigitalCredentialGuard();
  const o = opts();
  o.digital.requests = [o.digital.requests[0], o.digital.requests[0], o.digital.requests[0]];
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.TOO_MANY_CREDENTIALS);
});

test('非受信 provider 拒绝', () => {
  const g = new DigitalCredentialGuard();
  const o = opts();
  o.digital.providers = ['https://evil-wallet.net'];
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.PROVIDER_NOT_TRUSTED);
  const pol = defaultDigitalCredentialPolicy();
  pol.trustedProviders = ['https://official-wallet.gov'];
  const g2 = new DigitalCredentialGuard(pol);
  const o2 = opts();
  o2.digital.providers = ['https://official-wallet.gov'];
  o2.digital.nonce = 'f'.repeat(32);
  assert.equal(g2.decideGet(ctx(), o2).decision, 'allow');
});

test('nonce 过短/复用拒绝', () => {
  const g = new DigitalCredentialGuard();
  const short = opts();
  short.digital.nonce = 'abc';
  assert.equal(g.decideGet(ctx(), short).reason, DC_REASON.NONCE_REUSED_OR_BAD);
  const o = opts();
  assert.equal(g.decideGet(ctx(), o).decision, 'allow');
  assert.equal(g.decideGet(ctx(), o).reason, DC_REASON.NONCE_REUSED_OR_BAD);
});
