'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const cg = require('./certguard');

test('normalizeHost 接受 URL 与裸域名并归一化', () => {
  assert.equal(cg.normalizeHost('https://www.Example.COM:8443/a?b=1'), 'www.example.com');
  assert.equal(cg.normalizeHost('WWW.Example.COM.'), 'www.example.com');
  assert.equal(cg.normalizeHost('example.com'), 'example.com');
  assert.equal(cg.normalizeHost('https://[::1]:443/'), '::1');
  assert.equal(cg.normalizeHost('127.0.0.1:8080'), '127.0.0.1');
});

test('normalizeHost 拒绝非法输入', () => {
  for (const bad of ['', null, undefined, '   ', 'not a host !!', 'a b.com', 'http://', 'exa mple.com']) {
    assert.equal(cg.normalizeHost(bad), null, `应当拒绝: ${JSON.stringify(bad)}`);
  }
  assert.equal(cg.normalizeHost('a'.repeat(254)), null); // 超 253
});

test('normalizeFingerprint 去冒号/前缀并小写', () => {
  const hex = 'a'.repeat(64);
  assert.equal(cg.normalizeFingerprint(`sha256/${hex.toUpperCase().match(/.{2}/g).join(':')}`), hex);
  assert.equal(cg.normalizeFingerprint(hex), hex);
  assert.equal(cg.normalizeFingerprint('abc'), '');
  assert.equal(cg.normalizeFingerprint(''), '');
  assert.equal(cg.normalizeFingerprint('z'.repeat(64)), '');
});

test('derFingerprint 与直接 SHA-256 一致', () => {
  const der = crypto.randomBytes(120);
  const b64 = der.toString('base64');
  const expect = crypto.createHash('sha256').update(der).digest('hex');
  assert.equal(cg.derFingerprint(b64), expect);
  assert.equal(cg.derFingerprint(''), '');
  assert.equal(cg.derFingerprint(null), '');
});

test('resolveFingerprint 优先 fingerprint，缺失回退 DER', () => {
  const der = crypto.randomBytes(64);
  const fp = crypto.createHash('sha256').update(der).digest('hex');
  assert.equal(cg.resolveFingerprint({ fingerprint: `sha256/${fp}` }), fp);
  assert.equal(cg.resolveFingerprint({ data: der.toString('base64') }), fp);
  assert.equal(cg.resolveFingerprint({}), '');
  assert.equal(cg.resolveFingerprint(null), '');
});

test('parseCommonName 提取 CN', () => {
  assert.equal(cg.parseCommonName('CN=example.com, O=Example Inc, C=US'), 'example.com');
  assert.equal(cg.parseCommonName('O=Example,CN=*.example.com'), '*.example.com');
  assert.equal(cg.parseCommonName('O=Example'), '');
  assert.equal(cg.parseCommonName(''), '');
});

test('errorInfo 软错误可放行、硬错误与未知错误 fail-closed', () => {
  const soft = cg.errorInfo('err_cert_authority_invalid');
  assert.equal(soft.code, 'ERR_CERT_AUTHORITY_INVALID');
  assert.equal(soft.overridable, true);
  assert.ok(soft.title);

  for (const hard of ['ERR_CERT_REVOKED', 'ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN',
    'ERR_CERTIFICATE_TRANSPARENCY_REQUIRED']) {
    assert.equal(cg.errorInfo(hard).overridable, false, `${hard} 不可绕过`);
  }
  assert.equal(cg.errorInfo('ERR_SOME_FUTURE_UNKNOWN_CODE').overridable, false);
  assert.equal(cg.errorInfo('').overridable, false);
});

test('classifyCertError 汇总主机/错误/证书摘要', () => {
  const der = crypto.randomBytes(40);
  const fp = crypto.createHash('sha256').update(der).digest('hex');
  const r = cg.classifyCertError({
    url: 'https://shop.example.com/login',
    error: 'ERR_CERT_COMMON_NAME_INVALID',
    certificate: {
      subjectName: 'CN=other.example.net',
      issuerName: 'CN=Test CA',
      data: der.toString('base64'),
      validStart: 1,
      validExpiry: 2,
    },
  });
  assert.equal(r.host, 'shop.example.com');
  assert.equal(r.code, 'ERR_CERT_COMMON_NAME_INVALID');
  assert.equal(r.overridable, true);
  assert.equal(r.cert.fingerprint, fp);
  assert.equal(r.cert.subject, 'other.example.net');
  assert.equal(r.cert.issuer, 'Test CA');
});

test('createException 与 exceptionMatches 按主机+指纹绑定', () => {
  const cert = {
    subjectName: 'CN=lan.local',
    issuerName: 'CN=Lan Self Signed',
    fingerprint: `sha256/${'f'.repeat(64)}`,
  };
  const ex = cg.createException({ host: 'https://LAN.local/', certificate: cert, code: 'ERR_CERT_AUTHORITY_INVALID' });
  assert.ok(ex);
  assert.equal(ex.host, 'lan.local');
  assert.equal(ex.fingerprint, 'f'.repeat(64));

  assert.equal(cg.exceptionMatches(ex, { host: 'lan.local', fingerprint: 'f'.repeat(64) }), true);
  // 同主机但证书换了（潜在劫持）→ 不命中。
  assert.equal(cg.exceptionMatches(ex, { host: 'lan.local', fingerprint: 'e'.repeat(64) }), false);
  // 同指纹但主机不同 → 不命中。
  assert.equal(cg.exceptionMatches(ex, { host: 'other.local', fingerprint: 'f'.repeat(64) }), false);
});

test('createException 拒绝缺主机或无指纹', () => {
  assert.equal(cg.createException({ host: '', certificate: { fingerprint: `sha256/${'a'.repeat(64)}` } }), null);
  assert.equal(cg.createException({ host: 'a.com', certificate: {} }), null);
});

test('sanitizeExceptionRecord 只保留形状合法记录', () => {
  const clean = cg.sanitizeExceptionRecord({
    host: 'A.com.',
    fingerprint: 'A'.repeat(64),
    subject: 'x'.repeat(200),
    extra: { evil: true },
    addedAt: '123',
  });
  assert.equal(clean.host, 'a.com');
  assert.equal(clean.fingerprint, 'a'.repeat(64));
  assert.equal(clean.subject.length, 120); // 被裁剪
  assert.equal('extra' in clean, false);
  assert.equal(clean.addedAt, 123);

  for (const bad of [null, {}, { host: 'a.com' }, { fingerprint: 'a'.repeat(64) },
    { host: 'bad host', fingerprint: 'a'.repeat(64) }, { host: 'a.com', fingerprint: 'zz' }]) {
    assert.equal(cg.sanitizeExceptionRecord(bad), null);
  }
});

test('shortFingerprint 生成缩略形式', () => {
  const fp = 'ab12cd34' + '0'.repeat(48) + '99ff0011';
  const s = cg.shortFingerprint(fp);
  assert.ok(s.startsWith('ab12cd34'));
  assert.ok(s.endsWith('99ff0011'));
  assert.equal(cg.shortFingerprint('bad'), '');
});
