'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./cookiejarhardening');

const {
  REASON,
  inspectCookie,
  evaluateCookieJar,
  applyCookieJarHardening,
  describeReason,
} = guard;

nodeTest.test('plain host cookie passes', () => {
  const verdict = inspectCookie('sid=abc123; Path=/; Secure; HttpOnly');
  assert.equal(verdict.reason, REASON.ok);
  assert.equal(verdict.drop, false);
});

nodeTest.test('cookie scoped to public suffix is dropped', () => {
  const verdict = inspectCookie('sid=1; Domain=.com; Path=/');
  assert.equal(verdict.reason, REASON.publicSuffix);
  assert.equal(verdict.drop, true);
});

nodeTest.test('country level public suffix is dropped', () => {
  const verdict = inspectCookie('sid=1; Domain=.co.uk');
  assert.equal(verdict.reason, REASON.publicSuffix);
});

nodeTest.test('ip literal domain is dropped', () => {
  const verdict = inspectCookie('sid=1; Domain=192.168.1.10');
  assert.equal(verdict.reason, REASON.ipDomain);
  assert.equal(verdict.drop, true);
});

nodeTest.test('__Host- requires Secure, Path=/ and no Domain', () => {
  assert.equal(inspectCookie('__Host-a=1; Secure; Path=/').reason, REASON.ok);
  assert.equal(inspectCookie('__Host-a=1; Secure; Path=/; Domain=example.com').reason, REASON.hostPrefix);
  assert.equal(inspectCookie('__Host-a=1; Path=/').reason, REASON.hostPrefix);
  assert.equal(inspectCookie('__Host-a=1; Secure; Path=/sub').reason, REASON.hostPrefix);
});

nodeTest.test('__Secure- requires Secure', () => {
  assert.equal(inspectCookie('__Secure-a=1; Secure').reason, REASON.ok);
  assert.equal(inspectCookie('__Secure-a=1').reason, REASON.securePrefix);
});

nodeTest.test('SameSite=None without Secure is dropped', () => {
  assert.equal(inspectCookie('a=1; SameSite=None').reason, REASON.samesiteNone);
  assert.equal(inspectCookie('a=1; SameSite=None; Secure').reason, REASON.ok);
});

nodeTest.test('oversized cookie is dropped', () => {
  const value = 'x'.repeat(guard.MAX_COOKIE_BYTES + 10);
  const verdict = inspectCookie(`big=${value}`);
  assert.equal(verdict.reason, REASON.oversized);
});

nodeTest.test('control characters are dropped', () => {
  assert.equal(inspectCookie('a=1\u000d\u000aSet-Cookie: evil=1').reason, REASON.controlChars);
  assert.equal(inspectCookie('a=1\u202eevil').reason, REASON.controlChars);
});

nodeTest.test('malformed pair is dropped', () => {
  assert.equal(inspectCookie('noequals').reason, REASON.malformed);
  assert.equal(inspectCookie('=value').reason, REASON.malformed);
});

nodeTest.test('cookie count is capped', () => {
  const headers = { 'set-cookie': [] };
  for (let i = 0; i < guard.MAX_COOKIES + 5; i += 1) headers['set-cookie'].push(`c${i}=1; Secure`);
  const verdict = applyCookieJarHardening(headers);
  assert.equal(verdict.changed, true);
  assert.equal(headers['Set-Cookie'].length, guard.MAX_COOKIES);
});

nodeTest.test('header name lookup is case insensitive', () => {
  const headers = { 'Set-Cookie': ['sid=1; Domain=.com'] };
  const verdict = applyCookieJarHardening(headers);
  assert.equal(verdict.changed, true);
  assert.equal(headers['Set-Cookie'], undefined);
});

nodeTest.test('string header value is converted to array', () => {
  const headers = { 'set-cookie': 'sid=1; Secure' };
  const verdict = applyCookieJarHardening(headers);
  assert.equal(verdict.changed, false);
  assert.equal(headers['set-cookie'], 'sid=1; Secure');
});

nodeTest.test('clean responses stay untouched', () => {
  const headers = { 'set-cookie': ['a=1; Secure', 'b=2; HttpOnly'] };
  assert.equal(evaluateCookieJar(headers).changed, false);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0, reason);
  }
});
