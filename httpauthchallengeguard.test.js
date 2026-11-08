'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./httpauthchallengeguard');

const { REASON, evaluateAuthChallenge, applyAuthChallengeGuard, splitChallenges, schemeOf, describeReason } = guard;

nodeTest.test('no auth headers is untouched', () => {
  const verdict = evaluateAuthChallenge({ 'content-type': ['text/html'] }, { url: 'https://example.com' });
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.reason, REASON.OK);
});

nodeTest.test('Basic challenge on https main frame is allowed', () => {
  const verdict = evaluateAuthChallenge({ 'www-authenticate': ['Basic realm="x"'] }, { url: 'https://example.com', resourceType: 'mainFrame' });
  assert.equal(verdict.action, 'allow');
});

nodeTest.test('NTLM challenge is stripped', () => {
  const verdict = evaluateAuthChallenge({ 'www-authenticate': ['NTLM'] }, { url: 'https://example.com', resourceType: 'mainFrame' });
  assert.equal(verdict.action, 'strip');
  assert.equal(verdict.reason, REASON.NTLM_SCHEME);
  assert.deepEqual(verdict.replace.values, []);
});

nodeTest.test('Negotiate alongside Basic keeps Basic', () => {
  const headers = { 'www-authenticate': ['Negotiate, Basic realm="corp"'] };
  const result = applyAuthChallengeGuard(headers, { url: 'https://example.com', resourceType: 'mainFrame' });
  assert.equal(result.verdict.reason, REASON.NEGOTIATE_SCHEME);
  assert.deepEqual(headers['WWW-Authenticate'], ['Basic realm="corp"']);
});

nodeTest.test('Kerberos is treated as silent scheme', () => {
  const verdict = evaluateAuthChallenge({ 'www-authenticate': ['Kerberos'] }, { url: 'https://example.com' });
  assert.equal(verdict.reason, REASON.NEGOTIATE_SCHEME);
});

nodeTest.test('subresource challenge is removed entirely', () => {
  const verdict = evaluateAuthChallenge({ 'www-authenticate': ['Basic realm="x"'] }, { url: 'https://example.com/a.png', resourceType: 'image' });
  assert.equal(verdict.reason, REASON.SUBRESOURCE_CHALLENGE);
  assert.deepEqual(verdict.strip, ['WWW-Authenticate']);
});

nodeTest.test('plain http challenge is removed', () => {
  const verdict = evaluateAuthChallenge({ 'www-authenticate': ['Basic realm="x"'] }, { url: 'http://example.com', resourceType: 'mainFrame' });
  assert.equal(verdict.reason, REASON.INSECURE_TRANSPORT);
});

nodeTest.test('non-http url removes challenge', () => {
  const verdict = evaluateAuthChallenge({ 'www-authenticate': ['Basic'] }, { url: 'cosy://settings', resourceType: 'mainFrame' });
  assert.equal(verdict.reason, REASON.NON_HTTP_SCHEME);
});

nodeTest.test('proxy authenticate is always removed', () => {
  const verdict = evaluateAuthChallenge({ 'proxy-authenticate': ['Basic realm="proxy"'] }, { url: 'https://example.com' });
  assert.equal(verdict.reason, REASON.PROXY_CHALLENGE);
  assert.deepEqual(verdict.strip, ['Proxy-Authenticate']);
});

nodeTest.test('proxy authenticate wins over origin challenge', () => {
  const headers = { 'proxy-authenticate': ['Basic'], 'www-authenticate': ['NTLM'] };
  const result = applyAuthChallengeGuard(headers, { url: 'https://example.com', resourceType: 'mainFrame' });
  assert.equal(result.verdict.reason, REASON.PROXY_CHALLENGE);
  assert.equal(headers['WWW-Authenticate'], undefined);
  assert.equal(headers['Proxy-Authenticate'], undefined);
});

nodeTest.test('multiple array values are split into challenges', () => {
  const challenges = splitChallenges(['Basic realm="a"', 'Digest realm="b"', 'NTLM']);
  assert.equal(challenges.length, 3);
  assert.equal(schemeOf(challenges[2]), 'NTLM');
});

nodeTest.test('apply reports no change for clean response', () => {
  const headers = { 'www-authenticate': ['Basic realm="x"'] };
  const result = applyAuthChallengeGuard(headers, { url: 'https://example.com', resourceType: 'mainFrame' });
  assert.equal(result.changed, false);
});

nodeTest.test('missing url still evaluates schemes', () => {
  const verdict = evaluateAuthChallenge({ 'www-authenticate': ['NTLM'] }, {});
  assert.equal(verdict.reason, REASON.NTLM_SCHEME);
});

nodeTest.test('describeReason is non-empty for every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0, reason);
  }
});
