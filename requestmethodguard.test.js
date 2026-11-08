'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./requestmethodguard');

const { REASON, evaluateRequestMethod, describeReason } = guard;

nodeTest.test('ordinary GET request is allowed', () => {
  const verdict = evaluateRequestMethod({ url: 'https://example.com/a.js', method: 'GET', resourceType: 'script' });
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.reason, REASON.OK);
});

nodeTest.test('POST, PUT, PATCH, DELETE, HEAD, OPTIONS are allowed', () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
    const verdict = evaluateRequestMethod({ url: 'https://example.com/api', method });
    assert.equal(verdict.action, 'allow', method);
  }
});

nodeTest.test('lowercase methods are normalized', () => {
  assert.equal(evaluateRequestMethod({ url: 'https://example.com', method: 'get' }).action, 'allow');
});

nodeTest.test('TRACE is blocked', () => {
  const verdict = evaluateRequestMethod({ url: 'https://example.com', method: 'TRACE' });
  assert.equal(verdict.action, 'cancel');
  assert.equal(verdict.reason, REASON.UNSAFE_METHOD);
});

nodeTest.test('CONNECT and TRACK are blocked', () => {
  for (const method of ['CONNECT', 'TRACK']) {
    assert.equal(evaluateRequestMethod({ url: 'https://example.com', method }).reason, REASON.UNSAFE_METHOD);
  }
});

nodeTest.test('non-token method is blocked', () => {
  const verdict = evaluateRequestMethod({ url: 'https://example.com', method: 'GE T' });
  assert.equal(verdict.reason, REASON.UNKNOWN_METHOD);
});

nodeTest.test('unknown extension method is blocked', () => {
  const verdict = evaluateRequestMethod({ url: 'https://example.com', method: 'PROPFIND' });
  assert.equal(verdict.action, 'cancel');
  assert.equal(verdict.reason, REASON.UNKNOWN_METHOD);
});

nodeTest.test('control characters in url are blocked', () => {
  const verdict = evaluateRequestMethod({ url: 'https://example.com/\u0002x', method: 'GET' });
  assert.equal(verdict.reason, REASON.CONTROL_CHAR);
});

nodeTest.test('embedded credentials are blocked', () => {
  const verdict = evaluateRequestMethod({ url: 'https://user:pass@example.com/x', method: 'GET' });
  assert.equal(verdict.action, 'cancel');
  assert.equal(verdict.reason, REASON.URL_USERINFO);
});

nodeTest.test('file scheme subresources are blocked', () => {
  const verdict = evaluateRequestMethod({ url: 'file:///etc/passwd', method: 'GET', resourceType: 'image' });
  assert.equal(verdict.reason, REASON.BLOCKED_SCHEME);
});

nodeTest.test('ftp scheme is blocked', () => {
  assert.equal(evaluateRequestMethod({ url: 'ftp://example.com/a', method: 'GET' }).reason, REASON.BLOCKED_SCHEME);
});

nodeTest.test('data navigation is blocked only for main frame', () => {
  const nav = evaluateRequestMethod({ url: 'data:text/html,<b>x</b>', method: 'GET', resourceType: 'mainFrame' });
  assert.equal(nav.reason, REASON.DATA_NAVIGATION);
  const image = evaluateRequestMethod({ url: 'data:image/png;base64,AA', method: 'GET', resourceType: 'image' });
  assert.equal(image.action, 'allow');
});

nodeTest.test('https data-less urls still allow', () => {
  assert.equal(evaluateRequestMethod({ url: 'https://example.com/@user', method: 'GET' }).action, 'allow');
});

nodeTest.test('describeReason covers known and unknown', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0);
  }
  assert.equal(describeReason('what'), '未知原因');
});
