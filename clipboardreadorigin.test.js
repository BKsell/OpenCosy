'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const clip = require('./clipboardreadorigin');

const { REASON, isSecureContextUrl, originOf, decideClipboardRead, describeReason } = clip;

nodeTest.test('https pages are secure contexts', () => {
  assert.equal(isSecureContextUrl('https://example.com/a'), true);
});

nodeTest.test('loopback http pages are secure contexts', () => {
  for (const url of ['http://localhost:3000/', 'http://127.0.0.1/x', 'http://[::1]/y']) {
    assert.equal(isSecureContextUrl(url), true, url);
  }
});

nodeTest.test('plain http pages are not secure contexts', () => {
  assert.equal(isSecureContextUrl('http://example.com/'), false);
});

nodeTest.test('invalid urls are not secure contexts', () => {
  assert.equal(isSecureContextUrl('not a url'), false);
  assert.equal(isSecureContextUrl(''), false);
});

nodeTest.test('originOf normalizes scheme and host', () => {
  assert.equal(originOf('HTTPS://Example.COM/a/b'), 'https://example.com');
  assert.equal(originOf('bad'), '');
});

nodeTest.test('top-level foreground secure page with gesture is allowed', () => {
  const verdict = decideClipboardRead({
    permission: 'clipboard-read',
    pageUrl: 'https://example.com',
    isTopFrame: true,
    tabActive: true,
    userGesture: true,
  });
  assert.equal(verdict.allow, true);
  assert.equal(verdict.reason, REASON.OK);
});

nodeTest.test('insecure context is denied', () => {
  const verdict = decideClipboardRead({
    permission: 'clipboard-read',
    pageUrl: 'http://example.com',
    isTopFrame: true,
    tabActive: true,
    userGesture: true,
  });
  assert.equal(verdict.allow, false);
  assert.equal(verdict.reason, REASON.INSECURE_CONTEXT);
});

nodeTest.test('unparsable page url is denied', () => {
  const verdict = decideClipboardRead({ permission: 'clipboard-read', pageUrl: '::::' });
  assert.equal(verdict.allow, false);
  assert.equal(verdict.reason, REASON.BAD_PAGE_URL);
});

nodeTest.test('cross-origin request is denied', () => {
  const verdict = decideClipboardRead({
    permission: 'clipboard-read',
    pageUrl: 'https://example.com',
    requestOrigin: 'https://evil.com',
    isTopFrame: true,
    tabActive: true,
    userGesture: true,
  });
  assert.equal(verdict.allow, false);
  assert.equal(verdict.reason, REASON.CROSS_ORIGIN_FRAME);
});

nodeTest.test('same-origin request with explicit origin passes', () => {
  const verdict = decideClipboardRead({
    permission: 'clipboard-read',
    pageUrl: 'https://example.com/a',
    requestOrigin: 'https://example.com',
    isTopFrame: true,
    tabActive: true,
    userGesture: true,
  });
  assert.equal(verdict.allow, true);
});

nodeTest.test('sub frame is denied even on secure origin', () => {
  const verdict = decideClipboardRead({
    permission: 'clipboard-read',
    pageUrl: 'https://example.com',
    isTopFrame: false,
    tabActive: true,
    userGesture: true,
  });
  assert.equal(verdict.allow, false);
  assert.equal(verdict.reason, REASON.CROSS_ORIGIN_FRAME);
});

nodeTest.test('background tab is denied', () => {
  const verdict = decideClipboardRead({
    permission: 'clipboard-read',
    pageUrl: 'https://example.com',
    isTopFrame: true,
    tabActive: false,
    userGesture: true,
  });
  assert.equal(verdict.allow, false);
  assert.equal(verdict.reason, REASON.BACKGROUND_TAB);
});

nodeTest.test('missing gesture is denied', () => {
  const verdict = decideClipboardRead({
    permission: 'clipboard-read',
    pageUrl: 'https://example.com',
    isTopFrame: true,
    tabActive: true,
  });
  assert.equal(verdict.allow, false);
  assert.equal(verdict.reason, REASON.NO_USER_GESTURE);
});

nodeTest.test('other permissions are not applicable and allowed through', () => {
  const verdict = decideClipboardRead({ permission: 'camera', pageUrl: 'http://x' });
  assert.equal(verdict.allow, true);
  assert.equal(verdict.reason, REASON.NOT_APPLICABLE);
});

nodeTest.test('sanitized write is handled elsewhere', () => {
  const verdict = decideClipboardRead({ permission: 'clipboard-sanitized-write' });
  assert.equal(verdict.allow, true);
  assert.equal(verdict.reason, REASON.NOT_APPLICABLE);
});

nodeTest.test('missing permission falls back to clipboard-read rules', () => {
  const verdict = decideClipboardRead({ pageUrl: 'http://example.com', userGesture: true, isTopFrame: true, tabActive: true });
  assert.equal(verdict.allow, false);
  assert.equal(verdict.reason, REASON.INSECURE_CONTEXT);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0);
  }
  assert.equal(describeReason('nope'), '未知原因');
});
