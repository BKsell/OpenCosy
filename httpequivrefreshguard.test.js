'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./httpequivrefreshguard');

const { REASON, originOf, parseRefreshTarget, splitLinkHeader, evaluateRefresh, applyRefreshHeaderGuard, describeReason } = guard;

nodeTest.test('originOf normalizes http origins', () => {
  assert.equal(originOf('https://Example.com/path?q=1'), 'https://example.com');
  assert.equal(originOf('http://example.com:8080/x'), 'http://example.com:8080');
  assert.equal(originOf('data:text/html,x'), '');
  assert.equal(originOf('not a url'), '');
});

nodeTest.test('refresh target parsing keeps the url part', () => {
  assert.equal(parseRefreshTarget('5; url=https://evil.example/'), 'https://evil.example/');
  assert.equal(parseRefreshTarget('0;url="/next"'), '/next');
  assert.equal(parseRefreshTarget('30'), null);
});

nodeTest.test('link header splitting respects quoted commas', () => {
  const parts = splitLinkHeader('</a.css>; rel=preload, </b.css>; rel=prefetch');
  assert.equal(parts.length, 2);
  assert.ok(parts[0].startsWith('</a.css>'));
});

nodeTest.test('link target and rel are extracted', () => {
  const parsed = guard.linkTargetAndRel('</app.js>; rel="preload"; as=script');
  assert.equal(parsed.target, '/app.js');
  assert.equal(parsed.rel, 'preload');
});

nodeTest.test('same-origin refresh is still stripped', () => {
  const headers = { refresh: ['3; url=/home'] };
  const result = applyRefreshHeaderGuard(headers, { url: 'https://example.com/page' });
  assert.equal(result.changed, true);
  assert.equal(headers.refresh, undefined);
});

nodeTest.test('cross-origin refresh is reported', () => {
  const headers = { Refresh: ['0; url=https://evil.example/'] };
  const verdict = evaluateRefresh(headers, { url: 'https://example.com/page' });
  assert.equal(verdict.findings.length, 1);
  assert.equal(verdict.findings[0].reason, REASON.refreshCrossOrigin);
});

nodeTest.test('refresh without url is reported as header only', () => {
  const verdict = evaluateRefresh({ refresh: ['30'] }, { url: 'https://example.com/' });
  assert.equal(verdict.findings[0].reason, REASON.refreshHeader);
  assert.equal(verdict.findings[0].target, null);
});

nodeTest.test('cross-origin preload link is dropped', () => {
  const headers = { link: ['<https://cdn.evil/app.js>; rel=preload; as=script'] };
  const result = applyRefreshHeaderGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, true);
  assert.equal(headers.link, undefined);
});

nodeTest.test('same-origin preload link survives', () => {
  const headers = { link: ['</app.js>; rel=preload; as=script'] };
  const result = applyRefreshHeaderGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, false);
  assert.deepEqual(headers.link, ['</app.js>; rel=preload; as=script']);
});

nodeTest.test('cross-origin prefetch is reported and stripped', () => {
  const headers = { Link: ['<https://evil.example/x.css>; rel=prefetch'] };
  const verdict = applyRefreshHeaderGuard(headers, { url: 'https://example.com/' });
  assert.equal(verdict.findings[0].reason, REASON.linkPrefetch);
  assert.equal(headers.Link, undefined);
});

nodeTest.test('mixed link header keeps local entries', () => {
  const headers = { link: ['</a.js>; rel=preload, <https://evil.example/b.js>; rel=preload'] };
  const result = applyRefreshHeaderGuard(headers, { url: 'https://example.com/' });
  assert.equal(result.changed, true);
  assert.equal(headers.Link.length, 1);
  assert.ok(String(headers.Link[0]).includes('/a.js'));
});

nodeTest.test('unknown url keeps refresh stripped but not cross-origin', () => {
  const headers = { refresh: ['0; url=https://other.example/'] };
  const result = applyRefreshHeaderGuard(headers, {});
  assert.equal(result.changed, true);
  assert.equal(result.findings[0].reason, REASON.refreshHeader);
  assert.equal(headers.refresh, undefined);
});

nodeTest.test('clean headers are untouched', () => {
  const headers = { 'content-type': ['text/html'], link: ['</style.css>; rel=stylesheet'] };
  assert.equal(applyRefreshHeaderGuard(headers, { url: 'https://example.com/' }).changed, false);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0, reason);
  }
});
