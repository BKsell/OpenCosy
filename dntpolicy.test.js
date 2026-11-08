'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const dnt = require('./dntpolicy');

test('偏好关闭时不加任何头', () => {
  const r = dnt.decideRequest({ dnt: false, gpc: false }, { url: 'https://a.com/x' });
  assert.equal(r.active, false);
  assert.deepEqual(r.headers, {});
  assert.equal(dnt.headerSummary({ dnt: false, gpc: false }, { url: 'https://a.com' }), 'no-dnt-signal');
});

test('只开 DNT 时发 DNT:1', () => {
  const r = dnt.decideRequest({ dnt: true, gpc: false }, { url: 'https://a.com/x' });
  assert.equal(r.active, true);
  assert.equal(r.headers.DNT, '1');
  assert.equal(r.headers['Sec-GPC'], undefined);
});

test('只开 GPC 时发 Sec-GPC:1', () => {
  const r = dnt.decideRequest({ dnt: false, gpc: true }, { url: 'https://a.com/x' });
  assert.equal(r.active, true);
  assert.equal(r.headers['Sec-GPC'], '1');
  assert.equal(r.headers.DNT, undefined);
});

test('两个都开时两个头都发', () => {
  const r = dnt.decideRequest({ dnt: true, gpc: true }, { url: 'https://a.com/x' });
  assert.equal(r.active, true);
  assert.equal(r.headers.DNT, '1');
  assert.equal(r.headers['Sec-GPC'], '1');
  assert.equal(dnt.headerSummary({ dnt: true, gpc: true }, { url: 'https://a.com' }), 'dnt-signal:DNT+Sec-GPC');
});

test('非 http(s) 目标不发头（即便偏好开启）', () => {
  for (const u of ['file:///c:/x', 'data:text/html,x', 'chrome-extension://abc/x', 'blob:https://a/x', 'about:blank']) {
    const r = dnt.decideRequest({ dnt: true, gpc: true }, { url: u });
    assert.equal(r.active, false, u);
    assert.deepEqual(r.headers, {}, u);
  }
});

test('isWebTarget 只认 http/https', () => {
  assert.equal(dnt.isWebTarget('https://a.com'), true);
  assert.equal(dnt.isWebTarget('http://a.com'), true);
  assert.equal(dnt.isWebTarget('file:///x'), false);
  assert.equal(dnt.isWebTarget(''), false);
});

test('describeSignal 四态', () => {
  assert.equal(dnt.describeSignal({ dnt: true, gpc: true }), 'DNT + GPC 均已开启');
  assert.equal(dnt.describeSignal({ dnt: true, gpc: false }), 'DNT 已开启');
  assert.equal(dnt.describeSignal({ dnt: false, gpc: true }), 'GPC 已开启');
  assert.equal(dnt.describeSignal({ dnt: false, gpc: false }), 'DNT/GPC 均关闭');
  assert.equal(dnt.describeSignal(undefined), 'DNT/GPC 均关闭');
});

test('畸形 details 不抛异常，缺省放行', () => {
  assert.doesNotThrow(() => dnt.decideRequest({ dnt: true, gpc: true }, null));
  const r = dnt.decideRequest({ dnt: true, gpc: true }, { url: 'https://a.com', resourceType: undefined });
  assert.equal(r.active, true);
  assert.equal(r.headers.DNT, '1');
});

test('各子资源类型与顶层导航对 http(s) 都发头', () => {
  for (const rt of ['script','image','subFrame','xhr','mainFrame']) {
    const r = dnt.decideRequest({ dnt: true, gpc: true }, { url: 'https://a.com/x', resourceType: rt });
    assert.equal(r.active, true, rt);
  }
});
