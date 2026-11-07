'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./linkresponseguard');

function h(value) {
  return { link: [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('同源预载不改动', () => {
  const headers = h('</app.css>; rel=preload; as=style');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('未知关系类型被剔除', () => {
  const headers = h('</x>; rel=made-up, </app.js>; rel=preload');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_REL);
  assert.strictEqual(headers.link[0], '</app.js>; rel=preload');
});

test('缺少 rel 被剔除', () => {
  const headers = h('</x.css>');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.NO_REL);
  assert.strictEqual(headers.link, undefined);
});

test('明文目标被剔除', () => {
  const headers = h('<http://cdn.example.com/a.js>; rel=preload');
  const r = guard.applyLinkResponseGuard(headers, 'http://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('本地目标被剔除', () => {
  const headers = h('<file:///etc/passwd>; rel=preload');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('内嵌凭据目标被剔除', () => {
  const headers = h('<https://user:pass@example.com/x.js>; rel=preload');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CREDENTIALS);
});

test('跨源预载无 crossorigin 被剔除', () => {
  const headers = h('<https://cdn.example.net/a.js>; rel=preload');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
});

test('跨源预载带 crossorigin 保留', () => {
  const headers = h('<https://cdn.example.net/a.js>; rel=preload; crossorigin');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
});

test('跨源 canonical 保留', () => {
  const headers = h('<https://example.com/page>; rel=canonical');
  const r = guard.applyLinkResponseGuard(headers, 'https://www.example.com');
  assert.strictEqual(r.changed, false);
});

test('重复目标去重', () => {
  const headers = h('</a.js>; rel=preload, </a.js>; rel=preload');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE);
  assert.strictEqual(headers.link[0], '</a.js>; rel=preload');
});

test('超长取值整头剥除', () => {
  const headers = h(`</a.js>; rel=preload, <${'/b'.repeat(1200)}>; rel=preload`);
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers.link, undefined);
});

test('格式非法的条目被剔除', () => {
  const headers = h('not-a-link, </b.js>; rel=preload');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers.link[0], '</b.js>; rel=preload');
});

test('多关系类型含白名单外项被剔除', () => {
  const headers = h('</a.js>; rel="preload webfont"');
  const r = guard.applyLinkResponseGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_REL);
});
