'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./linkpreloadguard');

const page = { url: 'https://app.example.com/page' };

function h(value) {
  return { link: [value] };
}

test('无 Link 头时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('同源 preload 保留', () => {
  const headers = h('</main.js>; rel=preload; as=script');
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(headers.link[0], '</main.js>; rel=preload; as=script');
});

test('第三方 preconnect 被移除', () => {
  const headers = h('<https://cdn.tracker.net>; rel=preconnect');
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers.link, undefined);
});

test('混合条目只保留同源项', () => {
  const headers = h('</a.css>; rel=preload; as=style, <https://evil.example/x.js>; rel=preload; as=script');
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.changed, true);
  assert.deepStrictEqual(r.kept, ['</a.css>; rel=preload; as=style']);
  assert.strictEqual(headers.link[0], '</a.css>; rel=preload; as=style');
});

test('相对 URL 视为同源', () => {
  const headers = h('</assets/font.woff2>; rel=preload; as=font');
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('非 HTTP 协议被移除', () => {
  const headers = h('<javascript:alert(1)>; rel=preload');
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.BAD_SCHEME);
  assert.strictEqual(headers.link, undefined);
});

test('格式非法条目被移除', () => {
  const headers = h('garbage');
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长 Link 头被整段移除', () => {
  const headers = h(`</x>; rel=preload; as=script; note=${'a'.repeat(guard.MAX_HEADER_LENGTH)}`);
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers.link, undefined);
});

test('条目数超预算被整段移除', () => {
  const entries = [];
  for (let i = 0; i < guard.MAX_LINKS + 2; i += 1) entries.push(`</a${i}.css>; rel=preload; as=style`);
  const headers = h(entries.join(', '));
  const r = guard.applyLinkPreloadGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.link, undefined);
});

test('引号内逗号不会被误切', () => {
  const entries = guard.splitLinks('</a>; rel=preload; media="(min-width: 100px),print"');
  assert.strictEqual(entries.length, 1);
});

test('parseLink 解析参数', () => {
  const parsed = guard.parseLink('</a.css>; rel="preload"; as=style');
  assert.strictEqual(parsed.href, '/a.css');
  assert.strictEqual(parsed.params.rel, 'preload');
  assert.strictEqual(parsed.params.as, 'style');
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
