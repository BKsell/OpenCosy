'use strict';

// webbundleguard.test.js —— Web Bundle：bundle https/同源/完整性、resources 数量/scheme/跨站/私网/脚本、scope 过宽。

const test = require('node:test');
const assert = require('node:assert/strict');
const w = require('./webbundleguard');
const { WebBundleGuard, WBB_REASON, defaultWebBundlePolicy, isScriptUrl } = w;

function ctx(over) { return Object.assign({ origin: 'https://app.example.com' }, over || {}); }
function spec(over) {
  return Object.assign({
    href: 'https://app.example.com/static/main.wbn',
    resources: ['https://app.example.com/static/a.css', 'https://app.example.com/static/b.png'],
    scopes: ['https://app.example.com/static/'],
  }, over || {});
}

test('合规 bundle 放行', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink(ctx(), spec()).decision, 'allow');
});

test('非 https bundle 拒绝', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink(ctx(), spec({ href: 'http://app.example.com/a.wbn' })).reason, WBB_REASON.BAD_BUNDLE_URL);
});

test('跨站 bundle 默认拒绝；带 integrity 仍受同源策略拦', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink(ctx(), spec({ href: 'https://cdn.other.com/a.wbn' })).reason, WBB_REASON.BUNDLE_CROSS_ORIGIN);
});

test('无 resources/过多拒绝', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink(ctx(), spec({ resources: [] })).reason, WBB_REASON.NO_RESOURCES);
  const many = [];
  for (let i = 0; i < 33; i++) many.push('https://app.example.com/s/' + i + '.css');
  assert.equal(g.decideLink(ctx(), spec({ resources: many })).reason, WBB_REASON.TOO_MANY_RESOURCES);
});

test('http/私网/跨站 resource 拒绝', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink(ctx(), spec({ resources: ['http://app.example.com/a.css'] })).reason, WBB_REASON.INSECURE_RESOURCE);
  assert.equal(g.decideLink(ctx(), spec({ resources: ['https://10.0.0.1/a.css'] })).reason, WBB_REASON.RESOURCE_PRIVATE);
  assert.equal(g.decideLink(ctx(), spec({ resources: ['https://other.com/a.css'] })).reason, WBB_REASON.RESOURCE_CROSS_SITE);
});

test('bundle 内脚本资源默认拒绝', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink(ctx(), spec({ resources: ['https://app.example.com/static/app.js'] })).reason,
    WBB_REASON.SCRIPT_FROM_BUNDLE);
});

test('根 scope 拒绝', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink(ctx(), spec({ scopes: ['https://app.example.com/'] })).reason, WBB_REASON.SCOPE_TOO_WIDE);
});

test('非 https 页面拒绝', () => {
  const g = new WebBundleGuard();
  assert.equal(g.decideLink({ origin: 'http://x' }, spec()).reason, WBB_REASON.INSECURE_ORIGIN);
});

test('isScriptUrl 纯字符', () => {
  assert.equal(isScriptUrl('https://x/a.mjs'), true);
  assert.equal(isScriptUrl('https://x/a.css'), false);
});
