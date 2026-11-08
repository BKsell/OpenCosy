'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./mixedcontentguard');

test('https 资源放行', () => {
  const r = guard.applyMixedContentGuard({ resourceUrl: 'https://cdn.example.com/app.js', kind: 'script' });
  assert.strictEqual(r.action, 'allow');
});

test('主动内容 http 被阻断', () => {
  const r = guard.applyMixedContentGuard({ resourceUrl: 'http://cdn.example.com/app.js', kind: 'script' });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.reason, guard.REASON.ACTIVE_BLOCKED);
  assert.strictEqual(r.upgradeTo, 'https://cdn.example.com/app.js');
});

test('被动内容 http 被改写', () => {
  const r = guard.applyMixedContentGuard({ resourceUrl: 'http://cdn.example.com/a.png', kind: 'img' });
  assert.strictEqual(r.action, 'rewrite');
  assert.strictEqual(r.reason, guard.REASON.PASSIVE_UPGRADED);
  assert.strictEqual(r.url, 'https://cdn.example.com/a.png');
});

test('回环地址放行', () => {
  const r = guard.applyMixedContentGuard({ resourceUrl: 'http://127.0.0.1:3000/x.js', kind: 'script' });
  assert.strictEqual(r.action, 'allow');
  assert.strictEqual(r.reason, guard.REASON.PASSIVE_LOOPBACK);
});

test('未知类型按主动内容处理', () => {
  const r = guard.applyMixedContentGuard({ resourceUrl: 'http://cdn.example.com/x', kind: 'other' });
  assert.strictEqual(r.action, 'block');
});

test('非法资源 URL 阻断', () => {
  const r = guard.applyMixedContentGuard({ resourceUrl: 'nope' });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('元素分类', () => {
  assert.strictEqual(guard.classifyElement('link', 'stylesheet'), 'stylesheet');
  assert.strictEqual(guard.classifyElement('img', 'src'), 'img');
  assert.strictEqual(guard.classifyElement('script', 'src'), 'script');
  assert.strictEqual(guard.classifyElement('iframe', 'src'), 'iframe');
  assert.strictEqual(guard.classifyElement('div', 'style'), 'other');
});

test('批量审计统计阻断与改写', () => {
  const report = guard.auditMixedContentBatch([
    { resourceUrl: 'http://cdn.example.com/x.js', kind: 'script' },
    { resourceUrl: 'http://cdn.example.com/x.png', kind: 'img' },
    { resourceUrl: 'https://cdn.example.com/x.png', kind: 'img' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.blocked, 1);
  assert.strictEqual(report.rewritten, 1);
});
