'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./tabnabbingguard');

test('同站 _blank 无需改写', () => {
  const r = guard.applyTabnabbingGuard({ target: '_blank', currentUrl: 'https://a.example.com', url: 'https://b.example.com', rel: '' });
  assert.strictEqual(r.action, 'allow');
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('跨站 _blank 强制 noopener/noreferrer', () => {
  const r = guard.applyTabnabbingGuard({ target: '_blank', currentUrl: 'https://a.example.com', url: 'https://evil.example.org', rel: 'nofollow' });
  assert.strictEqual(r.action, 'rewrite');
  assert.strictEqual(r.reason, guard.REASON.OPENER_SEVERED);
  assert.strictEqual(r.rel.includes('noopener'), true);
  assert.strictEqual(r.rel.includes('noreferrer'), true);
});

test('已有 noopener 只补 noreferrer', () => {
  const r = guard.applyTabnabbingGuard({ target: '_blank', currentUrl: 'https://a.example.com', url: 'https://evil.example.org', rel: 'noopener' });
  assert.strictEqual(r.reason, guard.REASON.REL_ADDED);
  assert.strictEqual(r.rel, 'noopener noreferrer');
});

test('未知 _ target 被阻断', () => {
  const r = guard.applyTabnabbingGuard({ target: '_unknown', currentUrl: 'https://a.example.com', url: 'https://a.example.com' });
  assert.strictEqual(r.action, 'block');
  assert.strictEqual(r.blocked, true);
});

test('普通 target 放行', () => {
  const r = guard.applyTabnabbingGuard({ target: 'self', url: 'https://a.example.com' });
  assert.strictEqual(r.action, 'allow');
});

test('无 target 时放行', () => {
  const r = guard.applyTabnabbingGuard({ url: 'https://a.example.com' });
  assert.strictEqual(r.action, 'allow');
});

test('rel 去重排序', () => {
  const r = guard.applyTabnabbingGuard({ target: '_blank', currentUrl: 'https://a.example.com', url: 'https://evil.example.org', rel: 'noreferrer noreferrer' });
  assert.strictEqual(r.rel, 'noopener noreferrer');
});

test('批量审计统计', () => {
  const report = guard.auditLinkBatch([
    { target: '_blank', currentUrl: 'https://a.example.com', url: 'https://evil.example.org' },
    { target: '_blank', currentUrl: 'https://a.example.com', url: 'https://b.example.com' },
    { target: '_unknown' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.rewritten, 1);
  assert.strictEqual(report.blocked, 1);
});
