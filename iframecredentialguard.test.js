'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./iframecredentialguard');

test('普通跨站 iframe 无凭据表单放行', () => {
  const r = guard.applyIframeCredentialGuard({ frameUrl: 'https://embed.example.org/x', topUrl: 'https://a.example.com', sandbox: 'allow-scripts' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('不透明沙箱内的凭据表单被阻断', () => {
  const r = guard.applyIframeCredentialGuard({ frameUrl: 'https://embed.example.org/x', topUrl: 'https://a.example.com', sandbox: 'allow-scripts', credentialForm: true });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.OPAQUE_ORIGIN);
});

test('跨站 iframe 收集密码字段被阻断', () => {
  const r = guard.applyIframeCredentialGuard({ frameUrl: 'https://evil.example.org/x', topUrl: 'https://bank.example.com', fieldTypes: ['password', 'email'] });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_SITE_FRAME);
});

test('同站 iframe 密码字段放行', () => {
  const r = guard.applyIframeCredentialGuard({ frameUrl: 'https://login.example.com/x', topUrl: 'https://app.example.com', fieldTypes: ['password'] });
  assert.strictEqual(r.blocked, false);
});

test('沙箱逃逸 token 与凭据表单组合被阻断', () => {
  const r = guard.applyIframeCredentialGuard({ frameUrl: 'https://embed.example.org', topUrl: 'https://a.example.com', sandbox: 'allow-scripts allow-same-origin allow-top-navigation', credentialForm: true });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.SANDBOX_ESCAPE);
  assert.ok(r.detail.includes('allow-same-origin'));
});

test('非法 frame URL 被阻断', () => {
  const r = guard.applyIframeCredentialGuard({ frameUrl: 'about:blank#x', topUrl: 'https://a.example.com' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('sandbox 去重并标记逃逸组合', () => {
  const r = guard.normalizeSandbox(' allow-scripts allow-scripts  allow-same-origin ');
  assert.strictEqual(r.escapes, true);
  assert.deepStrictEqual(r.tokens, ['allow-scripts', 'allow-same-origin']);
});

test('批量审计限制 finding 数量', () => {
  const report = guard.auditEmbedBatch([
    { frameUrl: 'https://evil.example.org', topUrl: 'https://a.example.com', fieldTypes: ['password'] },
    { frameUrl: 'https://ok.example.org', topUrl: 'https://a.example.com' },
    { frameUrl: 'https://evil.example.org', topUrl: 'https://a.example.com', fieldTypes: ['password'] },
  ], { maxFindings: 2 });
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.blocked, 2);
  assert.strictEqual(report.findings.length, 2);
});
