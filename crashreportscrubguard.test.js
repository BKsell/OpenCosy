'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./crashreportscrubguard');

test('普通文本不改变', () => {
  const r = guard.applyCrashReportScrubGuard({ body: 'stack trace: TypeError at line 42' });
  assert.strictEqual(r.redactions, 0);
  assert.strictEqual(r.changed, false);
});

test('Windows 用户路径被脱敏', () => {
  const r = guard.scrub('at C:\\Users\\alice\\app\\main.js:1');
  assert.strictEqual(r.text.includes('alice'), false);
  assert.ok(r.reasons.includes('home-path'));
});

test('Linux 家目录被脱敏', () => {
  const r = guard.scrub('open /home/bob/project/core.js failed');
  assert.strictEqual(r.text.includes('bob'), false);
});

test('邮箱被脱敏', () => {
  const r = guard.scrub('contact user@example.com for details');
  assert.strictEqual(r.text.includes('user@example.com'), false);
});

test('GitHub token 被脱敏', () => {
  const r = guard.scrub('token ghp_abcdefghijklmnopqrstuvwxyz0123 leaked');
  assert.strictEqual(r.text.includes('ghp_'), false);
  assert.ok(r.reasons.includes('secret-token'));
});

test('内网 IP 被脱敏', () => {
  const r = guard.scrub('connect 192.168.10.24 failed');
  assert.strictEqual(r.text.includes('192.168.10.24'), false);
  assert.ok(r.reasons.includes('internal-ip'));
});

test('超长报告被截断', () => {
  const r = guard.applyCrashReportScrubGuard({ body: 'x'.repeat(200), maxLength: 100 });
  assert.strictEqual(r.body.length, 100);
  assert.strictEqual(r.truncated, true);
});

test('批量审计统计脱敏报告数', () => {
  const report = guard.auditCrashBatch([
    { body: 'mail a@b.com' },
    { body: 'nothing sensitive' },
    { body: 'path /home/carol/x' },
  ]);
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.redacted, 2);
});
