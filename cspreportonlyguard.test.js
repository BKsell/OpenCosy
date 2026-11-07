'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./cspreportonlyguard');

function h(value) {
  return { 'content-security-policy-report-only': [value] };
}

test('缺头不改动', () => {
  const r = guard.applyCspReportOnlyGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规策略不改动', () => {
  const headers = h("default-src 'self'; report-uri https://report.example.com");
  const r = guard.applyCspReportOnlyGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('明文 report-uri 被剔除', () => {
  const headers = h("default-src 'self'; report-uri http://insecure.example.com");
  const r = guard.applyCspReportOnlyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_REPORT_URI);
  assert.strictEqual(headers['content-security-policy-report-only'], "default-src 'self'");
});

test('缺强制指令时补 default-src', () => {
  const headers = h('report-uri https://report.example.com');
  const r = guard.applyCspReportOnlyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MISSING_DIRECTIVE);
  assert.ok(headers['content-security-policy-report-only'].startsWith("default-src 'self'"));
});

test('超长策略删除', () => {
  const headers = h('default-src ' + "'self' ".repeat(600));
  const r = guard.applyCspReportOnlyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['content-security-policy-report-only'], undefined);
});
