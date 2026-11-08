'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./nelreportguard');

function h(value, name = 'report-to') {
  return { [name]: [value] };
}

const page = { url: 'https://app.example.com/index.html' };

test('无上报头时不变更', () => {
  const headers = { 'content-type': ['text/html'] };
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('同源 Report-To 保留', () => {
  const value = JSON.stringify([{ group: 'default', max_age: 60, urls: [{ url: 'https://app.example.com/report' }] }]);
  const headers = h(value);
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.ok(headers['report-to']);
});

test('第三方 Report-To 被移除', () => {
  const value = JSON.stringify([{ group: 'tracker', urls: [{ url: 'https://cdn.tracker.io/collect' }] }]);
  const headers = h(value);
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers['report-to'], undefined);
});

test('明文上报端点判 insecure', () => {
  const value = JSON.stringify([{ urls: [{ url: 'http://app.example.com/report' }] }]);
  const headers = h(value);
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
  assert.strictEqual(headers['report-to'], undefined);
});

test('Report-To 非法 JSON 被移除', () => {
  const headers = h('[{"urls":');
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['report-to'], undefined);
});

test('超长 Report-To 被移除', () => {
  const headers = h('x'.repeat(guard.MAX_HEADER_LENGTH + 1));
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('Reporting-Endpoints 同源保留', () => {
  const headers = h('default="https://app.example.com/reports"', 'reporting-endpoints');
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(headers['reporting-endpoints'].length, 1);
});

test('Reporting-Endpoints 含第三方被移除', () => {
  const headers = h('default="https://evil.example.net/x", csp="https://app.example.com/y"', 'reporting-endpoints');
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers['reporting-endpoints'], undefined);
});

test('Reporting-Endpoints 结构非法被移除', () => {
  const headers = h('default=https://app.example.com/x', 'reporting-endpoints');
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('NEL 头被一并移除', () => {
  const headers = h(JSON.stringify([{ urls: [{ url: 'https://elsewhere.example/collect' }] }]));
  headers['nel'] = ['{"report_to":"default"}'];
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(headers['nel'], undefined);
});

test('大小写不敏感键名被识别', () => {
  const headers = h(JSON.stringify([{ urls: [{ url: 'https://other.example/x' }] }]), 'Report-To');
  const r = guard.applyReportingGuard(headers, page);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers['Report-To'], undefined);
});

test('describeReason 覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
